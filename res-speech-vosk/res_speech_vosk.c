/*
 * Asterisk -- An open source telephony toolkit.
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *
 * Please follow coding guidelines 
 * http://svn.digium.com/view/asterisk/trunk/doc/CODING-GUIDELINES
 */

/*! \file
 *
 * \brief Implementation of the Asterisk's Speech API via Vosk
 *
 * \author Nickolay V. Shmyrev <nshmyrev@alphacephei.com>
 * 
 * \ingroup applications
 */

/* Asterisk includes. */
#include "asterisk.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"

#define AST_MODULE "res_speech_vosk"
#include <asterisk/module.h>
#include <asterisk/config.h>
#include <asterisk/frame.h>
#include <asterisk/speech.h>
#include <asterisk/format_cache.h>
#include <asterisk/json.h>

#include <asterisk/http_websocket.h>
#include <fcntl.h>

#define VOSK_ENGINE_NAME "vosk"
#define VOSK_ENGINE_CONFIG "res-speech-vosk.conf"
#define VOSK_BUF_SIZE 3200

/** \brief Forward declaration of speech (client object) */
typedef struct vosk_speech_t vosk_speech_t;
/** \brief Forward declaration of engine (global object) */
typedef struct vosk_engine_t vosk_engine_t;

/* Speech structure flags */
enum vosk_speech_mode {
	VOSK_SPEECH_IMMEDIATE = 0,        /* Immediate complete after the speech recognition done */
	VOSK_SPEECH_QUIET = 1,        /* No complite recognition process while bacground sound are played to other party */
	VOSK_SPEECH_GRAMMAR = 2, /* Complete immediate after a valid grammar processed, otherwise continue recognition while playing sound. If no grammar set, works as VOSK_SPEECH_QUIET */
};

/* Grammar list mode flags */
enum vosk_grammar_mode {
	VOSK_GRAMMAR_ADD = 0, /* Add new grammar */
	VOSK_GRAMMAR_REMOVE = 1, /* Remove grammar */
};

/** \brief List of loading grammars */
struct vosk_grammar_list_t {
	char			*grammar_name;
	char			*file_name;
	int				mode;
	AST_LIST_ENTRY(vosk_grammar_list_t) list;
};

/** \brief Declaration of Vosk speech structure */
struct vosk_speech_t {
	/* Name of the speech object to be used for logging */
	char			*name;
	char			*language;
	char			*server;
	int				mode;
	char			*grammar;
	struct vosk_grammar_list_t *new_grammars;
	/* Websocket connection */
	struct			ast_websocket *ws;
	/* Buffer for frames */
	char			buf[VOSK_BUF_SIZE];
	int				offset;
	struct ast_speech_result *results;
};

/** \brief List of loaded servers */
struct vosk_engine_server_t {
	char			*name;
	char			*ws_url;
	AST_LIST_ENTRY(vosk_engine_server_t) list;
};

/** \brief Declaration of Vosk recognition engine */
struct vosk_engine_t {
	/* Log level */
	int			log_level;
	/* Websocket url*/
	char			*ws_url;
	struct 			vosk_engine_server_t *servers;
};

static struct vosk_engine_t vosk_engine;

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static int mod_table[] = {0, 2, 1};

char *base64_encode(const unsigned char *data,
			int input_length,
			int *output_length) {

	*output_length = 4 * ((input_length + 2) / 3);

	char *encoded_data = ast_calloc(*output_length, 1);
	if (encoded_data == NULL) return NULL;

	for (int i = 0, j = 0; i < input_length;) {

		uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (int i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[*output_length - 1 - i] = '=';

	return encoded_data;
}

/*! \brief Search list of servers and find corresponding one */
static const char* _server_list_get(char* server)
{
	struct vosk_engine_server_t *current_srv = vosk_engine.servers;
	int res = 0;
	char *ws_url = vosk_engine.ws_url;

	while (current_srv != NULL) {
		if (strcasecmp(current_srv->name, server) == 0) {
			ws_url = current_srv->ws_url;
			break;
		}
		/* Move on and then free ourselves */
		current_srv = AST_LIST_NEXT(current_srv, list);
	}

	return ws_url;
}

static int _grammar_list_free(struct vosk_grammar_list_t *list) {
	struct vosk_grammar_list_t *current_grammar = list, *prev_grammar = NULL;
	while (current_grammar != NULL) {
		prev_grammar = current_grammar;
		if (current_grammar->file_name != NULL) ast_free(current_grammar->file_name);
		if (current_grammar->grammar_name != NULL) ast_free(current_grammar->grammar_name);
		current_grammar = AST_LIST_NEXT(current_grammar, list);
		ast_free(prev_grammar);
	}
	return 0;
}

/** \brief Set up the speech structure within the engine */
static int vosk_recog_create(struct ast_speech *speech, struct ast_format *format)
{
	vosk_speech_t *vosk_speech;

	vosk_speech = ast_calloc(1, sizeof(vosk_speech_t));
	vosk_speech->name = "vosk";
	speech->data = vosk_speech;

	ast_log(LOG_NOTICE, "(%s) Create speech resource\n",vosk_speech->name);
}

/** \brief Destroy any data set on the speech structure by the engine */
static int vosk_recog_destroy(struct ast_speech *speech)
{
	vosk_speech_t *vosk_speech = speech->data;
	struct ast_speech_result *current_result = vosk_speech->results, *prev_result = NULL;
	ast_log(LOG_NOTICE, "(%s) Destroy speech resource\n",vosk_speech->name);

	if (vosk_speech->ws) {
		int fd = ast_websocket_fd(vosk_speech->ws);
		if (fd > 0) {
			ast_websocket_close(vosk_speech->ws, 1000);
			shutdown(fd, SHUT_RDWR);
		}
		ast_websocket_unref(vosk_speech->ws);
	}
	while (current_result != NULL) {
		prev_result = current_result;
		/* Deallocate what we can */
		if (current_result->grammar != NULL) {
			ast_free(current_result->grammar);
			current_result->grammar = NULL;
		}
		if (current_result->text != NULL) {
			ast_free(current_result->text);
			current_result->text = NULL;
		}
		/* Move on and then free ourselves */
		current_result = AST_LIST_NEXT(current_result, list);
		ast_free(prev_result);
		prev_result = NULL;
	}
	vosk_speech->results = NULL;
	if (vosk_speech->new_grammars != NULL) {
		_grammar_list_free(vosk_speech->new_grammars);
		vosk_speech->new_grammars = NULL;
	}
	if (vosk_speech->grammar) ast_free(vosk_speech->grammar);
	if (vosk_speech->server) ast_free(vosk_speech->server);
	if (vosk_speech->language) ast_free(vosk_speech->language);
	ast_free(vosk_speech);

	return 0;
}

/*! \brief Stop the in-progress recognition */
static int vosk_recog_stop(struct ast_speech *speech)
{
	vosk_speech_t *vosk_speech = speech->data;
	ast_log(LOG_NOTICE, "(%s) Stop recognition\n",vosk_speech->name);
	ast_speech_change_state(speech, AST_SPEECH_STATE_NOT_READY);
	return 0;
}

/** \brief Send grammar data to add named grammar and policy to the Vosk server */
static int vosk_load_ws_grammar(struct ast_websocket *ws, const char *grammar_name, const char *file_name) {
	int len = 0, result = 0, fd, file_size;
	char *buf = NULL, *file_contents = NULL, *base64 = NULL;
	if (!ast_file_is_readable(file_name)) return -1;
	fd = open(file_name, O_RDONLY);
	if (fd == -1) return -1;
	file_size = lseek(fd, 0, SEEK_END)+1;
	if (file_size>1024*1024) {
		close(fd);
		ast_log(LOG_WARNING, "(%s) Grammar file <%s> are too large, 1MB max size exceeds: %dK\n", "vosk", file_name, file_size/1024);
		return -1;
	}
	lseek(fd, 0, SEEK_SET);
	file_contents = ast_malloc(file_size+1);
	if (file_contents == NULL) {
		close(fd);
		ast_log(LOG_WARNING, "(%s) Grammar file <%s> loading faled, not fits into memory\n", "vosk", file_name);
		return -1;
	}
	file_size = read(fd, file_contents, file_size);
	close(fd);

	base64 = base64_encode(file_contents, file_size, &file_size);
	ast_free(file_contents);
	if(base64 == NULL) {
		return -1;
	}
	file_contents = base64;

	len = snprintf(buf, len, "{\"newgrammar\": \"%s\", \"grammar_data\": \"%s\"}", grammar_name, file_contents);
	if (len < 0) {
		ast_free(file_contents);
		return -1;
	}
	len++;
	buf = ast_malloc(len);
	if (buf == NULL) return -1;
	len = snprintf(buf, len, "{\"newgrammar\": \"%s\", \"grammar_data\": \"%s\"}", grammar_name, file_contents);
	if (len < 0) {
		ast_free(file_contents);
		ast_free(buf);
		return -1;
	}
	ast_log(LOG_NOTICE, "(%s) Upload grammar (%d) to engine over websocket: %s \n", "vosk", len, grammar_name);
	result = ast_websocket_write(ws, AST_WEBSOCKET_OPCODE_TEXT, buf, len);
	ast_free(file_contents);
	ast_free(buf);
	return result;
}

/** \brief Send command to unload (remove) named grammar in Vosk server */
static int vosk_remove_ws_grammar(struct ast_websocket *ws, const char *grammar_name) {
	int len = 0, result = 0;
	char* buf =	NULL;
	len = snprintf(buf, len, "{\"delgrammar\": \"%s\"}", grammar_name);
	if (len < 0) return -1;
	len++;
	buf = ast_malloc(len);
	if (buf == NULL) return -1;
	len = snprintf(buf, len, "{\"delgrammar\": \"%s\"}", grammar_name);
	if (len < 0) {
		ast_free(buf);
		return -1;
	}
	ast_log(LOG_NOTICE, "(%s) Remove grammar (%d) from engine over websocket: %s \n", "vosk", len, grammar_name);
	result = ast_websocket_write(ws, AST_WEBSOCKET_OPCODE_TEXT, buf, len);
	ast_free(buf);
	return result;
}

/** \brief Process collected grammar actions */
static int vosk_send_grammars(struct vosk_speech_t *vosk_speech) {
    struct vosk_grammar_list_t *current_grammar = vosk_speech->new_grammars, *prev_grammar = NULL;
	while (current_grammar != NULL) {
		prev_grammar = current_grammar;
		switch (current_grammar->mode) {
			case VOSK_GRAMMAR_ADD: vosk_load_ws_grammar(vosk_speech->ws, current_grammar->grammar_name, current_grammar->file_name); break;
			case VOSK_GRAMMAR_REMOVE: vosk_remove_ws_grammar(vosk_speech->ws, current_grammar->grammar_name); break;
		}
		current_grammar = AST_LIST_NEXT(prev_grammar, list);
	}
	if (vosk_speech->new_grammars != NULL) {
		_grammar_list_free(vosk_speech->new_grammars);
		vosk_speech->new_grammars = NULL;
	}
	return 0;
}

/** \brief Send command to activate named grammar in Vosk server */
static int vosk_set_ws_grammar(struct ast_websocket *ws, const char *grammar_name) {
	int len = 0, result = 0;
	char* buf =	NULL;
	len = snprintf(buf, len, "{\"setgrammar\": \"%s\"}", grammar_name);
	if (len < 0) return -1;
	len++;
	buf = ast_malloc(len);
	if (buf == NULL) return -1;
	len = snprintf(buf, len, "{\"setgrammar\": \"%s\"}", grammar_name);
	if (len < 0) {
		ast_free(buf);
		return -1;
	}
	ast_log(LOG_NOTICE, "(%s) Activate grammar (%d) in engine over websocket: %s \n", "vosk", len, grammar_name);
	result = ast_websocket_write(ws, AST_WEBSOCKET_OPCODE_TEXT, buf, len);
	ast_free(buf);
	return result;
}

/*! \brief Load a local grammar on the speech structure */
static int vosk_recog_load_grammar(struct ast_speech *speech, const char *grammar_name, const char *grammar_path)
{
	vosk_speech_t *vosk_speech = speech->data;
	struct vosk_grammar_list_t *current_grammar = vosk_speech->new_grammars, *prev_grammar = NULL;
	while (current_grammar != NULL) {
		prev_grammar = current_grammar;
		current_grammar = AST_LIST_NEXT(prev_grammar, list);
	}
	current_grammar = ast_calloc(sizeof(struct vosk_grammar_list_t), 1);
	if (current_grammar == NULL) return -1;
	current_grammar->file_name = ast_strdup(grammar_path);
	current_grammar->grammar_name = ast_strdup(grammar_name);
	current_grammar->mode = VOSK_GRAMMAR_ADD;
	if (prev_grammar == NULL) {
		vosk_speech->new_grammars = current_grammar;
	} else {
		prev_grammar->list.next = current_grammar;
	}
	if (vosk_speech->ws) {
		return vosk_send_grammars(vosk_speech);
	}
	return 0;
}

/** \brief Unload a local grammar */
static int vosk_recog_unload_grammar(struct ast_speech *speech, const char *grammar_name)
{
	vosk_speech_t *vosk_speech = speech->data;
	struct vosk_grammar_list_t *current_grammar = vosk_speech->new_grammars, *prev_grammar = NULL;
	while (current_grammar != NULL) {
		prev_grammar = current_grammar;
		current_grammar = AST_LIST_NEXT(prev_grammar, list);
	}
	current_grammar = ast_calloc(sizeof(struct vosk_grammar_list_t), 1);
	if (current_grammar == NULL) return -1;
	current_grammar->grammar_name = ast_strdup(grammar_name);
	current_grammar->mode = VOSK_GRAMMAR_REMOVE;
	if (prev_grammar == NULL) {
		vosk_speech->new_grammars = current_grammar;
	} else {
		prev_grammar->list.next = current_grammar;
	}
	if (vosk_speech->ws) {
		return vosk_send_grammars(vosk_speech);
	}
	return 0;
}

/** \brief Activate a loaded grammar */
static int vosk_recog_activate_grammar(struct ast_speech *speech, const char *grammar_name)
{
	vosk_speech_t *vosk_speech = speech->data;
	if (vosk_speech->grammar != NULL) ast_free(vosk_speech->grammar);
	vosk_speech->grammar = ast_strdup(grammar_name);
	if (vosk_speech->ws) {
		return vosk_set_ws_grammar(vosk_speech->ws, grammar_name);
	}
	return 0;
}

/** \brief Deactivate a loaded grammar */
static int vosk_recog_deactivate_grammar(struct ast_speech *speech, const char *grammar_name)
{
	vosk_speech_t *vosk_speech = speech->data;
	if (vosk_speech->grammar != NULL) ast_free(vosk_speech->grammar);
	vosk_speech->grammar = NULL;
	if (vosk_speech->ws) {
		return vosk_set_ws_grammar(vosk_speech->ws, "");
	}
	return 0;
}

/** \brief Write audio to the speech engine */
static int vosk_recog_write(struct ast_speech *speech, void *data, int len)
{
	vosk_speech_t *vosk_speech = speech->data;
	char *res;
	int res_len;

	ast_assert (vosk-speech->offset + len < VOSK_BUF_SIZE);

	memcpy(vosk_speech->buf + vosk_speech->offset, data, len);
	vosk_speech->offset += len;
	if (vosk_speech->offset == VOSK_BUF_SIZE) {
		ast_websocket_write(vosk_speech->ws, AST_WEBSOCKET_OPCODE_BINARY, vosk_speech->buf, VOSK_BUF_SIZE);
		vosk_speech->offset = 0;
	}

	if (ast_websocket_wait_for_input(vosk_speech->ws, 0) > 0) {
		res_len = ast_websocket_read_string(vosk_speech->ws, &res);
		if (res_len >= 0) {
			ast_log(LOG_NOTICE, "(%s) Got result: '%s'\n", vosk_speech->name, res);
			struct ast_json_error err;
			struct ast_json *res_json = ast_json_load_string(res, &err);
			if (res_json != NULL) {
				const char *text = ast_json_object_string_get(res_json, "text");
				const char *grammar = ast_json_object_string_get(res_json, "grammar");
				if (text != NULL && !ast_strlen_zero(text)) {
					struct ast_speech_result *current_result;
					ast_log(LOG_NOTICE, "(%s) Recognition result: %s\n", vosk_speech->name, text);

					current_result = ast_calloc(sizeof(struct ast_speech_result), 1);
					if (grammar != NULL) {
						current_result->grammar = ast_strdup(grammar);
					} else {
						current_result->grammar = ast_strdup("unknown");
					}
					current_result->text = ast_strdup(text);
					current_result->score = 100;

					/* Place recognition result to the top of result stack*/
					current_result->list.next = vosk_speech->results;
					vosk_speech->results = current_result;

					#ifdef AST_SPEECH_STREAM
					ast_log(LOG_NOTICE, "(%s) Stream playing: %s mode is:%s\n",vosk_speech->name, (ast_test_flag(speech, AST_SPEECH_STREAM)?"yes":"no"), ((vosk_speech->mode == VOSK_SPEECH_IMMEDIATE)?"immediate":((vosk_speech->mode == VOSK_SPEECH_QUIET)?"quiet":"grammar")));
					/* If stream to user are completed or immediate mode selected - finish regognition process */
					if (!ast_test_flag(speech, AST_SPEECH_STREAM) || (vosk_speech->mode == VOSK_SPEECH_IMMEDIATE)) {
						ast_speech_change_state(speech, AST_SPEECH_STATE_DONE);
					/* if streaming to user amd grammar match in grammar mode - finish recognition process*/
					} else if ((vosk_speech->mode == VOSK_SPEECH_GRAMMAR) && (strcasecmp(current_result->grammar, "unknown")!=0)) {
						ast_speech_change_state(speech, AST_SPEECH_STATE_DONE);
					}
					/* Continue the recognition process otherwise*/
					#else
					/* If no stream info support from asterisk speech API - finish recognition as usual */
					ast_speech_change_state(speech, AST_SPEECH_STATE_DONE);
					#endif
				}
				ast_json_free(res_json);
			} else {
				ast_log(LOG_ERROR, "(%s) JSON parse error: %s\n", vosk_speech->name, err.text);
			}
		} else {
			ast_log(LOG_NOTICE, "(%s) Got error result %d\n", vosk_speech->name, res_len);
		}
	}

	return 0;
}

/** \brief Signal DTMF was received */
static int vosk_recog_dtmf(struct ast_speech *speech, const char *dtmf)
{
	vosk_speech_t *vosk_speech = speech->data;
	ast_log(LOG_NOTICE, "(%s) Signal DTMF %s\n",vosk_speech->name,dtmf);
	return 0;
}

/** brief Prepare engine to accept audio */
static int vosk_recog_start(struct ast_speech *speech)
{
	enum ast_websocket_result result;
	vosk_speech_t *vosk_speech = speech->data;
	ast_log(LOG_NOTICE, "(%s) Start recognition\n",vosk_speech->name);
	if (!vosk_speech->ws) {
		const char *tmp;
		char *ws_url = NULL;
		int len;

		if (vosk_speech->server) {
			tmp = _server_list_get(vosk_speech->server);
		} else {
			tmp = vosk_engine.ws_url;
		}
		if(vosk_speech->language) {
			len = snprintf(ws_url, len, "%s?language=%s", tmp, vosk_speech->language);
			if(len>0) {
				len++;
				ws_url = ast_calloc(len, 1);
				if(!((ws_url!=NULL)&&(len = snprintf(ws_url, len, "%s?language=%s", tmp, vosk_speech->language)))) {
					ws_url = ast_strdup(tmp);
				}
			} else {
				ws_url = ast_strdup(tmp);
			}
		} else {
			ws_url = ast_strdup(tmp);
		}

		vosk_speech->ws = ast_websocket_client_create(ws_url, "ws", NULL, &result);
		ast_free(ws_url);

		ast_log(LOG_NOTICE, "(%s) Connecting to the speech recognition service result %d\n", vosk_speech->name, result);
		if (!vosk_speech->ws) {
			ast_speech_change_state(speech, AST_SPEECH_STATE_DONE);
			return -1;
		} 
		if (vosk_speech->new_grammars != NULL) vosk_send_grammars(vosk_speech);
		if (vosk_speech->grammar != NULL) vosk_set_ws_grammar(vosk_speech->ws, vosk_speech->grammar);
	}
	ast_speech_change_state(speech, AST_SPEECH_STATE_READY);
	return 0;
}

/** \brief Change an engine specific setting */
static int vosk_recog_change(struct ast_speech *speech, const char *name, const char *value)
{
	vosk_speech_t *vosk_speech = speech->data;
	ast_log(LOG_NOTICE, "(%s) Change setting name: %s value:%s\n",vosk_speech->name,name,value);
	if (strcasecmp(name, "language")==0) {
		if (vosk_speech->language != NULL) ast_free(vosk_speech->language);
		vosk_speech->language = ast_strdup(value);
		if (vosk_speech->ws != NULL) {
			int fd = ast_websocket_fd(vosk_speech->ws);
			if (fd > 0) {
				ast_websocket_close(vosk_speech->ws, 1000);
				shutdown(fd, SHUT_RDWR);
			}
			ast_websocket_unref(vosk_speech->ws);
			vosk_speech->ws = NULL;
		}
		return 0;
	} else if (strcasecmp(name, "server")==0) {
		if (vosk_speech->server != NULL) ast_free(vosk_speech->server);
		vosk_speech->server = ast_strdup(value);
		if (vosk_speech->ws != NULL) {
			int fd = ast_websocket_fd(vosk_speech->ws);
			if (fd > 0) {
				ast_websocket_close(vosk_speech->ws, 1000);
				shutdown(fd, SHUT_RDWR);
			}
			ast_websocket_unref(vosk_speech->ws);
			vosk_speech->ws = NULL;
		}
		return 0;
	} else if (strcasecmp(name, "mode")==0) {
		if (strcasecmp(value, "immediate")==0) {
			vosk_speech->mode = VOSK_SPEECH_IMMEDIATE;
			return 0;
		} else if (strcasecmp(value, "quiet")==0) {
			vosk_speech->mode = VOSK_SPEECH_QUIET;
			return 0;
		} else if (strcasecmp(value, "grammar")==0) {
			vosk_speech->mode = VOSK_SPEECH_GRAMMAR;
			return 0;
		}
		return -1;
	}
	return -1;
}

/** \brief Get an engine specific attribute */
static int vosk_recog_get_settings(struct ast_speech *speech, const char *name, char *buf, size_t len)
{
	vosk_speech_t *vosk_speech = speech->data;
	ast_log(LOG_NOTICE, "(%s) Get settings name: %s\n",vosk_speech->name,name);
	if (strcasecmp(name, "language")==0) {
		if (vosk_speech->language) {
			strncpy(buf, vosk_speech->language, len);
		} else {
			strncpy(buf, "", len);
		}
		return 0;
	} else if (strcasecmp(name, "server")==0) {
		if (vosk_speech->server) {
			strncpy(buf, vosk_speech->server, len);
		} else {
			strncpy(buf, "", len);
		}
		return 0;
	} else if (strcasecmp(name, "mode")==0) {
		switch (vosk_speech->mode) {
			case VOSK_SPEECH_IMMEDIATE: strncpy(buf, "immediate", len); break;
			case VOSK_SPEECH_QUIET: strncpy(buf, "quet", len); break;
			case VOSK_SPEECH_GRAMMAR: strncpy(buf, "grammar", len); break;
		}
		return 0;
	}
	return -1;
}

/** \brief Change the type of results we want back */
static int vosk_recog_change_results_type(struct ast_speech *speech,enum ast_speech_results_type results_type)
{
	return -1;
}

/** \brief Try to get result */
struct ast_speech_result* vosk_recog_get(struct ast_speech *speech)
{
	vosk_speech_t *vosk_speech = speech->data;
	struct ast_speech_result *speech_result = vosk_speech->results;
	vosk_speech->results = NULL;
	if (speech_result == NULL) {
	    speech_result = ast_calloc(sizeof(struct ast_speech_result), 1);
		speech_result->text = ast_strdup("");
		speech_result->score = 100;
	}

	ast_set_flag(speech, AST_SPEECH_HAVE_RESULTS);
	return speech_result;
}

/** \brief Speech engine declaration */
static struct ast_speech_engine ast_engine = {
	VOSK_ENGINE_NAME,
	vosk_recog_create,
	vosk_recog_destroy,
	vosk_recog_load_grammar,
	vosk_recog_unload_grammar,
	vosk_recog_activate_grammar,
	vosk_recog_deactivate_grammar,
	vosk_recog_write,
	vosk_recog_dtmf,
	vosk_recog_start,
	vosk_recog_change,
	vosk_recog_get_settings,
	vosk_recog_change_results_type,
	vosk_recog_get
};

/** \brief Load Vosk engine configuration (/etc/asterisk/res_speech_vosk.conf)*/
static int vosk_engine_config_load()
{
	const char *value = NULL;
	struct ast_flags config_flags = { 0 };
	struct ast_config *cfg = ast_config_load(VOSK_ENGINE_CONFIG, config_flags);
	char *category = NULL;
	struct vosk_engine_server_t *last_srv = vosk_engine.servers;
	if (!cfg) {
		ast_log(LOG_WARNING, "No such configuration file %s\n", VOSK_ENGINE_CONFIG);
		return -1;
	}
	if ((value = ast_variable_retrieve(cfg, "general", "log-level")) != NULL) {
		ast_log(LOG_DEBUG, "general.log-level=%s\n", value);
		vosk_engine.log_level = atoi(value);
	}
	if ((value = ast_variable_retrieve(cfg, "general", "url")) != NULL) {
		ast_log(LOG_NOTICE, "general.url=%s\n", value);
		vosk_engine.ws_url = ast_strdup(value);
	}
	if (!vosk_engine.ws_url) {
		vosk_engine.ws_url = ast_strdup("ws://localhost");
	}

	while (category = ast_category_browse(cfg, category)) {
		if (strcasecmp(category, "general")!=0) {
			if ((value = ast_variable_retrieve(cfg, category, "url")) != NULL) {
				ast_log(LOG_NOTICE, "%s.url=%s\n", category, value);
				if (last_srv == NULL) {
					vosk_engine.servers = ast_calloc(sizeof(struct vosk_engine_server_t), 1);
					last_srv = vosk_engine.servers;
				} else {
					last_srv->list.next = ast_calloc(sizeof(struct vosk_engine_server_t), 1);
					last_srv = AST_LIST_NEXT(last_srv, list);
				}
				last_srv->name = ast_strdup(category);
				last_srv->ws_url = ast_strdup(value);
			}
			
		}
	}
	ast_config_destroy(cfg);
	return 0;
}

/** \brief Load module */
static int load_module(void)
{
	ast_log(LOG_NOTICE, "Load res_speech_vosk module\n");

	vosk_engine.servers = NULL;
	/* Load engine configuration */
	vosk_engine_config_load();

	ast_engine.formats = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!ast_engine.formats) {
		ast_log(LOG_ERROR, "Failed to alloc media format capabilities\n");
		return AST_MODULE_LOAD_FAILURE;
	}
	ast_format_cap_append(ast_engine.formats, ast_format_slin, 0);

	if (ast_speech_register(&ast_engine)) {
		ast_log(LOG_ERROR, "Failed to register module\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

/*! \brief Free a list of servers */
static int _server_list_free(struct vosk_engine_server_t *server)
{
	struct vosk_engine_server_t *current_srv = server, *prev_srv = NULL;
	int res = 0;

	while (current_srv != NULL) {
		prev_srv = current_srv;
		/* Deallocate what we can */
		if (current_srv->name != NULL) {
			ast_free(current_srv->name);
			current_srv->name = NULL;
		}
		if (current_srv->ws_url != NULL) {
			ast_free(current_srv->ws_url);
			current_srv->ws_url = NULL;
		}
		/* Move on and then free ourselves */
		current_srv = AST_LIST_NEXT(current_srv, list);
		ast_free(prev_srv);
		prev_srv = NULL;
	}

	return res;
}

/** \brief Unload module */
static int unload_module(void)
{
	if(vosk_engine.ws_url != NULL) ast_free(vosk_engine.ws_url);

	if (vosk_engine.servers != NULL) {
		_server_list_free(vosk_engine.servers);
		vosk_engine.servers = NULL;
	}

	ast_log(LOG_NOTICE, "Unload res_speech_vosk module\n");
	if (ast_speech_unregister(VOSK_ENGINE_NAME)) {
		ast_log(LOG_ERROR, "Failed to unregister module\n");
	}
	return 0;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Vosk Speech Engine");
