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

#define VOSK_ENGINE_NAME "vosk"
#define VOSK_ENGINE_CONFIG "res_speech_vosk.conf"
#define VOSK_BUF_SIZE 3200

/** \brief Forward declaration of speech (client object) */
typedef struct vosk_speech_t vosk_speech_t;
/** \brief Forward declaration of engine (global object) */
typedef struct vosk_engine_t vosk_engine_t;

/** \brief Declaration of Vosk speech structure */
struct vosk_speech_t {
	/* Name of the speech object to be used for logging */
	char			*name;
	/* Websocket connection */
	struct			ast_websocket *ws;
	/* Buffer for frames */
	char			buf[VOSK_BUF_SIZE];
	int			offset;
	char			*last_result;
};

/** \brief Declaration of Vosk recognition engine */
struct vosk_engine_t {
	/* Websocket url*/
	char			*ws_url;
};

static struct vosk_engine_t vosk_engine;

/** \brief Set up the speech structure within the engine */
static int vosk_recog_create(struct ast_speech *speech, struct ast_format *format)
{
	vosk_speech_t *vosk_speech;
	enum ast_websocket_result result;

	vosk_speech = ast_calloc(1, sizeof(vosk_speech_t));
	vosk_speech->name = "vosk";
	speech->data = vosk_speech;

	ast_log(LOG_NOTICE, "(%s) Create speech resource %s\n",vosk_speech->name, vosk_engine.ws_url);

	vosk_speech->ws = ast_websocket_client_create(vosk_engine.ws_url, "ws", NULL, &result);
	if (!vosk_speech->ws) {
		ast_free(speech->data);
		return -1;
	} 

	ast_log(LOG_NOTICE, "(%s) Created speech resource result %d\n", vosk_speech->name, result);
}

/** \brief Destroy any data set on the speech structure by the engine */
static int vosk_recog_destroy(struct ast_speech *speech)
{
	vosk_speech_t *vosk_speech = speech->data;
	ast_log(LOG_NOTICE, "(%s) Destroy speech resource\n",vosk_speech->name);

	if (vosk_speech->ws) {
		int fd = ast_websocket_fd(vosk_speech->ws);
		if (fd > 0) {
			ast_websocket_close(vosk_speech->ws, 1000);
			shutdown(fd, SHUT_RDWR);
		}
		ast_websocket_unref(vosk_speech->ws);
	}
	ast_free(vosk_speech->last_result);
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

/*! \brief Load a local grammar on the speech structure */
static int vosk_recog_load_grammar(struct ast_speech *speech, const char *grammar_name, const char *grammar_path)
{
	return 0;
}

/** \brief Unload a local grammar */
static int vosk_recog_unload_grammar(struct ast_speech *speech, const char *grammar_name)
{
	return 0;
}

/** \brief Activate a loaded grammar */
static int vosk_recog_activate_grammar(struct ast_speech *speech, const char *grammar_name)
{
	vosk_speech_t *vosk_speech = speech->data;
        ast_log(LOG_NOTICE, "(%s) Attempting to load grammar \n",vosk_speech->name);
        ast_log(LOG_NOTICE, "Grammar: %s", grammar_name);
	
	/* maybe bigger? */
        char buffer[200];

        int j;
	
	/* does sample_rate do anything? what does words do? */
        j = sprintf(buffer, "{\"config\":{\"phrase_list\": %s, \"sample_rate\":8000,\"words\": 0}}", grammar_name);
	
        ast_log(LOG_NOTICE, "%s\n",buffer);
        ast_log(LOG_NOTICE, "JSON Length: %d\n",j);

        ast_log(LOG_NOTICE, "Writing grammar to websocket:\n");
        ast_websocket_write(vosk_speech->ws, AST_WEBSOCKET_OPCODE_TEXT, buffer, j);

	return 0;
}

/** \brief Deactivate a loaded grammar */
static int vosk_recog_deactivate_grammar(struct ast_speech *speech, const char *grammar_name)
{
	return 0;
}

/** \brief Write audio to the speech engine */
static int vosk_recog_write(struct ast_speech *speech, void *data, int len)
{
	vosk_speech_t *vosk_speech = speech->data;
	char *res;
	int res_len;

	ast_assert (vosk_speech->offset + len < VOSK_BUF_SIZE);

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
				const char *partial = ast_json_object_string_get(res_json, "partial");
				if (partial != NULL && !ast_strlen_zero(partial)) {
					ast_log(LOG_NOTICE, "(%s) Partial recognition result: %s\n", vosk_speech->name, partial);
					ast_free(vosk_speech->last_result);
					vosk_speech->last_result = ast_strdup(partial);
				} else if (text != NULL && !ast_strlen_zero(text)) {
					ast_log(LOG_NOTICE, "(%s) Recognition result: %s\n", vosk_speech->name, text);
					ast_free(vosk_speech->last_result);
					vosk_speech->last_result = ast_strdup(text);
					ast_speech_change_state(speech, AST_SPEECH_STATE_DONE);
				}
			} else {
				ast_log(LOG_ERROR, "(%s) JSON parse error: %s\n", vosk_speech->name, err.text);
			}
			ast_json_free(res_json);
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
	vosk_speech_t *vosk_speech = speech->data;
	ast_log(LOG_NOTICE, "(%s) Start recognition\n",vosk_speech->name);
	ast_speech_change_state(speech, AST_SPEECH_STATE_READY);
	return 0;
}

/** \brief Change an engine specific setting */
static int vosk_recog_change(struct ast_speech *speech, const char *name, const char *value)
{
	vosk_speech_t *vosk_speech = speech->data;
	ast_log(LOG_NOTICE, "(%s) Change setting name: %s value:%s\n",vosk_speech->name,name,value);
	return 0;
}

/** \brief Get an engine specific attribute */
static int vosk_recog_get_settings(struct ast_speech *speech, const char *name, char *buf, size_t len)
{
	vosk_speech_t *vosk_speech = speech->data;
	ast_log(LOG_NOTICE, "(%s) Get settings name: %s\n",vosk_speech->name,name);
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
	struct ast_speech_result *speech_result;

	vosk_speech_t *vosk_speech = speech->data;
	speech_result = ast_calloc(sizeof(struct ast_speech_result), 1);
	speech_result->text = ast_strdup(vosk_speech->last_result);
	speech_result->score = 100;

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
	if(!cfg) {
		ast_log(LOG_WARNING, "No such configuration file %s\n", VOSK_ENGINE_CONFIG);
		return -1;
	}
	if((value = ast_variable_retrieve(cfg, "general", "url")) != NULL) {
		ast_log(LOG_DEBUG, "general.url=%s\n", value);
		vosk_engine.ws_url = ast_strdup(value);
	}
	if (!vosk_engine.ws_url) {
		vosk_engine.ws_url = ast_strdup("ws://localhost");
	}
	ast_config_destroy(cfg);
	return 0;
}

/** \brief Load module */
static int load_module(void)
{
	ast_log(LOG_NOTICE, "Load res_speech_vosk module\n");

	/* Load engine configuration */
	vosk_engine_config_load();

	ast_engine.formats = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if(!ast_engine.formats) {
		ast_log(LOG_ERROR, "Failed to alloc media format capabilities\n");
		return AST_MODULE_LOAD_FAILURE;
	}
	ast_format_cap_append(ast_engine.formats, ast_format_slin, 0);

	if(ast_speech_register(&ast_engine)) {
		ast_log(LOG_ERROR, "Failed to register module\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

/** \brief Unload module */
static int unload_module(void)
{
	ast_free(vosk_engine.ws_url);

	ast_log(LOG_NOTICE, "Unload res_speech_vosk module\n");
	if(ast_speech_unregister(VOSK_ENGINE_NAME)) {
		ast_log(LOG_ERROR, "Failed to unregister module\n");
	}
	return 0;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Vosk Speech Engine");
