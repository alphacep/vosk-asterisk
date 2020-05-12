MAINTAINERCLEANFILES          = Makefile.in

AM_CPPFLAGS                   = -I$(top_srcdir)/include $(ASTERISK_INCLUDES)
AM_CFLAGS                     = -DAST_MODULE_SELF_SYM="__internal_res_speech_vosk"

moddir                        = $(ASTERISK_MODDIR)
mod_LTLIBRARIES               = res_speech_vosk.la

res_speech_vosk_la_SOURCES = res_speech_vosk.c

res_speech_vosk_la_LDFLAGS = -avoid-version -no-undefined -module

res_speech_vosk_la_LIBADD  = $(VOSK_LIBS)

load: 
	asterisk -rx "module load res_speech_vosk.so"

unload: 
	asterisk -rx "module unload res_speech_vosk.so"
