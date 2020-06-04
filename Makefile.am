AUTOMAKE_OPTIONS     = foreign
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 configure
ACLOCAL_AMFLAGS      = -I m4

SUBDIRS              = res-speech-vosk

EXTRA_DIST           = bootstrap conf/res-speech-vosk.conf

install-data-local:
	test -d $(DESTDIR)$(ASTERISK_CONF_DIR) || $(mkinstalldirs) $(DESTDIR)$(ASTERISK_CONF_DIR)
	test -f $(DESTDIR)$(ASTERISK_CONF_DIR)/res-speech-vosk.conf || $(INSTALL) -m 644 $(top_srcdir)/conf/res-speech-vosk.conf $(DESTDIR)$(ASTERISK_CONF_DIR)
