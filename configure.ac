AC_INIT(asterisk-vosk, 0.3.7)
AM_INIT_AUTOMAKE([no-define foreign nostdinc])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST
AC_PROG_CC
AC_PROG_INSTALL
AC_CONFIG_HEADERS([config.h])

LT_INIT

AC_ARG_WITH([asterisk],
    [--with-asterisk=DIR         specify location of Asterisk],
    [asterisk_dir=$withval],
    [asterisk_dir="/opt"])

asterisk_include_dir="${asterisk_dir}/include"
dnl Test Asterisk include directory and header file.
if test -f "$asterisk_include_dir/asterisk.h"; then
    if test -d "$asterisk_include_dir/asterisk"; then
        ASTERISK_INCLUDES="-I$asterisk_include_dir"
    else
        AC_MSG_ERROR([Could not find Asterisk include directory, make sure Asterisk development package is installed])
    fi
else
    AC_MSG_ERROR([Could not find asterisk.h, make sure Asterisk development package is installed])
fi
ASTERISK_MODDIR="${prefix}/lib/asterisk/modules"
ASTERISK_CONF_DIR="${prefix}/etc/asterisk"
AC_SUBST(ASTERISK_INCLUDES)
AC_SUBST(ASTERISK_MODDIR)
AC_SUBST(ASTERISK_CONF_DIR)

AC_CONFIG_FILES([
    Makefile
    res-speech-vosk/Makefile
])

AC_OUTPUT
