AC_INIT([snort_extra],[1.0.0-a4],[snort-team@cisco.com])
AC_CONFIG_AUX_DIR([.])
AC_PREREQ([2.69])
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE([foreign])
AM_SILENT_RULES([yes])

AC_PROG_INSTALL
AC_PROG_CC([clang gcc])
AC_PROG_CXX([clang++ g++])

LT_INIT

AX_CXX_COMPILE_STDCXX_11([noext], [mandatory])

gl_VISIBILITY()
CPPFLAGS="$CFLAG_VISIBILITY $CPPFLAGS"

PKG_CHECK_MODULES([SNORT3], [snort >= 3])

for i in `pkg-config --variable=cpp_opts snort`; do
    CPPFLAGS_VAL=`pkg-config --variable=${i}_CPPFLAGS snort`
    CPPFLAGS="${CPPFLAGS} ${CPPFLAGS_VAL}"
done

AC_SUBST([SNORT3_CFLAGS])
AC_SUBST([CPPFLAGS])

AC_CONFIG_FILES([
Makefile \
src/Makefile \
src/codecs/Makefile \
src/codecs/cd_eapol/Makefile \
src/codecs/cd_linux_sll/Makefile \
src/codecs/cd_null/Makefile \
src/codecs/cd_pflog/Makefile \
src/codecs/cd_pim/Makefile \
src/codecs/cd_ppp/Makefile \
src/codecs/cd_raw4/Makefile \
src/codecs/cd_raw6/Makefile \
src/codecs/cd_slip/Makefile \
src/codecs/cd_token_ring/Makefile \
src/codecs/cd_wlan/Makefile \
src/daqs/Makefile \
src/daqs/daq_socket/Makefile \
src/daqs/daq_regtest/Makefile \
src/inspectors/Makefile \
src/inspectors/data_log/Makefile \
src/inspectors/dpx/Makefile \
src/ips_options/Makefile \
src/ips_options/find/Makefile \
src/ips_options/ips_pkt_num/Makefile \
src/ips_options/ips_urg/Makefile \
src/loggers/Makefile \
src/loggers/alert_ex/Makefile \
src/loggers/alert_lua/Makefile \
src/loggers/alert_unixsock/Makefile \
src/loggers/log_null/Makefile \
src/search_engines/Makefile \
src/search_engines/lowmem/Makefile \
src/so_rules/Makefile \
src/so_rules/sid_18758/Makefile
])

AC_OUTPUT

AC_MSG_RESULT([
    $PACKAGE $VERSION
    ========

    prefix:         ${prefix}
    sysconfdir:     ${sysconfdir}
    libdir:         ${libdir}
    includedir:     ${includedir}

    compiler:       ${CC}
    compiler++:     ${CXX}
    cflags:         ${CFLAGS}
    cxxflags:       ${CXXFLAGS}
    cppflags:       ${CPPFLAGS}
    ldflags:        ${LDFLAGS}
    libs:           ${LIBS}
])
