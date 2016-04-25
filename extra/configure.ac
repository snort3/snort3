AC_INIT([snort_extra], [1.0.0-a4], [snort-team@cisco.com])
AC_PREREQ(2.69)

AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC([clang gcc])
AC_PROG_CXX([clang++ g++])
AC_PROG_LIBTOOL

LT_INIT

AX_CXX_COMPILE_STDCXX_11

PKG_CHECK_MODULES([SNORT3], [snort >= 3])

AC_SUBST([SNORT3_CFLAGS])

AC_CONFIG_FILES([
Makefile \
examples/Makefile \
examples/codecs/Makefile \
examples/codecs/cd_eapol/Makefile \
examples/codecs/cd_i4l_rawip/Makefile \
examples/codecs/cd_linux_sll/Makefile \
examples/codecs/cd_null/Makefile \
examples/codecs/cd_pflog/Makefile \
examples/codecs/cd_pim/Makefile \
examples/codecs/cd_ppp/Makefile \
examples/codecs/cd_raw4/Makefile \
examples/codecs/cd_raw6/Makefile \
examples/codecs/cd_slip/Makefile \
examples/codecs/cd_token_ring/Makefile \
examples/codecs/cd_wlan/Makefile \
examples/daqs/Makefile \
examples/daqs/daq_socket/Makefile \
examples/inspectors/Makefile \
examples/inspectors/data_log/Makefile \
examples/inspectors/dpx/Makefile \
examples/ips_options/Makefile \
examples/ips_options/find/Makefile \
examples/ips_options/ips_pkt_num/Makefile \
examples/ips_options/ips_urg/Makefile \
examples/loggers/Makefile \
examples/loggers/alert_ex/Makefile \
examples/loggers/alert_lua/Makefile \
examples/loggers/alert_unixsock/Makefile \
examples/loggers/log_null/Makefile \
examples/search_engines/Makefile \
examples/search_engines/lowmem/Makefile \
examples/so_rules/Makefile \
examples/so_rules/sid_18758/Makefile
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
