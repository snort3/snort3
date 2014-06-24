#--------------------------------------------------------------------------
# this file has the following sections:
#
# initialization
# host magic
# Checks for programs.
# visibility foo
# Checks for typedefs, structures, and compiler characteristics.
# vars
# enables
# with foo
# Checks for header files.
# Checks for libraries.
# DAQ foo
# outputs
#
# if you add an AC_DEFINE() for a symbol that appears in an exported
# header, you must also add that symbol to CPPFLAGS.  This ensures that
# external modules like those in examples can use pkg-config to get the
# same symbols Snort did.  See PERF_PROFILING for an example.
# 
# those should be going to AM_CPPFLAGS but adding the include paths breaks
# with both += and x='$x ...' forms.
#--------------------------------------------------------------------------
# initialization
#--------------------------------------------------------------------------

AC_INIT([snort], [2.10.091])
AC_PREREQ([2.68])

AC_CONFIG_SRCDIR([src/main.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

LT_INIT

AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_LIBTOOL
AC_C_BIGENDIAN
AC_C_INLINE

AM_CXXFLAGS="-std=c++11"
AX_CXX_COMPILE_STDCXX_11

#--------------------------------------------------------------------------
# host magic :(
#--------------------------------------------------------------------------

AC_CANONICAL_HOST

linux="no"
macos="no"

case "$host" in
  *-openbsd*)
    AC_DEFINE([OPENBSD],[1],[Define if OpenBSD])
    ;;
  *-sgi-irix*)
    AC_DEFINE([IRIX],[1],[Define if Irix])
    ;;
  *-solaris*)
    AC_DEFINE([SOLARIS],[1],[Define if Solaris])
    ;;
  *-sunos*)
    AC_DEFINE([SUNOS],[1],[Define if SunOS])
    ;;
  *-linux*)
    linux="yes"
    AC_DEFINE([LINUX],[1],[Define if Linux])
    ;;
  *-hpux*)
    AC_DEFINE([HPUX],[1],[Define if HP-UX])
    ;;
  *-freebsd*)
    AC_DEFINE([FREEBSD],[1],[Define if FreeBSD])
    ;;
  *-bsdi*)
    AC_DEFINE([BSDI],[1],[Define if BSDi])
    ;;
  *-aix*)
    AC_DEFINE([AIX],[1],[Define if AIX])
    ;;
  *-osf*)
    AC_DEFINE([OSF1],[1],[Define if OSF])
    ;;
  *-tru64*)
    AC_DEFINE([OSF1],[1],[Define if Tru64])
    ;;
  *-apple*)
    macos="yes"
    AC_DEFINE([MACOS],[1],[Define if MacOS])
esac

#--------------------------------------------------------------------------
# Checks for programs.
#--------------------------------------------------------------------------

# FIXIT should not need AM_CONIDTIONAL() here
AC_CHECK_PROG(have_asciidoc,asciidoc,yes,no)

AM_CONDITIONAL(MAKE_HTML_DOC, [test "x$have_asciidoc" = "xyes"])

# FIXIT should not need AM_CONIDTIONAL() here
AC_CHECK_PROG(have_dblatex,dblatex,yes,no)

AM_CONDITIONAL(MAKE_PDF_DOC, [test "x$have_dblatex" = "xyes"])

#--------------------------------------------------------------------------
# visibility foo
#--------------------------------------------------------------------------

# modified from gnulib/m4/visibility.m4
AC_DEFUN([CC_VISIBILITY],
[
    AC_REQUIRE([AC_PROG_CC])
    AC_MSG_CHECKING([for visibility support])
    AC_CACHE_VAL(gl_cv_cc_visibility, [
        gl_save_CFLAGS="$CFLAGS"
        # Add -Werror flag since some compilers, e.g. icc 7.1, don't support it,
        # but only warn about it instead of compilation failing
        CFLAGS="$CFLAGS -Werror -fvisibility=hidden"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
            extern __attribute__((__visibility__("hidden"))) int hiddenvar;
            extern __attribute__((__visibility__("default"))) int exportedvar;
            extern __attribute__((__visibility__("hidden"))) int hiddenfunc (void);
            extern __attribute__((__visibility__("default"))) int exportedfunc (void);]],
            [[]])],
            [gl_cv_cc_visibility="yes"],
            [gl_cv_cc_visibility="no"])
    ])
    AC_MSG_RESULT([$gl_cv_cc_visibility])
    CFLAGS="$gl_save_CFLAGS"
    if test "x$gl_cv_cc_visibility" = "xyes"; then
        # FIXIT should be hidden, default (visible) is workaround
        AM_CXXFLAGS="$AM_CXXFLAGS -fvisibility=default"
        AC_DEFINE([HAVE_VISIBILITY],[1],
            [Define if the compiler supports visibility declarations.])
    fi
])
CC_VISIBILITY()

#--------------------------------------------------------------------------
# Checks for typedefs, structures, and compiler characteristics.
#--------------------------------------------------------------------------

#AC_CHECK_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_CHECK_SIZEOF([char])
AC_CHECK_SIZEOF([short])
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([long int])
AC_CHECK_SIZEOF([long long int])
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long int])
AC_CHECK_SIZEOF([unsigned long long int])

# Check for int types
AC_CHECK_TYPES([uint8_t,uint16_t,uint32_t,uint64_t])
AC_CHECK_TYPES([int8_t,int16_t,int32_t,int64_t])

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_FUNC_STRTOD
AC_CHECK_FUNCS([endgrent endpwent ftruncate getcwd gettimeofday inet_ntoa isascii localtime_r memchr memmove memset mkdir select socket strcasecmp strchr strdup strerror strncasecmp strrchr strstr strtol strtoul])

#--------------------------------------------------------------------------
# vars
#--------------------------------------------------------------------------

AC_ARG_VAR(SIGNAL_SNORT_RELOAD, set the SIGNAL_SNORT_RELOAD value)

if test "x$SIGNAL_SNORT_RELOAD" != "x" ; then
   AC_DEFINE_UNQUOTED([SIGNAL_SNORT_RELOAD], [$SIGNAL_SNORT_RELOAD], [Set by user])
fi

AC_ARG_VAR(SIGNAL_SNORT_DUMP_STATS, set the SIGNAL_SNORT_DUMP_STATS value)

if test "x$SIGNAL_SNORT_DUMP_STATS" != "x" ; then
   AC_DEFINE_UNQUOTED([SIGNAL_SNORT_DUMP_STATS], [$SIGNAL_SNORT_DUMP_STATS], [Set by user])
fi

AC_ARG_VAR(SIGNAL_SNORT_ROTATE_STATS, set the SIGNAL_SNORT_ROTATE_STATS value)

if test "x$SIGNAL_SNORT_ROTATE_STATS" != "x" ; then
   AC_DEFINE_UNQUOTED([SIGNAL_SNORT_ROTATE_STATS], [$SIGNAL_SNORT_ROTATE_STATS], [Set by user])
fi

AC_ARG_VAR(SIGNAL_SNORT_READ_ATTR_TBL, set the SIGNAL_SNORT_READ_ATTR_TBL value)

if test "x$SIGNAL_SNORT_READ_ATTR_TBL" != "x" ; then
   AC_DEFINE_UNQUOTED([SIGNAL_SNORT_READ_ATTR_TBL], [$SIGNAL_SNORT_READ_ATTR_TBL], [Set by user])
fi

#--------------------------------------------------------------------------
# enables
#--------------------------------------------------------------------------

AM_CONDITIONAL(LINUX, [test "x$linux" = "xyes"])

AC_ARG_ENABLE(static-inspectors,
    [  --disable-static-inspectors    do not include inspectors in binary ],
       static_inspectors="$enableval", static_inspectors="yes")

AM_CONDITIONAL(STATIC_INSPECTORS, [test "x$static_inspectors" = "xyes"])

if test "x$static_inspectors" = "xyes"; then
    AC_DEFINE(STATIC_INSPECTORS, [1], [include internal inspectors in binary])
fi

AC_ARG_ENABLE(static-loggers,
    [  --disable-static-loggers    do not include loggers in binary ],
       static_loggers="$enableval", static_loggers="yes")

AM_CONDITIONAL(STATIC_LOGGERS, [test "x$static_loggers" = "xyes"])

if test "x$static_loggers" = "xyes"; then
    AC_DEFINE(STATIC_LOGGERS, [1], [include internal loggers in binary])
fi

AC_ARG_ENABLE(static-ips-options,
    [  --disable-static-ips-options    do not include ips options in binary ],
       static_ips_options="$enableval", static_ips_options="yes")

AM_CONDITIONAL(STATIC_IPS_OPTIONS, [test "x$static_ips_options" = "xyes"])

if test "x$static_ips_options" = "xyes"; then
    AC_DEFINE(STATIC_IPS_OPTIONS, [1],
        [include internal ips options in binary])
fi

AC_ARG_ENABLE(static-search-engines,
    [  --disable-static-search-engines    do not include search engines in binary ],
       static_search_engines="$enableval", static_search_engines="yes")

AM_CONDITIONAL(STATIC_SEARCH_ENGINES, [test "x$static_search_engines" = "xyes"])

if test "x$static_search_engines" = "xyes"; then
    AC_DEFINE(STATIC_SEARCH_ENGINES, [1], [include internal inspectors in
                                      binary])
fi

AC_ARG_ENABLE(static-codecs,
    [  --disable-static-codecs    do not include codecs in binary ],
       static_codecs="$enableval", static_codecs="yes")

AM_CONDITIONAL(STATIC_CODECS, [test "x$static_codecs" = "xyes"])

if test "x$static_codecs" = "xyes"; then
    AC_DEFINE(STATIC_CODECS, [1], [include internal decoders in
                                      binary])
fi

AC_ARG_ENABLE(valgrind,
[  --enable-valgrind        Only use if you are testing with valgrind.],
       enable_valgrind="$enableval", enable_valgrind="no")

if test "x$enable_valgrind" = "xyes"; then
    AC_DEFINE([VALGRIND_TESTING],[1],[Workarounds for valgrind testing])
fi

AC_ARG_ENABLE(ppm,
[  --disable-ppm            Disable packet/rule performance monitor],
       enable_ppm="$enableval", enable_ppm="yes")

if test "x$enable_ppm" = "xyes"; then
    AC_DEFINE(PPM_MGR, [1], [build ppm manager])
fi

AC_ARG_ENABLE(ppm-test,
[  --enable-ppm-test        Enable packet/rule performance monitor for readback],
       enable_ppm_test="$enableval", enable_ppm_test="no")

if test "x$enable_ppm_test" = "xyes"; then
    AC_DEFINE(PPM_TEST, [1], [build ppm manager for readback])
fi

AC_ARG_ENABLE(perfprofiling,
[  --disable-perfprofiling  Disable preprocessor and rule performance profiling],
       enable_perfprofiling="$enableval", enable_perfprofiling="yes")

if test "x$enable_perfprofiling" = "xyes"; then
    CPPFLAGS="$CPPFLAGS -DPERF_PROFILING"
    AC_DEFINE(PERF_PROFILING, [1], [enable profiling])
fi

AC_ARG_ENABLE(linux-smp-stats,
[  --enable-linux-smp-stats Enable statistics reporting through proc],
       enable_linux_smp_stats="$enableval", enable_linux_smp_stats="no")

AM_CONDITIONAL(BUILD_PROCPIDSTATS, test "x$enable_linux_smp_stats" = "xyes")

if test "x$enable_linux_smp_stats" = "xyes"; then
    AC_DEFINE(LINUX_SMP, [1], [enable proc stats])
fi

AC_ARG_ENABLE(debug-msgs,
[  --enable-debug-msgs      Enable debug printing options (bugreports and developers only)],
       enable_debug_msgs="$enableval", enable_debug_msgs="no")

if test "x$enable_debug_msgs" = "xyes"; then
    CPPFLAGS="$CPPFLAGS -DDEBUG_MSGS"
    AC_DEFINE(DEBUG_MSGS, [1], [enalbe debug messages])
fi

AC_ARG_ENABLE(debug,
[  --enable-debug           Enable debugging options (bugreports and developers only)],
       enable_debug="$enableval", enable_debug="no")

if test "x$enable_debug" = "xyes"; then
    CFLAGS="$CFLAGS -g"
    CPPFLAGS="$CPPFLAGS -DDEBUG"
    AC_DEFINE(DEBUG, [1], [enable debug build])
else
    # disable assert()ions
    AC_DEFINE(NDEBUG, [1], [disable assertions])
fi

AC_ARG_ENABLE(gdb,
[  --enable-gdb             Enable gdb debugging information],
       enable_gdb="$enableval", enable_gdb="no")

if test "x$enable_gdb" = "xyes"; then
    CFLAGS="$CFLAGS -g -ggdb"
fi

AC_ARG_ENABLE(profile,
[  --enable-profile         Enable profiling options (developers only)],
       enable_profile="$enableval", enable_profile="no")

if test "x$enable_profile" = "xyes"; then
    if test -n "$GCC"; then
        CFLAGS="$CFLAGS -pg"
    fi
    AC_DEFINE(PROFILE, [1], [enable profiling])
fi

AC_ARG_ENABLE(sourcefire,
[  --enable-sourcefire      Enable Sourcefire specific build options, encompasing --enable-perfprofiling and --enable-ppm],
       enable_sourcefire="$enableval", enable_sourcefire="no")

if test "x$enable_sourcefire" = "xyes"; then
    AC_DEFINE(SOURCEFIRE, [1], [enable sourcefire tweaks])
    AC_DEFINE(PPM_MGR, [1], [enable ppm])
    AC_DEFINE(PERF_PROFILING, [1], [enable profiling])
    CPPFLAGS="$CPPFLAGS -DPERF_PROFILING"
fi

AC_ARG_ENABLE(corefiles,
[  --disable-corefiles      Prevent Snort from generating core files],
       enable_corefiles="$enableval", enable_corefiles="yes")

if test "x$enable_corefiles" = "xno"; then
    AC_DEFINE(NOCOREFILE, [1], [do not generate a core file on segfault etc.])
fi

AC_ARG_ENABLE(non-ether-decoders,
[  --enable-non-ether-decoders  Enable non Ethernet decoders.],
       enable_non_ether_decoders="$enableval", enable_non_ether_decoders="no")

if test "x$enable_non_ether_decoders" = "xno"; then
    CPPFLAGS="$CPPFLAGS -DNO_NON_ETHER_DECODER"
    AC_DEFINE(NO_NON_ETHER_DECODER, [1], [do not build non-ethernet decoders])
fi
  
AM_CONDITIONAL(ENABLE_NON_ETHER_DECODER, test "x$enable_non_ether_decoders" = "xyes")

AC_ARG_ENABLE(intel_soft_cpm,
[  --enable-intel-soft-cpm  Enable Intel Soft CPM support],
       enable_intel_soft_cpm="$enableval", enable_intel_soft_cpm="no")

AM_CONDITIONAL(HAVE_INTEL_SOFT_CPM, test "x$enable_intel_soft_cpm" = "xyes")

if test "x$enable_intel_soft_cpm" = "xyes"; then
    AC_DEFINE(INTEL_SOFT_CPM, [1], [enable intel cpm support in build])
fi

AC_ARG_ENABLE(unit_tests,
    [  --enable-unit-tests      Build unit tests],
       enable_unit_tests="$enableval", enable_unit_tests="no")

if test "x$enable_unit_tests" = "xyes"; then
    AC_DEFINE(UNIT_TEST, [1], [enable unit tests in build])
fi

AM_CONDITIONAL(BUILD_UNIT_TESTS, test "x$enable_unit_tests" = "xyes")

AC_ARG_ENABLE(large-pcap,
[  --enable-large-pcap      Enable support for pcaps larger than 2 GB],
      enable_large_pcap="$enableval", enable_large_pcap="no")

if test "x$enable_large_pcap" = "xyes"; then
    CPPFLAGS="${CPPFLAGS} -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64"
fi

#--------------------------------------------------------------------------
# with foo
#--------------------------------------------------------------------------

AC_ARG_WITH(libpcap_includes,
	[  --with-pcap-includes=DIR    libpcap include directory],
	[with_libpcap_includes="$withval"],[with_libpcap_includes="no"])

if test "x$with_libpcap_includes" != "xno"; then
   CPPFLAGS="${CPPFLAGS} -I${with_libpcap_includes}"
fi

AC_ARG_WITH(libpcap_libraries,
	[  --with-pcap-libraries=DIR   libpcap library directory],
	[with_libpcap_libraries="$withval"],[with_libpcap_libraries="no"])

if test "x$with_libpcap_libraries" != "xno"; then
   LDFLAGS="${LDFLAGS} -L${with_libpcap_libraries}"
fi

AC_ARG_WITH(luajit_includes,
	[  --with-luajit-includes=DIR    luajit include directory],
	[with_luajit_includes="$withval"],[with_luajit_includes="no"])

if test "x$with_luajit_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_luajit_includes}"
fi

AC_ARG_WITH(luajit_libraries,
	[  --with-luajit-libraries=DIR   luajit library directory],
	[with_luajit_libraries="$withval"],[with_luajit_libraries="no"])

if test "x$with_luajit_libraries" != "xno"; then
    LDFLAGS="${LDFLAGS} -L${with_luajit_libraries} -lluajit-5.1"

    if test "x$macos" != "xno"; then
        LDFLAGS="${LDFLAGS} -pagezero_size 10000 -image_base 100000000"
    fi
fi

AC_ARG_WITH(libpcre_includes,
       [  --with-pcre-includes=DIR    libpcre include directory],
       [with_libpcre_includes="$withval"],[with_libpcre_includes="no"])

if test "x$with_libpcre_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libpcre_includes}"
    ICONFIGFLAGS="${ICONFIGFLAGS} -I${with_libpcre_includes}"
else
    CPPFLAGS="${CPPFLAGS} `pcre-config --cflags`"
fi

AC_ARG_WITH(libpcre_libraries,
       [  --with-pcre-libraries=DIR   libpcre library directory],
       [with_libpcre_libraries="$withval"],[with_libpcre_libraries="no"])

if test "x$with_libpcre_libraries" != "xno"; then
    LDFLAGS="${LDFLAGS}  -L${with_libpcre_libraries}"
else
    LDFLAGS="${LDFLAGS} `pcre-config --libs`"
fi

AC_ARG_WITH(openssl_includes,
       [  --with-openssl-includes=DIR    openssl include directory],
       [with_openssl_includes="$withval"],[with_openssl_includes="no"])

if test "x$with_openssl_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_openssl_includes}"
    ICONFIGFLAGS="${ICONFIGFLAGS} -I${with_openssl_includes}"
fi

AC_ARG_WITH(openssl_libraries,
       [  --with-openssl-libraries=DIR   openssl library directory],
       [with_openssl_libraries="$withval"],[with_openssl_libraries="no"])

if test "x$with_openssl_libraries" != "xno"; then
    LDFLAGS="${LDFLAGS}  -L${with_openssl_libraries}"
fi

AC_ARG_WITH(dnet_includes,
    [  --with-dnet-includes=DIR       libdnet include directory],
    [with_dnet_includes="$withval"],[with_dnet_includes="no"])

if test "x$with_dnet_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_dnet_includes}"
else
    CPPFLAGS="${CPPFLAGS} `dnet-config --cflags 2>/dev/null`"
fi

AC_ARG_WITH(dnet_libraries,
    [  --with-dnet-libraries=DIR      libdnet library directory],
    [with_dnet_libraries="$withval"],[with_dnet_libraries="no"])

if test "x$with_dnet_libraries" != "xno"; then
    LDFLAGS="${LDFLAGS} -L${with_dnet_libraries}"
else
    LDFLAGS="${LDFLAGS} `dnet-config --libs 2>/dev/null`"
fi

AC_ARG_WITH(daq_includes,
	[  --with-daq-includes=DIR        DAQ include directory],
	[with_daq_includes="$withval"],[with_daq_includes="no"])

if test "x$with_daq_includes" != "xno"; then
   CPPFLAGS="${CPPFLAGS} -I${with_daq_includes}"
   ICONFIGFLAGS="${ICONFIGFLAGS} -I${with_daq_includes}"
fi

AC_ARG_WITH(daq_libraries,
	[  --with-daq-libraries=DIR       DAQ library directory],
	[with_daq_libraries="$withval"],[with_daq_libraries="no"])

if test "x$with_daq_libraries" != "xno"; then
   LDFLAGS="${LDFLAGS} -L${with_daq_libraries}"
fi

AC_ARG_WITH(intel_soft_cpm_includes,
	[  --with-intel-soft-cpm-includes=DIR      Intel Soft CPM include directory],
	[with_intel_soft_cpm_includes="$withval"],[with_intel_soft_cpm_includes="no"])

if test "x$with_intel_soft_cpm_includes" != "xno"; then
    enable_intel_soft_cpm="yes"
    CPPFLAGS="${CPPFLAGS} -I${with_intel_soft_cpm_includes}"
fi

AC_ARG_WITH(intel_soft_cpm_libraries,
	[  --with-intel-soft-cpm-libraries=DIR     Intel Soft CPM library directory],
	[with_intel_soft_cpm_libraries="$withval"],[with_intel_soft_cpm_libraries="no"])

if test "x$with_intel_soft_cpm_libraries" != "xno"; then
    enable_intel_soft_cpm="yes"
    LDFLAGS="${LDFLAGS} -L${with_intel_soft_cpm_libraries}"
    LIBS="${LIBS} -lpm"
fi

#--------------------------------------------------------------------------
# Checks for header files.
#--------------------------------------------------------------------------

AC_FUNC_ALLOCA
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h libintl.h limits.h malloc.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h wchar.h])

# Verify that we have the headers
SHA_H=""
OPENSSL_SHA_L=""
AC_CHECK_HEADERS([openssl/sha.h],, SHA_H="no")

if test "x$SHA_H" != "xno"; then
    AC_CHECK_LIB(crypto, [SHA256_Init],, OPENSSL_SHA_L="no")
    if test "x$OPENSSL_SHA_L" != "xno"; then
        AC_DEFINE([HAVE_OPENSSL_SHA],[1], [openssl SHA available])
    fi
fi

AC_CHECK_HEADERS(dnet.h,,DNET_H="no")
AC_CHECK_HEADERS(dumbnet.h,,DUMBNET_H="no")

if test "x$DNET_H" = "xno" -a "x$DUMBNET_H" = "xno"; then
    echo
    echo "   ERROR!  dnet header not found, go get it from"
    echo "   http://code.google.com/p/libdnet/ or use the --with-dnet-*"
    echo "   options, if you have it installed in an unusual place"
    exit
fi

#--------------------------------------------------------------------------
# Checks for libraries.
#--------------------------------------------------------------------------

LPCAP=""
AC_CHECK_LIB(pcap, pcap_datalink,, LPCAP="no")

# If both the AC_CHECK_LIB for normal pcap and pfring-enabled pcap fail then exit.
if test "x$LPCAP" = "xno"; then
  if test "x$LPFRING_PCAP" = "xno"; then
    echo
    echo "   ERROR!  Libpcap library/headers (libpcap.a (or .so)/pcap.h)"
    echo "   not found, go get it from http://www.tcpdump.org"
    echo "   or use the --with-pcap-* options, if you have it installed"
    echo "   in unusual place.  Also check if your libpcap depends on another"
    echo "   shared library that may be installed in an unusual place"
    exit 1
  fi
fi

AC_MSG_CHECKING([for pcap_lex_destroy])
AC_RUN_IFELSE(
[AC_LANG_PROGRAM(
[[
#include <pcap.h>
]],
[[
   pcap_lex_destroy();
]])],
[have_pcap_lex_destroy="yes"],
[have_pcap_lex_destroy="no"])
AC_MSG_RESULT($have_pcap_lex_destroy)
if test "x$have_pcap_lex_destroy" = "xyes"; then
    AC_DEFINE([HAVE_PCAP_LEX_DESTROY],[1],[Can cleanup lex buffer stack created by pcap bpf filter])
fi

AC_MSG_CHECKING([for pcap_lib_version])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[#include <pcap.h>]],
        [[pcap_lib_version();]]
    )],
    [have_pcap_lib_version="yes"],
    [have_pcap_lib_version="no"]
)
AC_MSG_RESULT($have_pcap_lib_version)

if test "x$have_pcap_lib_version" = "xyes"; then
    AC_DEFINE([HAVE_PCAP_LIB_VERSION],[1],
        [Can output the library version.])
fi

# PCRE configuration (required)
# Verify that we have the headers
PCRE_H=""
AC_CHECK_HEADERS(pcre.h,, PCRE_H="no")
if test "x$PCRE_H" = "xno"; then
  echo
  echo "   ERROR!  Libpcre header not found."
  echo "   Get it from http://www.pcre.org"
  exit 1
fi

# Verify that we have the library
PCRE_L=""
pcre_version_six=""
AC_CHECK_LIB(pcre, pcre_compile, ,PCRE_L="no")
if test "x$PCRE_L" = "xno"; then
    echo
    echo "   ERROR!  Libpcre library not found."
    echo "   Get it from http://www.pcre.org"
    echo
    exit 1
else
    AC_MSG_CHECKING(for libpcre version 6.0 or greater)
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pcre.h>]], [[
       #if (PCRE_MAJOR < 6)
       #error "Version failure"
       #else
       int a, b = 0, c = 0, d = 0;
       pcre *tmp = NULL;
       a = pcre_copy_named_substring(tmp, "", &b, c, "", "", d);
       #endif
      ]])],[pcre_version_six="yes"],[pcre_version_six="no"])
fi

if test "x$pcre_version_six" != "xyes"; then
    AC_MSG_RESULT(no)
    echo
    echo "    ERROR!  Libpcre library version >= 6.0 not found."
    echo "    Get it from http://www.pcre.org"
    echo
    exit 1
else
    AC_MSG_RESULT(yes)
fi

AC_CHECK_LIB(dnet, eth_set,,[DNET="no"])
AC_CHECK_LIB(dumbnet, eth_set,,[DUMBNET="no"])

if test "x$DNET" = "xno" -a "x$DUMBNET" = "xno"; then
    echo
    echo "   ERROR!  dnet library not found, go get it from"
    echo "   http://code.google.com/p/libdnet/ or use the --with-dnet-*"
    echo "   options, if you have it installed in an unusual place"
    exit
fi

Z_LIB=""
AC_CHECK_HEADERS(zlib.h,, Z_LIB="no")
if test "x$Z_LIB" = "xno"; then
    echo
    echo "   ERROR!  zlib header not found, go get it from"
    echo "   http://www.zlib.net"
    exit
fi

Z_LIB=""
AC_CHECK_LIB(z, inflate,, Z_LIB="no")
if test "x$Z_LIB" = "xno"; then
    echo
    echo "   ERROR!  zlib library not found, go get it from"
    echo "   http://www.zlib.net"
    exit
fi
LIBS="$LIBS -lz"

AC_CHECK_LIB(dl, dlsym, DLLIB="yes", DLLIB="no")

if test "x$enable_unit_tests" = "xyes"; then
    AC_CHECK_LIB(check,srunner_create)
fi

#--------------------------------------------------------------------------
# DAQ foo
#--------------------------------------------------------------------------

AC_ARG_ENABLE(static_daq,
[  --disable-static-daq     Link static DAQ modules.],
       enable_static_daq="$enableval", enable_static_daq="yes")

if test "$DLLIB" != "no"; then
    LIBS="${LIBS} -ldl"
else
    AC_CHECK_LIB(c, dlsym, DLLIB="yes", DLLIB="no")
    if test "$DLLIB" = "no"; then
       echo
       echo "   ERROR!  programmatic interface to dynamic link loader"
       echo "   not found.  Cannot build Snort."
       echo
       exit 1
    fi
fi

if test "x$enable_static_daq" = "xyes"; then
    LDAQ=""
    LIBS="${LIBS} `daq-modules-config --static --libs`"
    AC_CHECK_LIB([daq_static], [daq_load_modules],
        [LIBS="-ldaq_static ${LIBS}"], [LDAQ="no"], [ ])

    if test "x$LDAQ" = "xno"; then
        echo
        echo "   ERROR!  daq_static library not found, go get it from"
        echo "   http://www.snort.org/."
        #AC_MSG_ERROR("Fatal!")  # FIXTHIS switch over to this macro
        exit 1                   # instead of raw exits!
    fi
else
    LDAQ=""
    AC_CHECK_LIB([daq], [daq_load_modules],
        [LIBS="${LIBS} -ldaq"], [LDAQ="no"], [ ])

    if test "x$LDAQ" = "xno"; then
        echo
        echo "   ERROR!  daq library not found, go get it from"
        echo "   http://www.snort.org/."
        #AC_MSG_ERROR("Fatal!")
        exit 1
    fi
fi

AC_MSG_CHECKING([for daq address space ID])

AC_RUN_IFELSE(
[AC_LANG_PROGRAM(
[[
#include <daq.h>
]],
[[
   DAQ_PktHdr_t hdr;
   hdr.address_space_id = 0;
]])],
[have_daq_address_space_id="yes"],
[have_daq_address_space_id="no"])

AC_MSG_RESULT($have_daq_address_space_id)

if test "x$have_daq_address_space_id" = "xyes"; then
    AC_DEFINE([HAVE_DAQ_ADDRESS_SPACE_ID],[1],
        [DAQ version supports address space ID in header.])
fi

#--------------------------------------------------------------------------
# outputs
#--------------------------------------------------------------------------

# :(
# FIXIT should be using AM_* flavors instead
CFLAGS="${CFLAGS} ${CCONFIGFLAGS}"
CFLAGS=`echo $CFLAGS | sed -e 's/-I\/usr\/include //g'`
CPPFLAGS="${CPPFLAGS} ${CONFIGFLAGS}"
CPPFLAGS=`echo $CPPFLAGS | sed -e 's/-I\/usr\/include //g'`

CXXFLAGS="$CFLAGS"
echo "$AM_CFLAGS $CFLAGS" > cflags.out
echo "$AM_CPPFLAGS $CPPFLAGS" > cppflags.out

AM_CPPFLAGS='-I$(top_srcdir) -I$(top_srcdir)/src -I$(top_srcdir)/src/main -I$(top_srcdir)/src/parser -I$(top_srcdir)/src/utils -I$(top_srcdir)/src/loggers -I$(top_srcdir)/src/time -I$(top_srcdir)/src/protocols -I$(top_srcdir)/src/network_inspectors -I$(top_srcdir)/src/log -I$(top_srcdir)/src/events -I$(top_srcdir)/src/sfip -I$(top_srcdir)/src/detection -I$(top_srcdir)/src/hash' 

AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CXXFLAGS)
AC_SUBST(CONFIGFLAGS)
AC_SUBST(CCONFIGFLAGS)
AC_SUBST(ICONFIGFLAGS)

AC_CONFIG_FILES([ \
snort.pc \
Makefile \
src/Makefile \
src/actions/Makefile \
src/codecs/Makefile \
src/codecs/root/Makefile \
src/codecs/link/Makefile \
src/codecs/ip/Makefile \
src/codecs/misc/Makefile \
src/control/Makefile \
src/detection/Makefile \
src/events/Makefile \
src/file_api/Makefile \
src/file_api/libs/Makefile \
src/filters/Makefile \
src/flow/Makefile \
src/framework/Makefile \
src/hash/Makefile \
src/helpers/Makefile \
src/ips_options/Makefile \
src/log/Makefile \
src/loggers/Makefile    \
src/main/Makefile \
src/managers/Makefile \
src/stream/Makefile \
src/stream/base/Makefile \
src/stream/ip/Makefile \
src/stream/icmp/Makefile \
src/stream/tcp/Makefile \
src/stream/udp/Makefile \
src/network_inspectors/Makefile \
src/network_inspectors/arp_spoof/Makefile \
src/network_inspectors/normalize/Makefile \
src/network_inspectors/perf_monitor/Makefile \
src/network_inspectors/port_scan/Makefile \
src/packet_io/Makefile \
src/parser/Makefile \
src/service_inspectors/Makefile     \
src/service_inspectors/back_orifice/Makefile \
src/service_inspectors/ftp_telnet/Makefile \
src/service_inspectors/http_inspect/Makefile \
src/service_inspectors/nhttp_inspect/Makefile \
src/service_inspectors/rpc_decode/Makefile \
src/protocols/Makefile \
src/search_engines/Makefile \
src/sfip/Makefile \
src/sfrt/Makefile \
src/target_based/Makefile \
src/test/Makefile \
src/time/Makefile \
src/utils/Makefile \
lua/Makefile \
doc/Makefile \
etc/Makefile \
tools/Makefile \
tools/u2boat/Makefile \
tools/u2spewfoo/Makefile \
])

AC_OUTPUT

