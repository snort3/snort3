#--------------------------------------------------------------------------
# this file has the following sections:
#
# initialization
# api options
# host magic
# checks for programs
# visibility foo
# typedefs, structures, and compiler characteristics
# basic functions, headers, libs
# vars
# enables
# unit tests
# required libs (daq / sfbpf, dnet, hwloc, luajit, openssl / crypto, pcap, pcre, zlib)
# optional libs (hyperscan, lzma, safec)
# outputs
#
# if you add an AC_DEFINE() for a symbol that appears in an exported
# header, you must also add that symbol to CPPFLAGS.  This ensures that
# external modules like those in examples can use pkg-config to get the
# same symbols Snort did.
#--------------------------------------------------------------------------
# initialization
#--------------------------------------------------------------------------

AC_INIT([snort],[3.0.0-a4],[snort-team@cisco.com])
AC_PREREQ([2.69])

AC_CONFIG_SRCDIR([src/main.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h src/framework/api_options.h])

AM_INIT_AUTOMAKE(foreign nostdinc)
AM_SILENT_RULES([yes])

AC_PROG_CC([clang gcc])
AC_PROG_CXX([clang++ g++])
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_C_BIGENDIAN
AC_C_INLINE

CFLAGS="-std=gnu99 $CFLAGS"

AX_CXX_COMPILE_STDCXX_11([noext], [mandatory])

LT_INIT

PKG_PROG_PKG_CONFIG

AX_CODE_COVERAGE

#--------------------------------------------------------------------------
# api options
#--------------------------------------------------------------------------

# build options which affect plugin compatibility must be appended to this
# string to ensure issues are caught when loading:

API_OPTIONS=""

# presently such cases were eliminated.  however, if any arise, add a
# statement like the following after the associated AC_DEFINE() statement:

# AC_DEFINE(([HAVE_OPTION],[1], [option-name is enabled])
# API_OPTIONS="$API_OPTIONS option-name"

# API_OPTIONS is #defined in config.h but that file is not exported so it
# is also #defined in api_options.h.

#--------------------------------------------------------------------------
# host magic :(
#--------------------------------------------------------------------------

AC_CANONICAL_HOST

linux="no"
macos="no"

case "$host" in
  *-linux*)
    linux="yes"
    ;;
  *-apple*)
    macos="yes"
esac

#--------------------------------------------------------------------------
# Checks for programs.
#--------------------------------------------------------------------------

AC_CHECK_PROG(have_asciidoc,asciidoc,yes,no)

AM_CONDITIONAL(MAKE_HTML_DOC, [test "x$have_asciidoc" = "xyes"])

AC_CHECK_PROG(have_dblatex,dblatex,yes,no)

AM_CONDITIONAL(MAKE_PDF_DOC, [test "x$have_dblatex" = "xyes" -a "x$have_asciidoc" = "xyes"])

AC_CHECK_PROG(have_w3m,w3m,yes,no)

AM_CONDITIONAL(MAKE_TEXT_DOC, [test "x$have_w3m" = "xyes" -a "x$have_asciidoc" = "xyes"])

#--------------------------------------------------------------------------
# visibility foo (enable it if we can)
#--------------------------------------------------------------------------

gl_VISIBILITY()
CPPFLAGS="$CFLAG_VISIBILITY $CPPFLAGS"

#--------------------------------------------------------------------------
# thread-local storage foo
#--------------------------------------------------------------------------
# FIXIT-L should define a macro for try-compile-link-cache-val idiom
AC_DEFUN([CXX_EXTERN_GNU_TLS],
[
    AC_REQUIRE([AC_PROG_CXX])
    AC_MSG_CHECKING([for extern GNU __thread support])
    gl_save_CPPFLAGS="$CPPFLAGS"

    AC_LANG_PUSH(C++)
    AC_CACHE_VAL(gl_cv_cxx_extern_gnu_tls, [
        CPPFLAGS="-std=c++11 -fPIC -shared -Wl,-undefined,dynamic_lookup"
        AC_LINK_IFELSE([AC_LANG_SOURCE([[
            extern __thread int x;
            void foo() { ++x; }]])],
            [gl_cv_cxx_extern_gnu_tls="yes"],
            [gl_cv_cxx_extern_gnu_tls="no"])
    ])
    AC_LANG_POP()

    AC_MSG_RESULT([$gl_cv_cxx_extern_gnu_tls])
    CPPFLAGS="$gl_save_CPPFLAGS"
])
CXX_EXTERN_GNU_TLS()

AC_DEFUN([CXX_THREAD_LOCAL],
[
    AC_REQUIRE([AC_PROG_CXX])
    AC_MSG_CHECKING([for thread_local keyword support])
    gl_save_CPPFLAGS="$CPPFLAGS"

    AC_LANG_PUSH(C++)
    AC_CACHE_VAL(gl_cv_cxx_thread_local, [
        CPPFLAGS="-std=c++11"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
            thread_local int x;]],
            [[]])],
            [gl_cv_cxx_thread_local="yes"],
            [gl_cv_cxx_thread_local="no"])
    ])
    AC_LANG_POP()

    AC_MSG_RESULT([$gl_cv_cxx_thread_local])
    CPPFLAGS="$gl_save_CPPFLAGS"
])
CXX_THREAD_LOCAL()

#if test "x$gl_cv_cxx_extern_gnu_tls" = "xno"; then
#    if test "x$gl_cv_cxx_thread_local" = "xyes"; then
#        AC_DEFINE([USE_THREAD_LOCAL],[1],
#            [Define if thread_local keyword should be used])
#    else
#        AC_MSG_ERROR([Compiler does not support thread_local OR extern __thread declarations])
#    fi
#fi

#--------------------------------------------------------------------------
# typedefs, structures, and compiler characteristics
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

#--------------------------------------------------------------------------
# basic functions, headers, libs
#--------------------------------------------------------------------------

AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_FUNC_STRTOD
AC_FUNC_ALLOCA

AC_CHECK_FUNCS([endgrent endpwent ftruncate getcwd gettimeofday inet_ntoa isascii localtime_r memchr memmove memset mkdir select socket strcasecmp strchr strdup strerror strncasecmp strrchr strstr strtol strtoul mallinfo malloc_trim])

AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h libintl.h limits.h malloc.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h wchar.h])

AC_CHECK_LIB(dl, dlsym, DLLIB="yes", DLLIB="no")

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

AC_ARG_ENABLE(static-ips-actions,
    AS_HELP_STRING([--disable-static-ips-actions],[do not include ips actions in binary ]),
    static_ips_actions="$enableval", static_ips_actions="yes")

AM_CONDITIONAL(STATIC_IPS_ACTIONS, [test "x$static_ips_actions" = "xyes"])

if test "x$static_ips_actions" = "xyes"; then
    AC_DEFINE(STATIC_IPS_ACTIONS, [1], [include internal ips actions in binary])
fi

AC_ARG_ENABLE(static-inspectors,
    AS_HELP_STRING([--disable-static-inspectors],[do not include inspectors in binary ]),
    static_inspectors="$enableval", static_inspectors="yes")

AM_CONDITIONAL(STATIC_INSPECTORS, [test "x$static_inspectors" = "xyes"])

if test "x$static_inspectors" = "xyes"; then
    AC_DEFINE(STATIC_INSPECTORS, [1], [include internal inspectors in binary])
fi

AC_ARG_ENABLE(static-loggers,
    AS_HELP_STRING([--disable-static-loggers],[do not include loggers in binary ]),
    static_loggers="$enableval", static_loggers="yes")

AM_CONDITIONAL(STATIC_LOGGERS, [test "x$static_loggers" = "xyes"])

if test "x$static_loggers" = "xyes"; then
    AC_DEFINE(STATIC_LOGGERS, [1], [include internal loggers in binary])
fi

AC_ARG_ENABLE(static-ips-options,
    AS_HELP_STRING([--disable-static-ips-options],[do not include ips options in binary ]),
    static_ips_options="$enableval", static_ips_options="yes")

AM_CONDITIONAL(STATIC_IPS_OPTIONS, [test "x$static_ips_options" = "xyes"])

if test "x$static_ips_options" = "xyes"; then
    AC_DEFINE(STATIC_IPS_OPTIONS, [1], [include internal ips options in binary])
fi

AC_ARG_ENABLE(static-search-engines,
    AS_HELP_STRING([--disable-static-search-engines],[do not include search engines in binary ]),
    static_search_engines="$enableval", static_search_engines="yes")

AM_CONDITIONAL(STATIC_SEARCH_ENGINES, [test "x$static_search_engines" = "xyes"])

if test "x$static_search_engines" = "xyes"; then
    AC_DEFINE(STATIC_SEARCH_ENGINES, [1], [include internal search engines in binary])
fi

AC_ARG_ENABLE(static-codecs,
    AS_HELP_STRING([--disable-static-codecs],[do not include codecs in binary ]),
    static_codecs="$enableval", static_codecs="yes")

AM_CONDITIONAL(STATIC_CODECS, [test "x$static_codecs" = "xyes"])

if test "x$static_codecs" = "xyes"; then
    AC_DEFINE(STATIC_CODECS, [1], [include internal decoders in binary])
fi

AC_ARG_ENABLE(shell,
    AS_HELP_STRING([--enable-shell],[enable command line shell support]),
    enable_shell="$enableval", enable_shell="no")

if test "x$enable_shell" = "xyes"; then
    AC_DEFINE(SHELL, [1], [enable shell support])
fi

AM_CONDITIONAL(ENABLE_SHELL, test "x$enable_shell" = "xyes")

AC_ARG_ENABLE(tsc-clock,
    AS_HELP_STRING([--enable-tsc-clock],[use timestamp counter register clock (x86 only)]),
    enable_tsc_clock="$enableval", enable_tsc_clock="no")

if test "x$enable_tsc_clock" = "xyes"; then
    AC_DEFINE(USE_TSC_CLOCK, [1], [enable tsc clock])
fi

AC_ARG_ENABLE(large-pcap,
    AS_HELP_STRING([--enable-large-pcap],[enable support for pcaps larger than 2 GB]),
    enable_large_pcap="$enableval", enable_large_pcap="no")

if test "x$enable_large_pcap" = "xyes"; then
    CPPFLAGS="${CPPFLAGS} -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"
fi

AC_ARG_ENABLE(debug-msgs,
    AS_HELP_STRING([--enable-debug-msgs],[enable debug printing options (bugreports and developers only)]),
    enable_debug_msgs="$enableval", enable_debug_msgs="no")

AM_CONDITIONAL(DEBUG_MSGS, test "x$enable_debug_msgs" = "xyes")

if test "x$enable_debug_msgs" = "xyes"; then
    CPPFLAGS="$CPPFLAGS -DDEBUG_MSGS"
    AC_DEFINE(DEBUG_MSGS, [1], [enable debug messages])
fi

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[enable debugging options (bugreports and developers only)]),
    enable_debug="$enableval", enable_debug="no")

if test "x$enable_debug" = "xyes"; then
    CPPFLAGS="$CPPFLAGS -g -DDEBUG"
    AC_DEFINE(DEBUG, [1], [enable debug build])
else
    # disable assert()ions
    AC_DEFINE(NDEBUG, [1], [disable assertions])
fi

AC_ARG_ENABLE(gdb,
    AS_HELP_STRING([--enable-gdb],[enable gdb debugging information]),
    enable_gdb="$enableval", enable_gdb="no")

if test "x$enable_gdb" = "xyes"; then
    CFLAGS="$CFLAGS -g -ggdb"
    CXXFLAGS="$CXXFLAGS -g -ggdb"
fi

AC_ARG_ENABLE(gprof-profile,
    AS_HELP_STRING([--enable-gprof-profile],[enable gprof profiling output (developers only)]),
    enable_gprof_profile="$enableval", enable_gprof_profile="no")

# FIXIT-L need to check for g++ not gcc
if test "x$enable_gprof_profile" = "xyes"; then
    if test -n "$GCC"; then
        CFLAGS="$CFLAGS -pg"
        CXXFLAGS="$CXXFLAGS -pg"
    fi
    AC_DEFINE(PROFILE, [1], [enable gprof profiling])
fi

AC_ARG_ENABLE(corefiles,
    AS_HELP_STRING([--disable-corefiles],[prevent Snort from generating core files]),
    enable_corefiles="$enableval", enable_corefiles="yes")

if test "x$enable_corefiles" = "xno"; then
    AC_DEFINE(NOCOREFILE, [1], [do not generate a core file on segfault etc.])
fi

AC_ARG_ENABLE(address-sanitizer,
    AS_HELP_STRING([--enable-address-sanitizer],[enable address sanitizer support]),
    [
        AX_CHECK_COMPILE_FLAG([-fsanitize=address], [SANITIZER_CXXFLAGS="$SANITIZER_CXXFLAGS -fsanitize=address"])
        AX_CHECK_COMPILE_FLAG([-fno-omit-frame-pointer], [SANITIZER_CXXFLAGS="$SANITIZER_CXXFLAGS -fno-omit-frame-pointer"])
        AX_CHECK_LINK_FLAG([-fsanitize=address], [SANITIZER_LDFLAGS="$SANITIZER_LDFLAGS -fsanitize=address"], [], [$SANITIZER_LDFLAGS])
        AX_CHECK_LINK_FLAG([-static-libasan], [SANITIZER_LDFLAGS="$SANITIZER_LDFLAGS -static-libasan"], [], [$SANITIZER_LDFLAGS])
    ])

AC_ARG_ENABLE(thread-sanitizer,
    AS_HELP_STRING([--enable-thread-sanitizer],[enable thread sanitizer support]),
    [
        AX_CHECK_COMPILE_FLAG([-fsanitize=thread], [SANITIZER_CXXFLAGS="$SANITIZER_CXXFLAGS -fsanitize=thread"])
        AX_CHECK_COMPILE_FLAG([-fno-omit-frame-pointer], [SANITIZER_CXXFLAGS="$SANITIZER_CXXFLAGS -fno-omit-frame-pointer"])
        AX_CHECK_LINK_FLAG([-fsanitize=thread], [SANITIZER_LDFLAGS="$SANITIZER_LDFLAGS -fsanitize=thread"], [], [$SANITIZER_LDFLAGS])
        AX_CHECK_LINK_FLAG([-static-libtsan], [SANITIZER_LDFLAGS="$SANITIZER_LDFLAGS -static-libtsan"], [], [$SANITIZER_LDFLAGS])
    ])

#--------------------------------------------------------------------------
# compile-time security features
#--------------------------------------------------------------------------

# Based on Debian's hardening options (https://wiki.debian.org/Hardening)
# Desired options:
# CPPFLAGS: -Wdate-time -D_FORTIFY_SOURCE=2
# CFLAGS/CXXFLAGS: -fPIE -fstack-protector-strong -Wformat -Werror=format-security
# LDFLAGS: -fPIE -pie -Wl,-z,relro -Wl,-z,now

AC_ARG_ENABLE(hardened_build,
    AS_HELP_STRING([--enable-hardened-build], [Detect and use compile-time hardening options]))

if test "x$enable_hardened_build" = "xyes"; then

    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS -Werror"

    AX_CHECK_PREPROC_FLAG([-Wdate-time], [HARD_CPPFLAGS="$HARD_CPPFLAGS -Wdate-time"])

    AX_CHECK_PREPROC_FLAG([-D_FORTIFY_SOURCE=2], [HARD_CPPFLAGS="$HARD_CPPFLAGS -D_FORTIFY_SOURCE=2"])

    AX_CHECK_COMPILE_FLAG([-fstack-protector-strong], [HARD_CFLAGS="$HARD_CFLAGS -fstack-protector-strong"])

    AX_CHECK_COMPILE_FLAG([-Wformat], [HARD_CFLAGS="$HARD_CFLAGS -Wformat"])

    AX_CHECK_COMPILE_FLAG([-Werror=format-security], [HARD_CFLAGS="$HARD_CFLAGS -Werror=format-security"])

    AX_CHECK_LINK_FLAG([-Wl,-z,relro], [HARD_LDFLAGS="$HARD_LDFLAGS -Wl,-z,relro"])

    AX_CHECK_LINK_FLAG([-Wl,-z,now], [HARD_LDFLAGS="$HARD_LDFLAGS -Wl,-z,now"])

    CPPFLAGS="$save_CPPFLAGS"

fi

# PIE support gets its own switch since it requires any static libraries Snort wants to link in to
# be built with PIC, which may or may not be feasible for the user.

AC_ARG_ENABLE(pie,
    AS_HELP_STRING([--enable-pie], [Attempt to produce a position-independent executable]))

if test "x$enable_pie" = "xyes"; then

    AX_CHECK_COMPILE_FLAG([-fPIE], [HARD_CFLAGS="$HARD_CFLAGS -fPIE"])

    AX_CHECK_LINK_FLAG([-fPIE -pie], [HARD_LDFLAGS="$HARD_LDFLAGS -fPIE -pie"])

fi

AC_ARG_ENABLE(safec,
    AS_HELP_STRING([--disable-safec], [Do not use libsafec bounds checking even if available]),
    enable_safec="$enableval", enable_safec="yes")

if test "x$enable_safec" = "xyes"; then
    AC_DEFINE(ENABLE_SAFEC, [1], [enable libsafec functions if present])
fi

#--------------------------------------------------------------------------
# C++11 threads
#--------------------------------------------------------------------------

AC_LANG_PUSH([C++])
ax_cxx11_thread_flags="none -pthread"
for flag in $ax_cxx11_thread_flags ; do
    case $flag in
        none)
        AC_MSG_CHECKING([whether C++11 threads work without any flags])
        ;;

        -*)
        AC_MSG_CHECKING([whether C++11 threads work with $flag])
        CXX11_THREAD_CXXFLAGS="$flag"
        ;;
    esac

    save_CXXFLAGS="$CXXFLAGS"
    CXXFLAGS="$CXX11_THREAD_CXXFLAGS $CXXFLAGS"

    AC_RUN_IFELSE([AC_LANG_PROGRAM([#include <iostream>
                   #include <thread>
                   void call_from_thread() { }],
                   [std::thread t1(call_from_thread); t1.join()])],
                   [ax_cxx11_thread_ok=yes],
                   [ax_cxx11_thread_ok=no])

    CXXFLAGS="$save_CXXFLAGS"

    AC_MSG_RESULT([$ax_cxx11_thread_ok])
    if test "x$ax_cxx11_thread_ok" = xyes ; then
        break;
    fi

    CXX11_THREAD_CXXFLAGS=
done
AC_LANG_POP([C++])
if test "x$ax_cxx11_thread_ok" != xyes ; then
    AC_MSG_ERROR([could not find CXXFLAGS that allow C++11 threads to work])
fi
CXXFLAGS="$CXX11_THREAD_CXXFLAGS $CXXFLAGS"

#--------------------------------------------------------------------------
# unit tests
#--------------------------------------------------------------------------

AC_ARG_ENABLE(unit_tests,
    AS_HELP_STRING([--enable-unit-tests],[build unit tests]),
    enable_unit_tests="$enableval", enable_unit_tests="no")

have_cpputest_pc="no"

if test "x$enable_unit_tests" = "xyes"; then
    PKG_CHECK_EXISTS([cpputest], [ have_cpputest_pc="yes" ], [ have_cpputest_pc="no" ])

    if test "x${have_cpputest_pc}" = "xyes" ; then
        CPPUTEST_CPPFLAGS="`${PKG_CONFIG} --cflags cpputest`"
        CPPUTEST_LDFLAGS="`${PKG_CONFIG} --libs cpputest`"
    fi

    AC_DEFINE(UNIT_TEST, [1], [enable unit tests in build])
fi

AM_CONDITIONAL(ENABLE_UNIT_TESTS, test "x$enable_unit_tests" = "xyes")
AM_CONDITIONAL(BUILD_CPPUTESTS, test "x$have_cpputest_pc" = "xyes")

#--------------------------------------------------------------------------
# piglet
#--------------------------------------------------------------------------

AC_ARG_ENABLE(piglet,
    AS_HELP_STRING([--enable-piglet],[build piglet test harness]),
    enable_piglet="$enableval", enable_piglet="no")

if test "x$enable_piglet" = "xyes"; then
    AC_DEFINE(PIGLET, [1], [enable piglet test harness in build])
fi

AM_CONDITIONAL(ENABLE_PIGLET, test "x$enable_piglet" = "xyes")

#--------------------------------------------------------------------------
#--------------------------------------------------------------------------
# Required libraries
#--------------------------------------------------------------------------
#--------------------------------------------------------------------------

#--------------------------------------------------------------------------
# daq / sfbpf
#--------------------------------------------------------------------------

AC_ARG_WITH(daq_includes,
    AS_HELP_STRING([--with-daq-includes=DIR],[DAQ include directory]),
    [with_daq_includes="$withval"],[with_daq_includes="no"])

DAQ_CPPFLAGS=""
if test "x$with_daq_includes" != "xno"; then
    DAQ_CPPFLAGS="-I${with_daq_includes}"
    CPPFLAGS="${CPPFLAGS} ${DAQ_CPPFLAGS}"
fi

AC_ARG_WITH(daq_libraries,
    AS_HELP_STRING([--with-daq-libraries=DIR],[DAQ library directory]),
    [with_daq_libraries="$withval"],[with_daq_libraries="no"])

if test "x$with_daq_libraries" != "xno"; then
    LDFLAGS="${LDFLAGS} -L${with_daq_libraries}"
fi

AC_ARG_ENABLE(static_daq,
    AS_HELP_STRING([--disable-static-daq],[link static DAQ modules]),
    enable_static_daq="$enableval", enable_static_daq="yes")

if test "$DLLIB" != "no"; then
    LIBS="${LIBS} -ldl"
else
    AC_CHECK_LIB(c, dlsym, DLLIB="yes", DLLIB="no")
    if test "$DLLIB" = "no"; then
       echo
       echo "   ERROR:  programmatic interface to dynamic link loader"
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
        echo "   ERROR:  daq_static library not found, go get it from"
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
        echo "   ERROR:  daq library not found, go get it from"
        echo "   http://www.snort.org/."
        #AC_MSG_ERROR("Fatal!")
        exit 1
    fi
fi

AC_CHECK_HEADERS(sfbpf.h,,[SFBPF_H="no"])

if test "x$SFBPF_H" = "xno"; then
    echo
    echo "   ERROR:  sfbpf header not found"
    exit
fi

AC_CHECK_LIB(sfbpf, sfbpf_compile, [LIBS="${LIBS} -lsfbpf"], [SFBPF="no"])

if test "x$SFBPF" = "xno"; then
    echo
    echo "   ERROR:  sfbpf library not found"
    exit
fi

#--------------------------------------------------------------------------
# dnet
#--------------------------------------------------------------------------

AC_ARG_WITH(dnet_includes,
    AS_HELP_STRING([--with-dnet-includes=DIR],[libdnet include directory]),
    [with_dnet_includes="$withval"],[with_dnet_includes="no"])

DNET_CPPFLAGS=""
if test "x$with_dnet_includes" != "xno"; then
    DNET_CPPFLAGS="-I${with_dnet_includes}"
else
    DNET_CPPFLAGS="`dnet-config --cflags 2>/dev/null`"
fi
CPPFLAGS="${CPPFLAGS} ${DNET_CPPFLAGS}"

AC_ARG_WITH(dnet_libraries,
    AS_HELP_STRING([--with-dnet-libraries=DIR],[libdnet library directory]),
    [with_dnet_libraries="$withval"],[with_dnet_libraries="no"])

if test "x$with_dnet_libraries" != "xno"; then
    DNET_LIBS="-L${with_dnet_libraries}"
else
    DNET_LIBS="`dnet-config --libs 2>/dev/null`"
fi
LDFLAGS="${LDFLAGS} ${DNET_LIBS}"

AC_CHECK_HEADERS(dnet.h,,DNET_H="no")
AC_CHECK_HEADERS(dumbnet.h,,DUMBNET_H="no")

if test "x$DNET_H" = "xno" -a "x$DUMBNET_H" = "xno"; then
    echo
    echo "   ERROR:  dnet header not found, go get it from"
    echo "   https://github.com/dugsong/libdnet.git or use the --with-dnet-*"
    echo "   options, if you have it installed in an unusual place"
    exit
fi

AC_CHECK_LIB(dnet, eth_set,,[DNET="no"])
AC_CHECK_LIB(dumbnet, eth_set,,[DUMBNET="no"])

if test "x$DNET" = "xno" -a "x$DUMBNET" = "xno"; then
    echo
    echo "   ERROR:  dnet library not found, go get it from"
    echo "   http://code.google.com/p/libdnet/ or use the --with-dnet-*"
    echo "   options, if you have it installed in an unusual place"
    exit
fi

#--------------------------------------------------------------------------
# hwloc
#--------------------------------------------------------------------------

AC_MSG_CHECKING([for hwloc pkg-config presence])
PKG_CHECK_EXISTS([hwloc], [have_hwloc_pkgconfig="yes"], [have_hwloc_pkgconfig="no"])
AC_MSG_RESULT(${have_hwloc_pkgconfig})

HWLOC_CPPFLAGS=""
if test "${have_hwloc_pkgconfig}" = "yes" ; then
    HWLOC_CPPFLAGS=`${PKG_CONFIG} --cflags hwloc`
    HWLOC_LDFLAGS=`${PKG_CONFIG} --libs-only-L hwloc`
fi

AC_ARG_WITH(hwloc_includes,
    AS_HELP_STRING([--with-hwloc-includes=DIR],[hwloc include directory]),
    [with_hwloc_includes="$withval"],[with_hwloc_includes="no"])

if test "x$with_hwloc_includes" != "xno"; then
    HWLOC_CPPFLAGS="-I${with_hwloc_includes}"
fi

AC_ARG_WITH(hwloc_libraries,
    AS_HELP_STRING([--with-hwloc-libraries=DIR],[hwloc library directory]),
    [with_hwloc_libraries="$withval"],[with_hwloc_libraries="no"])

if test "x$with_hwloc_libraries" != "xno"; then
    HWLOC_LDFLAGS="-L${with_hwloc_libraries}"
fi

CPPFLAGS="${HWLOC_CPPFLAGS} ${CPPFLAGS}"
LDFLAGS="${HWLOC_LDFLAGS} ${LDFLAGS}"

AC_CHECK_HEADERS([hwloc.h], , [AC_MSG_ERROR(hwloc header not found.)])
AC_CHECK_LIB(hwloc, hwloc_set_thread_cpubind, , [AC_MSG_ERROR(Linking against hwloc library failed.)])

#--------------------------------------------------------------------------
# luajit
#--------------------------------------------------------------------------

AC_MSG_CHECKING([for luajit pkg-config presence])
PKG_CHECK_EXISTS([luajit], [ have_luajit_pkgconfig="yes" ], [ have_luajit_pkgconfig="no" ])
AC_MSG_RESULT(${have_luajit_pkgconfig})

LUAJIT_CPPFLAGS=""
if test "${have_luajit_pkgconfig}" = "yes" ; then
    LUAJIT_CPPFLAGS=`${PKG_CONFIG} --cflags luajit`
    LUAJIT_LDFLAGS=`${PKG_CONFIG} --libs-only-L luajit`
fi

AC_ARG_WITH(luajit_includes,
    AS_HELP_STRING([--with-luajit-includes=DIR],[luajit include directory]),
    [with_luajit_includes="$withval"],[with_luajit_includes="no"])

if test "x$with_luajit_includes" != "xno"; then
    LUAJIT_CPPFLAGS="-I${with_luajit_includes}"
fi

AC_ARG_WITH(luajit_libraries,
    AS_HELP_STRING([--with-luajit-libraries=DIR],[luajit library directory]),
    [with_luajit_libraries="$withval"],[with_luajit_libraries="no"])

if test "x$with_luajit_libraries" != "xno"; then
    LUAJIT_LDFLAGS="-L${with_luajit_libraries}"
fi

if test "x$macos" != "xno"; then
    LUAJIT_LDFLAGS="${LUAJIT_LDFLAGS} -pagezero_size 10000 -image_base 100000000"
fi

CPPFLAGS="${CPPFLAGS} ${LUAJIT_CPPFLAGS}"
LDFLAGS="${LDFLAGS} ${LUAJIT_LDFLAGS}"

AC_LANG_PUSH([C++])
AC_CHECK_HEADERS([luajit.h lua.hpp], , [AC_MSG_ERROR("LuaJIT headers not found.")])
AC_CHECK_LIB(luajit-5.1, main, , [AC_MSG_ERROR("Linking against LuaJIT library failed.")])
AC_LANG_POP([C++])

#--------------------------------------------------------------------------
# openssl / crypto
#--------------------------------------------------------------------------

AC_ARG_WITH(openssl_includes,
    AS_HELP_STRING([--with-openssl-includes=DIR],[openssl include directory]),
    [with_openssl_includes="$withval"],[with_openssl_includes="no"])

OPENSSL_CPPFLAGS=""
if test "x$with_openssl_includes" != "xno"; then
    OPENSSL_CPPFLAGS="-I${with_openssl_includes}"
    CPPFLAGS="${CPPFLAGS} ${OPENSSL_CPPFLAGS}"
fi

AC_ARG_WITH(openssl_libraries,
    AS_HELP_STRING([--with-openssl-libraries=DIR],[openssl library directory]),
    [with_openssl_libraries="$withval"],[with_openssl_libraries="no"])

if test "x$with_openssl_libraries" != "xno"; then
    LDFLAGS="${LDFLAGS} -L${with_openssl_libraries}"
fi

AC_CHECK_HEADERS([openssl/md5.h openssl/sha.h openssl/x509.h], , [AC_MSG_ERROR("OpenSSL headers not found.")])
AC_CHECK_LIB([crypto], [MD5_Init], , [AC_MSG_ERROR("OpenSSL crypto library not found.")])

#--------------------------------------------------------------------------
# pcap
#--------------------------------------------------------------------------

AC_ARG_WITH(pcap_includes,
    AS_HELP_STRING([--with-pcap-includes=DIR],[libpcap include directory]),
    [with_libpcap_includes="$withval"],[with_libpcap_includes="no"])

PCAP_CPPFLAGS=""
if test "x$with_libpcap_includes" != "xno"; then
    PCAP_CPPFLAGS="-I${with_libpcap_includes}"
    CPPFLAGS="${CPPFLAGS} ${PCAP_CPPFLAGS}"
fi

AC_ARG_WITH(pcap_libraries,
    AS_HELP_STRING([--with-pcap-libraries=DIR],[libpcap library directory]),
    [with_libpcap_libraries="$withval"],[with_libpcap_libraries="no"])

if test "x$with_libpcap_libraries" != "xno"; then
    LDFLAGS="${LDFLAGS} -L${with_libpcap_libraries}"
fi

LPCAP=""
AC_CHECK_HEADERS([pcap.h],, LPCAP="no")
AC_CHECK_LIB(pcap, pcap_datalink,, LPCAP="no")

if test "x$LPCAP" = "xno"; then
    echo
    echo "   ERROR:  Libpcap library/headers (libpcap.a (or .so)/pcap.h)"
    echo "   not found, go get it from http://www.tcpdump.org"
    echo "   or use the --with-pcap-* options, if you have it installed"
    echo "   in unusual place.  Also check if your libpcap depends on another"
    echo "   shared library that may be installed in an unusual place"
    exit 1
fi

#--------------------------------------------------------------------------
# pcre
#--------------------------------------------------------------------------

AC_MSG_CHECKING([for libpcre pkg-config presence])
PKG_CHECK_EXISTS([libpcre], [ have_libpcre_pkgconfig="yes" ], [ have_libpcre_pkgconfig="no" ])
AC_MSG_RESULT(${have_libpcre_pkgconfig})

PCRE_CPPFLAGS=""
if test "${have_libpcre_pkgconfig}" = "yes" ; then
    PCRE_CPPFLAGS=`${PKG_CONFIG} --cflags libpcre`
    PCRE_LDFLAGS=`${PKG_CONFIG} --libs-only-L libpcre`
fi

AC_ARG_WITH(pcre_includes,
    AS_HELP_STRING([--with-pcre-includes=DIR],[libpcre include directory]),
    [with_libpcre_includes="$withval"],[with_libpcre_includes="no"])

if test "x$with_libpcre_includes" != "xno"; then
    PCRE_CPPFLAGS="-I${with_libpcre_includes}"
elif test "${have_libpcre_pkgconfig}" = "no"; then
    PCRE_CPPFLAGS="`pcre-config --cflags`"
fi

AC_ARG_WITH(pcre_libraries,
    AS_HELP_STRING([--with-pcre-libraries=DIR],[libpcre library directory]),
    [with_libpcre_libraries="$withval"],[with_libpcre_libraries="no"])

if test "x$with_libpcre_libraries" != "xno"; then
    PCRE_LDFLAGS="-L${with_libpcre_libraries}"
elif test "${have_libpcre_pkgconfig}" = "no"; then
    PCRE_LDFLAGS="`pcre-config --libs`"
fi

CPPFLAGS="${CPPFLAGS} ${PCRE_CPPFLAGS}"
LDFLAGS="${LDFLAGS} ${PCRE_LDFLAGS}"

# PCRE configuration (required)
# Verify that we have the headers
PCRE_H=""
AC_CHECK_HEADERS(pcre.h,, PCRE_H="no")
if test "x$PCRE_H" = "xno"; then
  echo
  echo "   ERROR:  Libpcre header not found."
  echo "   Get it from http://www.pcre.org"
  exit 1
fi

# Verify that we have the library
PCRE_L=""
AC_CHECK_LIB(pcre, pcre_compile, ,PCRE_L="no")
if test "x$PCRE_L" = "xno"; then
    echo
    echo "   ERROR:  Libpcre library not found."
    echo "   Get it from http://www.pcre.org"
    echo
    exit 1
fi

#--------------------------------------------------------------------------
# zlib
#--------------------------------------------------------------------------

Z_LIB=""
AC_CHECK_HEADERS(zlib.h,, Z_LIB="no")
if test "x$Z_LIB" = "xno"; then
    echo
    echo "   ERROR:  zlib header not found, go get it from"
    echo "   http://www.zlib.net"
    exit
fi

Z_LIB=""
AC_CHECK_LIB(z, inflate,, Z_LIB="no")
if test "x$Z_LIB" = "xno"; then
    echo
    echo "   ERROR:  zlib library not found, go get it from"
    echo "   http://www.zlib.net"
    exit
fi
LIBS="$LIBS -lz"

#--------------------------------------------------------------------------
#--------------------------------------------------------------------------
# Optional libraries
#--------------------------------------------------------------------------
#--------------------------------------------------------------------------

#--------------------------------------------------------------------------
# flatbuffers (optional)
#--------------------------------------------------------------------------

AC_LANG_PUSH(C++)

AC_ARG_WITH(flatbuffers_includes,
    AS_HELP_STRING([--with-flatbuffers-includes=DIR],[flatbuffers include directory]),
    [with_flatbuffers_includes="$withval"],[with_flatbuffers_includes="no"])

if test "x$with_flatbuffers_includes" != "xno"; then
    FLATBUFFERS_CPPFLAGS="-I${with_flatbuffers_includes}"
fi

AC_ARG_WITH(flatbuffers_libraries,
    AS_HELP_STRING([--with-flatbuffers-libraries=DIR],[flatbuffers library directory]),
    [with_flatbuffers_libraries="$withval"],[with_flatbuffers_libraries="no"])

if test "x$with_flatbuffers_libraries" != "xno"; then
    FLATBUFFERS_LDFLAGS="-L${with_flatbuffers_libraries}"
fi

CPPFLAGS="${CPPFLAGS} ${FLATBUFFERS_CPPFLAGS}"
LDFLAGS="${LDFLAGS} ${FLATBUFFERS_LDFLAGS}"

AC_CHECK_HEADERS(flatbuffers/flatbuffers.h, FBS_HEADERS="yes", FBS_HEADERS="no")

SAVED_LDFLAGS=$LDFLAGS
LDFLAGS="$LDFLAGS -lflatbuffers"
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([#include <flatbuffers/flatbuffers.h>],
    ["flatbuffers::FlatBufferBuilder builder;"])],
    [TEST_LIBS="$TEST_LIBS -lflatbufferes"] [FBS_LIBS="yes"], 
    [AC_MSG_WARN([libflatbuffers is not installed.])])
LDFLAGS=$SAVED_LDFLAGS

if test "x$FBS_LIBS" = "xyes"; then
    if test "x$FBS_HEADERS" != "xno"; then
        AC_DEFINE([HAVE_FLATBUFFERS],[1],[can build flatbuffers code])
        LIBS="${LIBS} -lflatbuffers"
    fi
fi

AC_LANG_POP()

AM_CONDITIONAL([HAVE_FLATBUFFERS], [test "x$FBS_HEADERS" = "xyes"])

#--------------------------------------------------------------------------
# hyperscan (optional)
#--------------------------------------------------------------------------

AC_MSG_CHECKING([for hyperscan >= 4.4.0 pkg-config presence])
PKG_CHECK_EXISTS([libhs >= 4.4.0], [ have_hyperscan_pkgconfig="yes" ], [ have_hyperscan_pkgconfig="no" ])
AC_MSG_RESULT(${have_hyperscan_pkgconfig})

HYPERSCAN_CPPFLAGS=""
if test "${have_hyperscan_pkgconfig}" = "yes" ; then
    HYPERSCAN_CPPFLAGS=`${PKG_CONFIG} --cflags libhs`
    HYPERSCAN_LDFLAGS=`${PKG_CONFIG} --libs-only-L libhs`
fi

AC_ARG_WITH(hyperscan_includes,
    AS_HELP_STRING([--with-hyperscan-includes=DIR],[libhs include directory]),
    [with_hyperscan_includes="$withval"],[with_hyperscan_includes="no"])

if test "x$with_hyperscan_includes" != "xno"; then
    HYPERSCAN_CPPFLAGS="-I${with_hyperscan_includes}"
fi

AC_ARG_WITH(hyperscan_libraries,
    AS_HELP_STRING([--with-hyperscan-libraries=DIR],[libhs library directory]),
    [with_hyperscan_libraries="$withval"],[with_hyperscan_libraries="no"])

if test "x$with_hyperscan_libraries" != "xno"; then
    HYPERSCAN_LDFLAGS="-L${with_hyperscan_libraries}"
fi

CPPFLAGS="${CPPFLAGS} ${HYPERSCAN_CPPFLAGS}"
LDFLAGS="${LDFLAGS} ${HYPERSCAN_LDFLAGS}"

AC_CHECK_HEADERS(hs.h, HS_HEADERS="yes", HS_HEADERS="no")
AC_CHECK_LIB(hs, hs_scan, HS_LIB="yes", HS_LIB="no")

if test "x$HS_LIB" != "xno"; then
    if test "x$HS_HEADERS" != "xno"; then
        AC_DEFINE([HAVE_HYPERSCAN],[1],[can build hyperscan code])
        LIBS="${LIBS} -lhs"
    fi
fi

AM_CONDITIONAL([HAVE_HYPERSCAN], [test "x$HS_HEADERS" = "xyes" -a "x$HS_LIB" = "xyes"])

#--------------------------------------------------------------------------
# lzma (optional)
#--------------------------------------------------------------------------

AC_ARG_WITH(lzma_includes,
    AS_HELP_STRING([--with-lzma-includes=DIR],[liblzma include directory]),
    [with_lzma_includes="$withval"],[with_lzma_includes="no"])

LZMA_CPPFLAGS=""
if test "x$with_lzma_includes" != "xno"; then
    LZMA_CPPFLAGS="-I${with_lzma_includes}"
    CPPFLAGS="${CPPFLAGS} ${LZMA_CPPFLAGS}"
fi

AC_ARG_WITH(lzma_libraries,
    AS_HELP_STRING([--with-lzma-libraries=DIR],[liblzma library directory]),
    [with_lzma_libraries="$withval"],[with_lzma_libraries="no"])

if test "x$with_lzma_libraries" != "xno"; then
    LDFLAGS="${LDFLAGS} -L${with_lzma_libraries}"
fi

AC_CHECK_HEADERS(lzma.h, LZMA_HEADERS="yes", LZMA_HEADERS="no")
AC_CHECK_LIB(lzma, lzma_code, LZMA_LIB="yes", LZMA_LIB="no")

if test "x$LZMA_LIB" != "xno"; then
    if test "x$LZMA_HEADERS" != "xno"; then
        AC_DEFINE([HAVE_LZMA],[1],[can build lzma code])
        LIBS="${LIBS} -llzma"
    fi
fi

#--------------------------------------------------------------------------
# safec (optional)
#--------------------------------------------------------------------------
AC_MSG_CHECKING([for safec pkg-config presence])
PKG_CHECK_EXISTS([safec-1.0], [ have_safec_pkgconfig="yes" ], [ have_safec_pkgconfig="no" ])
AC_MSG_RESULT(${have_safec_pkgconfig})

if test "${have_safec_pkgconfig}" = "yes" ; then
    SAFEC_CFLAGS=`${PKG_CONFIG} --cflags safec-1.0`
    SAFEC_LDFLAGS=`${PKG_CONFIG} --libs-only-L safec-1.0`
fi

CPPFLAGS="${CPPFLAGS} ${SAFEC_CFLAGS}"
LDFLAGS="${LDFLAGS} ${SAFEC_LDFLAGS}"

AC_CHECK_HEADERS(libsafec/safe_lib.h, SAFEC_HEADERS="yes", SAFEC_HEADERS="no")
AC_CHECK_LIB(safec-1.0, memcpy_s, SAFEC_LIB="yes", SAFEC_LIB="no")

if test "x$SAFEC_LIB" != "xno"; then
    if test "x$SAFEC_HEADERS" != "xno"; then
        AC_DEFINE([HAVE_SAFEC],[1],[can build safec code])
        LIBS="${LIBS} -lsafec-1.0"
    fi
fi

#--------------------------------------------------------------------------
# outputs
#--------------------------------------------------------------------------

AC_DEFINE_UNQUOTED([API_OPTIONS], ["$API_OPTIONS"], [plugin api related build options])

if test -n "$SANITIZER_CXXFLAGS" ; then
    CFLAGS="$SANITIZER_CXXFLAGS $CFLAGS"
    CXXFLAGS="$SANITIZER_CXXFLAGS $CXXFLAGS"
fi

if test "x${CODE_COVERAGE_ENABLED}" = "xyes" ; then
    CFLAGS=`echo $CFLAGS | ${SED} 's/-O\w//g'`
    CXXFLAGS=`echo $CXXFLAGS | ${SED} 's/-O\w//g'`
fi

# Global defaults for AM_* flags.  Can be overridden on a per-Makefile.am basis.
AM_CPPFLAGS='-I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/src -I$(top_srcdir)/src/network_inspectors'
AM_CPPFLAGS="${AM_CPPFLAGS} ${CODE_COVERAGE_CPPFLAGS} ${HARD_CPPFLAGS}"
AM_CFLAGS="${CODE_COVERAGE_CFLAGS} ${HARD_CFLAGS}"
AM_CXXFLAGS="${CODE_COVERAGE_CXXFLAGS} ${HARD_CFLAGS}"
AM_LDFLAGS="${CODE_COVERAGE_LDFLAGS} ${HARD_LDFLAGS}"

# Special AM_CPPFLAGS for snort2lua.
snort2lua_CPPFLAGS='-I$(top_builddir) -I$(top_srcdir)/tools/snort2lua'
snort2lua_CPPFLAGS="${snort2lua_CPPFLAGS} ${CODE_COVERAGE_CPPFLAGS}"

AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_CXXFLAGS)
AC_SUBST(AM_LDFLAGS)

AC_SUBST(snort2lua_CPPFLAGS)

AC_SUBST(CPPUTEST_CPPFLAGS)
AC_SUBST(CPPUTEST_LDFLAGS)

AC_SUBST(PCAP_CPPFLAGS)
AC_SUBST(HWLOC_CPPFLAGS)
AC_SUBST(LUAJIT_CPPFLAGS)
AC_SUBST(PCRE_CPPFLAGS)
AC_SUBST(DNET_CPPFLAGS)
AC_SUBST(DAQ_CPPFLAGS)
AC_SUBST(FLATBUFFERS_CPPFLAGS)
AC_SUBST(LZMA_CPPFLAGS)
AC_SUBST(OPENSSL_CPPFLAGS)
AC_SUBST(HYPERSCAN_CPPFLAGS)

AC_SUBST(SANITIZER_LDFLAGS)

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
src/decompress/Makefile \
src/detection/Makefile \
src/events/Makefile \
src/file_api/Makefile \
src/filters/Makefile \
src/flow/Makefile \
src/flow/test/Makefile \
src/framework/Makefile \
src/hash/Makefile \
src/hash/test/Makefile \
src/helpers/Makefile \
src/lua/Makefile \
src/ips_options/Makefile \
src/ips_options/test/Makefile \
src/latency/Makefile \
src/log/Makefile \
src/log/test/Makefile \
src/loggers/Makefile    \
src/main/Makefile \
src/managers/Makefile \
src/memory/Makefile \
src/mime/Makefile \
src/pub_sub/Makefile \
src/stream/Makefile \
src/stream/base/Makefile \
src/stream/ip/Makefile \
src/stream/icmp/Makefile \
src/stream/libtcp/Makefile \
src/stream/tcp/Makefile \
src/stream/udp/Makefile \
src/stream/user/Makefile \
src/stream/file/Makefile \
src/stream/test/Makefile \
src/network_inspectors/Makefile \
src/network_inspectors/appid/Makefile \
src/network_inspectors/appid/test/Makefile \
src/network_inspectors/appid/detector_plugins/test/Makefile \
src/network_inspectors/appid/service_plugins/test/Makefile \
src/network_inspectors/arp_spoof/Makefile \
src/network_inspectors/binder/Makefile \
src/network_inspectors/normalize/Makefile \
src/network_inspectors/packet_capture/Makefile \
src/network_inspectors/perf_monitor/Makefile \
src/network_inspectors/port_scan/Makefile \
src/network_inspectors/reputation/Makefile \
src/packet_io/Makefile \
src/parser/Makefile \
src/piglet/Makefile \
src/piglet_plugins/Makefile \
src/service_inspectors/Makefile     \
src/service_inspectors/back_orifice/Makefile \
src/service_inspectors/dce_rpc/Makefile \
src/service_inspectors/dnp3/Makefile \
src/service_inspectors/dns/Makefile \
src/service_inspectors/ftp_telnet/Makefile \
src/service_inspectors/gtp/Makefile \
src/service_inspectors/imap/Makefile \
src/service_inspectors/modbus/Makefile \
src/service_inspectors/http_inspect/Makefile \
src/service_inspectors/http_inspect/test/Makefile \
src/service_inspectors/pop/Makefile \
src/service_inspectors/rpc_decode/Makefile \
src/service_inspectors/sip/Makefile \
src/service_inspectors/smtp/Makefile \
src/service_inspectors/ssh/Makefile \
src/service_inspectors/ssl/Makefile \
src/service_inspectors/wizard/Makefile \
src/ports/Makefile \
src/protocols/Makefile \
src/search_engines/Makefile \
src/search_engines/test/Makefile \
src/sfip/Makefile \
src/side_channel/Makefile \
src/side_channel/test/Makefile \
src/connectors/Makefile \
src/connectors/file_connector/Makefile \
src/connectors/file_connector/test/Makefile \
src/connectors/tcp_connector/Makefile \
src/connectors/tcp_connector/test/Makefile \
src/sfrt/Makefile \
src/target_based/Makefile \
src/host_tracker/Makefile \
src/host_tracker/test/Makefile \
src/catch/Makefile \
src/time/Makefile \
src/profiler/Makefile \
src/utils/Makefile \
lua/Makefile \
doc/Makefile \
daqs/Makefile \
tools/Makefile \
tools/flatbuffers/Makefile \
tools/u2boat/Makefile \
tools/u2spewfoo/Makefile \
tools/snort2lua/Makefile \
tools/snort2lua/config_states/Makefile \
tools/snort2lua/data/Makefile \
tools/snort2lua/data/data_types/Makefile \
tools/snort2lua/keyword_states/Makefile \
tools/snort2lua/output_states/Makefile \
tools/snort2lua/preprocessor_states/Makefile \
tools/snort2lua/rule_states/Makefile \
tools/snort2lua/helpers/Makefile \
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

    am_cppflags:    ${AM_CPPFLAGS}
    am_cflags:      ${AM_CFLAGS}
    am_cxxflags:    ${AM_CXXFLAGS}
    am_ldflags:     ${AM_LDFLAGS}
])
