#--------------------------------------------------------------------------
# initialization
#--------------------------------------------------------------------------

AC_INIT([snort_extra], [1.0.0-a4], [snort-team@sourcefire.com])
AC_PREREQ(2.69)

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE(foreign)
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC([clang gcc])
AC_PROG_CXX([clang++ g++])
AC_PROG_LIBTOOL

LT_INIT

# Use the same defines Snort used
# (absolutely critical to ensure struct definitions match)
CPPFLAGS="$CPPFLAGS `pkg-config --cflags snort`"

CPPFLAGS="$CPPFLAGS -DBUILDING_SO"

CFLAGS="$CFLAGS -std=gnu99"
CXXFLAGS="$CXXFLAGS -std=c++11"

AX_CXX_COMPILE_STDCXX_11

#--------------------------------------------------------------------------
# visibility foo
#--------------------------------------------------------------------------

# modified from gnulib/m4/visibility.m4
AC_DEFUN([CC_VISIBILITY],
[
    AC_REQUIRE([AC_PROG_CC])
    AC_MSG_CHECKING([for visibility support])
    gl_save_CFLAGS="$CFLAGS"

    AC_CACHE_VAL(gl_cv_cc_visibility, [
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
        # flags pulled from snort but we need to define the have
        #CFLAGS="$CFLAGS -fvisibility=hidden"
        #CXXFLAGS="$CXXFLAGS -fvisibility=hidden"
        AC_DEFINE([HAVE_VISIBILITY],[1],
            [Define if the compiler supports visibility declarations.])
    fi
])
CC_VISIBILITY()

#--------------------------------------------------------------------------
# outputs
#--------------------------------------------------------------------------

AC_SUBST(AM_CXXFLAGS)

AC_CONFIG_FILES([ \
    Makefile \
    src/Makefile \
    src/codecs/Makefile \
    src/daqs/Makefile \
    src/inspectors/Makefile \
    src/ips_options/Makefile \
    src/loggers/Makefile \
    src/search_engines/Makefile \
    src/so_rules/Makefile \
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
