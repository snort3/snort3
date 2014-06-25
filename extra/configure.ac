# Process this file with autoconf to produce a configure script.

AC_INIT([snort_examples], [1.0], [snort-team@sourcefire.com])
AC_PREREQ(2.69)

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CXX
AC_PROG_LIBTOOL

# Use the same defines Snort used
# (absolutely critical to ensure struct definitions match)
CXXFLAGS=`pkg-config --cflags snort`

AM_CXXFLAGS="-std=c++11"
AX_CXX_COMPILE_STDCXX_11

# not sure why this is borked
#AC_ENABLE_VISIBILITY()
#
# so we do like snort:
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
        AM_CXXFLAGS="$AM_CXXFLAGS -fvisibility=default"
        AC_DEFINE([HAVE_VISIBILITY],[1],
            [Define if the compiler supports visibility declarations.])
    fi
])
CC_VISIBILITY()

# Checks for libraries.
AC_ARG_WITH(snort-includes,
            [  --with-snort-includes=DIR    snort include directory],
            [with_snort_includes="$withval"], [with_snort_includes="no"])

if test "x$with_snort_includes" != "xno"; then
    AM_CPPFLAGS="${AM_CPPFLAGS} -I${with_snort_includes}"
fi

AC_SUBST(AM_CXXFLAGS)
AC_SUBST(AM_CPPFLAGS)

AC_CONFIG_FILES([ \
    Makefile \
    src/Makefile \
    src/codecs/Makefile \
    src/inspectors/Makefile \
    src/ips_options/Makefile \
    src/loggers/Makefile \
    src/search_engines/Makefile \
    src/so_rules/Makefile \
])

AC_OUTPUT

