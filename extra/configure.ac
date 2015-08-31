## Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License Version 2 as
## published by the Free Software Foundation.  You may not use, modify or
## distribute this program under any other version of the GNU General
## Public License.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Process this file with autoconf to produce a configure script.

AC_INIT([snort_extra], [1.0.0-a2], [snort-team@sourcefire.com])
AC_PREREQ(2.69)

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE(foreign)

LT_INIT

# Checks for programs.
AC_PROG_CXX
AC_PROG_LIBTOOL

# Use the same defines Snort used
# (absolutely critical to ensure struct definitions match)
CXXFLAGS=`pkg-config --cflags snort`
CFLAGS=`pkg-config --cflags snort`
AM_CPPFLAGS=`pkg-config --cflags-only-I snort`

CFLAGS="$CFLAGS -std=c99"
AM_CFLAGS="-std=c99"
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
        AM_CXXFLAGS="$AM_CXXFLAGS -fvisibility=hidden"
        AC_DEFINE([HAVE_VISIBILITY],[1],
            [Define if the compiler supports visibility declarations.])
    fi
])
CC_VISIBILITY()

AC_ARG_WITH(snort-includes,
    AC_HELP_STRING([--with-snort-includes=DIR],[snort include directory]),
    [with_snort_includes="$withval"],[with_snort_includes="no"])

if test "x$with_snort_includes" != "xno"; then
    AM_CPPFLAGS="${AM_CPPFLAGS} -I${with_snort_includes}"
fi

AC_SUBST(AM_CXXFLAGS)
AC_SUBST(AM_CPPFLAGS)

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

