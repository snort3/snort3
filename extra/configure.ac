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
CFLAGS=`pkg-config --cflags snort`
CXXFLAGS=`pkg-config --variable=cxxflags snort`
CPPFLAGS=`pkg-config --variable=cppflags snort`

AX_CXX_COMPILE_STDCXX_11

AC_ARG_WITH(snort-includes,
    AC_HELP_STRING([--with-snort-includes=DIR],[snort include directory]),
    [with_snort_includes="$withval"],[with_snort_includes="no"])

if test "x$with_snort_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_snort_includes}"
fi

AC_SUBST(AM_CXXFLAGS)

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

