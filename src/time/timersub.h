/* Copyright (C) 1991-1994,96,97,98,99,2000,01,02
        Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA
*/

#ifndef TIMERSUB_H
#define TIMERSUB_H

// never worry about timersub type activities again -- from GLIBC and upcased.
#define TIMERSUB(a, b, result)                                                \
    do {                                                                      \
        (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                         \
        (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                      \
        if ((result)->tv_usec < 0) {                                          \
            --(result)->tv_sec;                                               \
            (result)->tv_usec += 1000000;                                     \
        }                                                                     \
    } while (0)

#endif

