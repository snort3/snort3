//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// safec.h author Carter Waxman <cwaxman@cisco.com>

#ifndef UTILS_SAFEC_H
#define UTILS_SAFEC_H

//FIXIT-M combine these macros in the build foo 
#if defined(HAVE_SAFEC) && defined(ENABLE_SAFEC)

extern "C"
{
#include <libsafec/safe_lib.h>
}

#else

#define memcpy_s(dst, dsize, src, ssize) memcpy(dst, src, ssize)
#define memmove_s(dst, dsize, src, ssize) memmove(dst, src, ssize)

#define set_mem_constraint_handler_s(x)
#define set_str_constraint_handler_s(x)

#endif

#endif

