//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
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

#ifndef SNORT_TYPES_H
#define SNORT_TYPES_H

// defines common types if not already defined

#include <cinttypes>
#include <cstddef>
#include <cstdint>

typedef uint16_t Port;

/* use these macros for 64 bit format portability */
#define STDu64 "%" PRIu64
#define FMTu64(fmt) "%" fmt PRIu64

#define STDi64 "%" PRIi64
#define FMTi64(fmt) "%" fmt PRIi64

#define STDx64 "%" PRIx64
#define FMTx64(fmt) "%" fmt PRIx64

#define UNUSED(x) (void)(x)

#ifdef NDEBUG
#define NORETURN_ASSERT
#else
#define NORETURN_ASSERT [[noreturn]]
#endif

#ifndef SO_PUBLIC
#if defined _WIN32 || defined __CYGWIN__
#  ifdef __GNUC__
#    define SO_PUBLIC __attribute__((dllimport))
#  else
#    define SO_PUBLIC __declspec(dllimport)
#  endif
#  define DLL_LOCAL
#else
#  ifdef HAVE_VISIBILITY
#    define SO_PUBLIC  __attribute__ ((visibility("default")))
#    define SO_PRIVATE __attribute__ ((visibility("hidden")))
#  else
#    define SO_PUBLIC
#    define SO_PRIVATE
#  endif
#endif
#endif

#if !defined(__GNUC__) || __GNUC__ < 2 || \
    (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#define __attribute__(x)    /* delete __attribute__ if non-gcc or gcc1 */
#endif

#endif

