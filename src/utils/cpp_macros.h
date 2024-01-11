//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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
// cpp_macros.h author Michael Altizer <mialtize@cisco.com>

#ifndef CPP_MACROS_H
#define CPP_MACROS_H

// Miscellaneous C preprocessor macros

// Turn x into a string literal without expanding macro definitions
// Example:
//      #define BUILD 123
//      STRINGIFY(BUILD)
// Result:
//      "BUILD"
#define STRINGIFY(x) #x

// Turn x into a string literal after macro-expanding it
// Example:
//      #define BUILD 123
//      STRINGIFY_MX(BUILD)
// Result:
//      "123"
#define STRINGIFY_MX(x) STRINGIFY(x)

// Concatenate preprocessor tokens x and y without expanding macro definitions
// Example:
//      #define ice snow
//      #define cream cone
//      PPCAT(ice, cream)
// Result:
//      icecream
#define PPCAT(x, y) x ## y

// Concatenate preprocessor tokens x and y after macro-expanding them
// Example:
//      #define ice snow
//      #define cream cone
//      PPCAT_MX(ice, cream)
// Result:
//      snowcone
#define PPCAT_MX(x, y) PPCAT(x, y)

// Pair of macros to temporarily enable and then disable warnings for structures
// being automatically padded.  Currently implemented for Clang and GCC >= 5.0.
#if defined(__clang__) && !defined(__ICC)
#  define PADDING_GUARD_BEGIN \
    _Pragma(STRINGIFY( clang diagnostic push )) \
    _Pragma(STRINGIFY( clang diagnostic warning "-Wpadded" ))
#  define PADDING_GUARD_END \
    _Pragma(STRINGIFY( clang diagnostic pop ))
#elif defined(__GNUC__) && __GNUC__ > 4 && !defined(__ICC)
#  define PADDING_GUARD_BEGIN \
    _Pragma(STRINGIFY( GCC diagnostic push )) \
    _Pragma(STRINGIFY( GCC diagnostic warning "-Wpadded" ))
#  define PADDING_GUARD_END \
    _Pragma(STRINGIFY( GCC diagnostic pop ))
#else
#  define PADDING_GUARD_BEGIN
#  define PADDING_GUARD_END
#endif

// Pair of macros to temporarily disable and then enable warnings for code
// that is accessing members of packed types with pointers
#if defined(__clang__) && __clang_major__ >= 4 && !defined(__ICC)
#  define PACKED_MEMBER_ADDR_BEGIN \
    _Pragma(STRINGIFY( clang diagnostic push )) \
    _Pragma(STRINGIFY( clang diagnostic ignored "-Waddress-of-packed-member" ))
#  define PACKED_MEMBER_ADDR_END \
    _Pragma(STRINGIFY( clang diagnostic pop ))
#elif defined(__GNUC__) && __GNUC__ >= 9 && !defined(__ICC)
#  define PACKED_MEMBER_ADDR_BEGIN \
    _Pragma(STRINGIFY( GCC diagnostic push )) \
    _Pragma(STRINGIFY( GCC diagnostic ignored "-Waddress-of-packed-member" ))
#  define PACKED_MEMBER_ADDR_END \
    _Pragma(STRINGIFY( GCC diagnostic pop ))
#else
#  define PACKED_MEMBER_ADDR_BEGIN
#  define PACKED_MEMBER_ADDR_END
#endif

#endif
