//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

#define STRINGIFY(x) #x

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

#endif
