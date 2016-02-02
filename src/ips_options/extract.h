//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#ifndef EXTRACT_H
#define EXTRACT_H

#include "main/snort_types.h"

#define ENDIAN_BIG    0x0
#define ENDIAN_LITTLE 0x1
#define ENDIAN_FUNC   0x2

#define PARSELEN      10

SO_PUBLIC int string_extract(
    int bytes_to_grab, int base, const uint8_t* ptr,
    const uint8_t* start, const uint8_t* end, uint32_t* value);

SO_PUBLIC int byte_extract(
    int endianess, int bytes_to_grab, const uint8_t* ptr,
    const uint8_t* start, const uint8_t* end, uint32_t* value);

#endif

