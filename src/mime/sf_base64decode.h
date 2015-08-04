//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
// sf_base64decode.h author Patrick Mullen <pmullen@sourcefire.com>

#ifndef SF_BASE64DECODE_H
#define SF_BASE64DECODE_H

// A Base-64 decoder

#include "main/snort_types.h"

// FIXIT-L: inbuf should probably be const uint8_t*
SO_PUBLIC int sf_base64decode(
    uint8_t* inbuf, uint32_t inbuf_size,
    uint8_t* outbuf, uint32_t outbuf_size,
    uint32_t* bytes_written
);

#endif

