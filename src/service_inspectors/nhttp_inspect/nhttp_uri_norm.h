/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      URI Normalizer class
//

#ifndef NHTTP_URI_NORM_H
#define NHTTP_URI_NORM_H

#include "nhttp_scratch_pad.h"

class UriNormalizer {
public:
    static void normalize(const field &input, field &result, bool doPath, ScratchPad &scratchPad, uint64_t &infractions);

private:
    static const NHttpEnums::CharAction uriChar[256];
    static const int8_t asHex[256];
    static const bool goodPercent[256];

    static bool noPathCheck(const uint8_t* inBuf, int32_t inLength, uint64_t& infractions);
    static bool pathCheck(const uint8_t* inBuf, int32_t inLength, uint64_t& infractions);

    static int32_t normCharClean(const uint8_t*, int32_t, uint8_t*, uint64_t&, const void* notUsed);
    static int32_t normBackSlash(const uint8_t*, int32_t, uint8_t*, uint64_t&, const void* notUsed);
    static int32_t normPathClean(const uint8_t*, int32_t, uint8_t*, uint64_t&, const void* notUsed);
};

#endif


