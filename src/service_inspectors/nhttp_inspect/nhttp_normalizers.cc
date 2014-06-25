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
//  @brief      Normalizer functions
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include "nhttp_enum.h"
#include "nhttp_str_to_code.h"
#include "nhttp_normalizers.h"

using namespace NHttpEnums;

// Collection of stock normalization functions. This will probably grow throughout the life of the software. New functions must follow the standard signature.
// The void* at the end is for any special configuration data the function requires.

int32_t normDecimalInteger(const uint8_t* inBuf, int32_t inLength, uint8_t* outBuf, uint64_t& infractions, const void *) {
    // Limited to 18 decimal digits, not including leading zeros, to fit comfortably into int64_t
    int64_t total = 0;
    int nonLeadingZeros = 0;
    for (int32_t k=0; k < inLength; k++) {
        int value = inBuf[k] - '0';
        if (nonLeadingZeros || (value != 0)) nonLeadingZeros++;
        if (nonLeadingZeros > 18) {
            infractions |= INF_BADHEADERDATA;
            return STAT_PROBLEMATIC;
        }
        if ((value < 0) || (value > 9)) {
            infractions |= INF_BADHEADERDATA;
            return STAT_PROBLEMATIC;
        }
        total = total*10 + value;
    }
    ((int64_t*)outBuf)[0] = total;
    return sizeof(int64_t);
}


int32_t norm2Lower(const uint8_t* inBuf, int32_t inLength, uint8_t *outBuf, uint64_t&, const void *) {
    for (int32_t k=0; k < inLength; k++) {
        outBuf[k] = ((inBuf[k] < 'A') || (inBuf[k] > 'Z')) ? inBuf[k] : inBuf[k] - ('A' - 'a');
    }
    return inLength;
}


int32_t normStrCode(const uint8_t* inBuf, int32_t inLength, uint8_t *outBuf, uint64_t&, const void *table) {
    ((int64_t*)outBuf)[0] = strToCode(inBuf, inLength, (const StrCode*)table);
    return sizeof(int64_t);
}

int32_t normSeqStrCode(const uint8_t* inBuf, int32_t inLength, uint8_t *outBuf, uint64_t&, const void *table) {
    int32_t numCodes = 0;
    const uint8_t* start = inBuf;
    while (true) {
        int32_t length;
        for (length = 0; (start + length < inBuf + inLength) && (start[length] != ','); length++);
        if (length == 0) ((uint32_t*)outBuf)[numCodes++] = STAT_EMPTYSTRING;
        else ((int64_t*)outBuf)[numCodes++] = strToCode(start, length, (const StrCode*)table);
        if (start + length >= inBuf + inLength) break;
        start += length + 1;
    }
    return numCodes * sizeof(int64_t);
}

// Remove all space and tab characters (known as LWS or linear white space in the RFC)
int32_t normRemoveLws(const uint8_t* inBuf, int32_t inLength, uint8_t *outBuf, uint64_t&, const void *) {
    int32_t length = 0;
    for (int32_t k = 0; k < inLength; k++) {
        if ((inBuf[k] != ' ') && (inBuf[k] != '\t')) outBuf[length++] = inBuf[k];
    }
    return length;
}












































