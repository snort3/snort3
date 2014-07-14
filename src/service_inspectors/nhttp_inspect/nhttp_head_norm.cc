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
//  @brief      HeaderNormalizer class
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include "snort.h"
#include "snort_types.h"

#include "nhttp_enum.h"
#include "nhttp_str_to_code.h"
#include "nhttp_head_norm.h"

using namespace NHttpEnums;

// This derivation removes embedded CRLFs (wrapping), omits leading and trailing linear white space, and replaces internal strings of <SP> and <LF> with a single <SP>
int32_t HeaderNormalizer::deriveHeaderContent(const uint8_t *value, int32_t length, uint8_t *buffer) {
    int32_t outLength = 0;
    bool lastWhite = true;
    for (int32_t k=0; k < length; k++) {
        if ((value[k] == '\r') && (k+1 < length) && (value[k+1] == '\n')) k++;
        else if ((value[k] != ' ') && (value[k] != '\t')) {
            lastWhite = false;
            buffer[outLength++] = value[k];
        }
        else if (!lastWhite) {
            lastWhite = true;
            buffer[outLength++] = ' ';
        }
    }
    if ((outLength > 0) && (buffer[outLength - 1] == ' ')) outLength--;
    return outLength;
}

// This method normalizes the header field value for headId.
int32_t HeaderNormalizer::normalize(const HeaderId headId, const int count, ScratchPad &scratchPad, uint64_t &infractions,
        const HeaderId headerNameId[], const field headerValue[], const int32_t numHeaders, field &resultField) const {
    if (resultField.length != STAT_NOTCOMPUTE) return resultField.length;
    if (format == NORM_NULL) return resultField.length = STAT_NOTCONFIGURED;
    if (count == 0) return resultField.length = STAT_NOSOURCE;

    // Search Header IDs from all the headers in this message. concatenateRepeats means the header can properly be
    // present more than once. The standard normalization is to concatenate all the repeated field values into a
    // comma-separated list. Otherwise only the first value will be normalized and the rest will be ignored.

    int numMatches = 0;
    int32_t bufferLength = 0;
    int currMatch;
    for (int k=0; k < numHeaders; k++) {
        if (headerNameId[k] == headId) {
            if (++numMatches == 1) currMatch = k;    // remembering location of the first matching header
            bufferLength += headerValue[k].length;
            if (!concatenateRepeats || (numMatches >= count)) break;
        }
    }
    assert((!concatenateRepeats && (numMatches == 1)) || (concatenateRepeats && (numMatches == count)));
    bufferLength += numMatches - 1;    // allow space for concatenation commas

    // We are allocating twice as much memory as we need to store the normalized field value. The raw field value will
    // be copied into one half of the buffer. Concatenation and white space normalization happen during this step. Next
    // a series of normalization functions will transform the value into final form. Each normalization copies the value
    // from one half of the buffer to the other. Based on whether the number of normalization functions is odd or even,
    // the initial placement in the buffer is chosen so that the final normalization leaves the field value at the front
    // of the buffer. The buffer space actually used is locked down in the scratchPad. The remainder of the first half
    // and all of the second half are returned to the scratchPad for future use.

    // Round up to multiple of eight so that both halves are 64-bit aligned. 200 is a "way too big" fudge factor to allow
    // for modest expansion of field size during normalization.
    bufferLength += (8-bufferLength%8)%8 + 200;
    uint8_t* const scratch = scratchPad.request(2*bufferLength);
    if (scratch == nullptr) return resultField.length = STAT_INSUFMEMORY;

    uint8_t* const frontHalf = scratch;
    uint8_t* const backHalf = scratch + bufferLength;
    uint8_t* working = (numNormalizers%2 == 0) ? frontHalf : backHalf;
    int32_t dataLength = 0;
    for (int j=0; j < numMatches; j++) {
        if (j >= 1) {
            *working++ = ',';
            dataLength++;
            while (headerNameId[++currMatch] != headId);
        }
        int32_t growth = deriveHeaderContent(headerValue[currMatch].start, headerValue[currMatch].length, working);
        working += growth;
        dataLength += growth;
    }

    for (int i=0; i < numNormalizers; i++) {
        if (i%2 != numNormalizers%2) dataLength = normalizer[i](backHalf, dataLength, frontHalf, infractions, normArg[i]);
        else                         dataLength = normalizer[i](frontHalf, dataLength, backHalf, infractions, normArg[i]);
        if (dataLength <= 0) return resultField.length = dataLength;
    }
    resultField.start = scratch;
    resultField.length = dataLength;
    scratchPad.commit(dataLength);
    return resultField.length;
}



