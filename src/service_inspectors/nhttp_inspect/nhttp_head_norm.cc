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

void HeaderNormalizer::normalize(ScratchPad &scratchPad, uint64_t &infractions, HeaderId headId, const HeaderId headerNameId[], const field headerValue[], int32_t numHeaders,
        field &resultField) const {
    // This method normalizes the header field value for headId.
    if (format == NORM_NULL) {
        resultField.length = STAT_NOTCONFIGURED;
        return;
    }

    // Search Header IDs from all the headers in this message. A critical issue is whether the header can be present more than once in a message. concatenateRepeats means the
    // header can be present more than once. The standard normalization is to concatenate all the repeated field values into a comma-separated list. Otherwise there should not
    // be more than one instance of this header. infractRepeats causes us to inspect for improper repeated headers. Regardless of whether we look for these extra values only
    // the first value will be normalized.

    int numMatches = 0;
    int32_t bufferLength = 0;
    int firstMatch = -1;
    for (int k=0; k < numHeaders; k++) {
        if (headerNameId[k] == HEAD__NOTCOMPUTE) break;
        if (headerNameId[k] == headId) {
            numMatches++;
            if (numMatches == 1) firstMatch = k;
            if ((numMatches == 1) || concatenateRepeats) bufferLength += headerValue[k].length;
            if (!concatenateRepeats && !infractRepeats) break;
        }
    }
    if (numMatches == 0) {
        resultField.length = STAT_NOTPRESENT;
        return;
    }
    if (infractRepeats && (numMatches >= 2)) infractions |= INF_BADHEADERREPS;

    // The scratchPad provides the space to store the normalized value. We are allocating twice as much memory as we need to store the normalized field value. The raw field
    // value will be copied into one half of the buffer. Concatenation and white space normalization happen during this step. Next a series of normalization functions will
    // transform the value into final form. Each normalization copies the value from one half of the buffer to the other. Based on whether the number of normalization functions
    // is odd or even, the initial placement in the buffer is chosen so that the final normalization leaves the field value at the front of the buffer. The buffer space actually
    // used is locked down in the scratchPad. The remainder of the first half and all of the second half are returned to the scratchPad for future use.
    if (concatenateRepeats) bufferLength += numMatches - 1;    // allow space for concatenation commas
    // Round up to multiple of eight so that both halves are 64-bit aligned.
    // 200 is a "way too big" fudge factor to allow for modest expansion of field size during normalization. Needs improvement.
    bufferLength += (8-bufferLength%8)%8 + 200;
    uint8_t * const scratch = scratchPad.request(2*bufferLength);
    if (scratch == nullptr) {
        resultField.length = STAT_INSUFMEMORY;
        return;
    }

    uint8_t * const frontHalf = scratch;
    uint8_t * const backHalf = scratch + bufferLength;
    uint8_t *working = (numNormalizers%2 == 0) ? frontHalf : backHalf;
    int currMatch = firstMatch;
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
        if (!concatenateRepeats) break;
    }

    for (int i=0; i < numNormalizers; i++) {
        if (i%2 != numNormalizers%2) dataLength = normalizer[i](backHalf, dataLength, frontHalf, infractions, normArg[i]);
        else                         dataLength = normalizer[i](frontHalf, dataLength, backHalf, infractions, normArg[i]);
        if (dataLength <= 0) {
            resultField.length = dataLength;
            return;
        }
    }
    resultField.start = scratch;
    resultField.length = dataLength;
    scratchPad.commit(dataLength);
}


