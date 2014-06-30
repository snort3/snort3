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
//  @brief      URI normalization functions
//


// &&&#include <string.h>
#include <assert.h>
#include <sys/types.h>

#include "nhttp_enum.h"
#include "nhttp_uri_norm.h"

using namespace NHttpEnums;

void UriNormalizer::normalize(const field &input, field &result, ScratchPad &scratchPad, uint64_t &infractions) const {
    if (result.length != STAT_NOTCOMPUTE) return;
    if (input.length < 0) {
        result.length = STAT_NOTPRESENT;
        return;
    }

    // Almost all HTTP requests are honest and rarely need expensive normalization processing. We do a quick scan for
    // red flags and only perform normalization if something comes up. Otherwise we set the normalized field to point
    // at the raw value.
    if ( ( doPath && pathCheck(input.start, input.length, infractions))      ||
         (!doPath && noPathCheck(input.start, input.length, infractions)))
    {
        result.start = input.start;
        result.length = input.length;
        return;
    }

    // Add an extra byte because normalization on rare occasions adds an extra character
    // We need working space for two copies to do multiple passes.
    // Round up to multiple of eight so that both copies are 64-bit aligned.
    const int32_t bufferLength = input.length + 1 + (8-(input.length+1)%8)%8;
    uint8_t * const scratch = scratchPad.request(2 * bufferLength);
    if (scratch == nullptr) {
        result.length = STAT_INSUFMEMORY;
        return;
    }
    uint8_t* const frontHalf = scratch;
    uint8_t* const backHalf = scratch + bufferLength;

    int32_t dataLength;
    dataLength = normCharClean(input.start, input.length, frontHalf, infractions, nullptr);
    if (doPath) {
        dataLength = normBackSlash(frontHalf, dataLength, backHalf, infractions, nullptr);
        dataLength = normPathClean(backHalf, dataLength, frontHalf, infractions, nullptr);
    }

    scratchPad.commit(dataLength);
    result.start = frontHalf;
    result.length = dataLength;
}

bool UriNormalizer::noPathCheck(const uint8_t* inBuf, int32_t inLength, uint64_t& infractions) const {
    for (int32_t k = 0; k < inLength; k++) {
        if (nonPathChar[inBuf[k]] == CHAR_NORMAL) continue;
        infractions |= INF_URINEEDNORM;
        return false;
    }
    return true;
}

bool UriNormalizer::pathCheck(const uint8_t* inBuf, int32_t inLength, uint64_t& infractions) const {
    for (int32_t k = 0; k < inLength; k++) {
        if (pathChar[inBuf[k]] == CHAR_NORMAL) continue;
        if ((inBuf[k] == '/') && ((k == 0) || (inBuf[k-1] != '/'))) continue;
        infractions |= INF_URINEEDNORM;
        return false;
    }
    return true;
}

int32_t UriNormalizer::normCharClean(const uint8_t* inBuf, int32_t inLength, uint8_t *outBuf, uint64_t& infractions, const void *) const {
    int32_t length = 0;
    for (int32_t k = 0; k < inLength; k++) {
        switch (nonPathChar[inBuf[k]]) {
          case CHAR_NORMAL:
            outBuf[length++] = inBuf[k];
            break;
          case CHAR_INVALID:
            infractions |= INF_URIBADCHAR;
            outBuf[length++] = inBuf[k];
            break;
          case CHAR_EIGHTBIT:
            infractions |= INF_URI8BITCHAR;
            outBuf[length++] = inBuf[k];
            break;
          case CHAR_PERCENT:
            if ((k+2 < inLength) && (asHex[inBuf[k+1]] != -1) && (asHex[inBuf[k+2]] != -1)) {
                if (asHex[inBuf[k+1]] <= 7) {
                    uint8_t value = asHex[inBuf[k+1]] * 16 + asHex[inBuf[k+2]];
                    if (goodPercent[value]) {
                        // Normal % escape of an ASCII special character that is supposed to be escaped
                        infractions |= INF_URIPERCENTNORMAL;
                        outBuf[length++] = '%';
                    }
                    else {
                        // Suspicious % escape of an ASCII character that does not need to be escaped
                        infractions |= INF_URIPERCENTASCII;
                        if (nonPathChar[value] == CHAR_INVALID) infractions |= INF_URIBADCHAR;
                        outBuf[length++] = value;
                        k += 2;
                    }
                }
                else {
                    // UTF-8 decoding not implemented yet
                    infractions |= INF_URIPERCENTUTF8;
                    outBuf[length++] = '%';
                }
            }
            else if ((k+5 < inLength) && (inBuf[k+1] == 'u') && (asHex[inBuf[k+2]] != -1) && (asHex[inBuf[k+3]] != -1)
               && (asHex[inBuf[k+4]] != -1) && (asHex[inBuf[k+5]] != -1)) {
                // 'u' UTF-16 decoding not implemented yet
                infractions |= INF_URIPERCENTUCODE;
                outBuf[length++] = '%';
            }
            else {
                // Don't recognize it
                infractions |= INF_URIPERCENTOTHER;
                outBuf[length++] = '%';
            }
            break;
          default:
            assert(0);
            break;
        }
    }
    return length;
}

// Convert URI backslashes to slashes
int32_t UriNormalizer::normBackSlash(const uint8_t* inBuf, int32_t inLength, uint8_t *outBuf, uint64_t& infractions, const void *) const {
    for (int32_t k = 0; k < inLength; k++) {
        if (inBuf[k] != '\\') outBuf[k] = inBuf[k];
        else {
            outBuf[k] = '/';
            infractions |= INF_URIBACKSLASH;
        }
    }
    return inLength;
}

// Caution: worst case output length is one greater than input length
int32_t UriNormalizer::normPathClean(const uint8_t* inBuf, int32_t inLength, uint8_t *outBuf, uint64_t& infractions, const void *) const {
    int32_t length = 0;
    // It simplifies the code that handles /./ and /../ to pretend there is an extra '/' after the buffer.
    // Avoids making a special case of URIs that end in . or ..
    // That is why the loop steps off the end of the input buffer by saying <= instead of <.
    for (int32_t k = 0; k <= inLength; k++) {
        // Pass through all non-slash characters and also the leading slash
        if (((k < inLength) && (inBuf[k] != '/')) || (k == 0)) {
            outBuf[length++] = inBuf[k];
        }
        // Ignore this slash if it directly follows another slash
        else if ((k < inLength) && (length >= 1) && (outBuf[length-1] == '/')) {
            infractions |= INF_URIMULTISLASH;
        }
        // This slash is the end of a /./ pattern, ignore this slash and remove the period from the output
        else if ((length >= 2) && (outBuf[length-1] == '.') && (outBuf[length-2] == '/')) {
            infractions |= INF_URISLASHDOT;
            length -= 1;
        }
        // This slash is the end of a /../ pattern, normalization depends on whether there is a previous directory that
        // we can remove
        else if ((length >= 3) && (outBuf[length-1] == '.') && (outBuf[length-2] == '.') && (outBuf[length-3] == '/')) {
            infractions |= INF_URISLASHDOTDOT;
            // Traversing above the root of the absolute path. A path of the form /../../../foo/bar/whatever cannot be
            // further normalized. Instead of taking away a directory we leave the .. and write out the new slash.
            // This code can write out the pretend slash after the end of the buffer. That is intentional so that the
            // normal form of "/../../../.." is "/../../../../"
            if ( (length == 3) ||
                ((length >= 6) && (outBuf[length-4] == '.') && (outBuf[length-5] == '.') && (outBuf[length-6] == '/')))
            {
                infractions |= INF_URIROOTTRAV;
                outBuf[length++] = '/';
            }
            // Remove the previous directory from the output. "/foo/bar/../" becomes "/foo/"
            else {
                for (length -= 3; outBuf[length-1] != '/'; length--);
            }
        }
        // Pass through an ordinary slash
        else if (k < inLength) outBuf[length++] = '/';
    }
    return length;
}























