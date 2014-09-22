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
//  @brief      Section-specific splitters
//

#include "nhttp_splitter.h"

using namespace NHttpEnums;

ScanResult NHttpRequestSplitter::split(const uint8_t* buffer, uint32_t length) {
    for (uint32_t k = 0; k < length; k++) {
        // Count the alternating <CR> and <LF> characters we have seen in a row
        if (((buffer[k] == '\r') && (num_crlf == 0)) ||
            ((buffer[k] == '\n') && (num_crlf == 1))) {
            num_crlf++;
            if (num_crlf < 2) {
                continue;
            }
        }
        else {
            num_crlf = 0;
            continue;
        }
        num_flush = k+1;
        // If the first two octets are CRLF then they must be discarded.
        return ((octets_seen + k + 1) == 2) ? SCAN_DISCARD : SCAN_FOUND;
    }
    octets_seen += length;
    return SCAN_NOTFOUND;
}

ScanResult NHttpStatusSplitter::split(const uint8_t* buffer, uint32_t length) {
    for (uint32_t k = 0; k < length; k++) {
        // Count the alternating <CR> and <LF> characters we have seen in a row
        if (((buffer[k] == '\r') && (num_crlf == 0)) ||
            ((buffer[k] == '\n') && (num_crlf == 1))) {
            num_crlf++;
            if (num_crlf < 2) {
                continue;
            }
        }
        else {
            num_crlf = 0;
            continue;
        }
        num_flush = k+1;
        // If the first two octets are CRLF then they must be discarded.
        return ((octets_seen + k + 1) == 2) ? SCAN_DISCARD : SCAN_FOUND;
    }
    octets_seen += length;
    return SCAN_NOTFOUND;
}

ScanResult NHttpChunkHeaderSplitter::split(const uint8_t* buffer, uint32_t length) {
    for (uint32_t k = 0; k < length; k++) {
        // Count the alternating <CR> and <LF> characters we have seen in a row
        if (((buffer[k] == '\r') && (num_crlf == 0)) ||
            ((buffer[k] == '\n') && (num_crlf == 1))) {
            num_crlf++;
            if (num_crlf < 2) {
                continue;
            }
        }
        else {
            num_crlf = 0;
            continue;
        }
        num_flush = k+1;
        // If the first two octets are CRLF then they must be discarded.
        return ((octets_seen + k + 1) == 2) ? SCAN_DISCARD : SCAN_FOUND;
    }
    octets_seen += length;
    return SCAN_NOTFOUND;
}

ScanResult NHttpHeaderSplitter::split(const uint8_t* buffer, uint32_t length) {
    if (peek_status == SCAN_FOUND) {
        return SCAN_FOUND;
    }
    buffer += peek_octets;
    length -= peek_octets;
    peek_octets = 0;
    for (uint32_t k = 0; k < length; k++) {
        // Count the alternating <CR> and <LF> characters we have seen in a row
        if (((buffer[k] == '\r') && (num_crlf%2 == 0)) ||
            ((buffer[k] == '\n') && (num_crlf%2 == 1))) {
            num_crlf++;
            if ((num_crlf == 2) && (octets_seen + k + 1) == 2) {
                num_flush = k+1;
                return SCAN_FOUND;
            }
            if (num_crlf < 4) {
                continue;
            }
        }
        else {
            num_crlf = 0;
            continue;
        }
        num_flush = k + 1 + peek_octets;
        return SCAN_FOUND;
    }
    octets_seen += length;
    return SCAN_NOTFOUND;
}

ScanResult NHttpHeaderSplitter::peek(const uint8_t* buffer, uint32_t length) {
    assert(octets_seen == 0);
    peek_status = split(buffer, length);
    peek_octets = length;
    return peek_status;
}


ScanResult NHttpTrailerSplitter::split(const uint8_t* buffer, uint32_t length) {
    for (uint32_t k = 0; k < length; k++) {
        // Count the alternating <CR> and <LF> characters we have seen in a row
        if (((buffer[k] == '\r') && (num_crlf%2 == 0)) ||
            ((buffer[k] == '\n') && (num_crlf%2 == 1))) {
            num_crlf++;
            if ((num_crlf == 2) && (octets_seen + k + 1) == 2) {
                num_flush = k+1;
                return SCAN_FOUND;
            }
            if (num_crlf < 4) {
                continue;
            }
        }
        else {
            num_crlf = 0;
            continue;
        }
        num_flush = k+1;
        return SCAN_FOUND;
    }
    octets_seen += length;
    return SCAN_NOTFOUND;
}



