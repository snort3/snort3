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

//#include "nhttp_uri_norm.h"
#include "nhttp_splitter.h"

using namespace NHttpEnums;

void NHttpSplitter::conditional_reset() {
    if (complete) {
        octets_seen = 0;
        num_crlf = 0;
        num_flush = 0;
        complete = false;
    }
}

ScanResult NHttpStartSplitter::split(const uint8_t* buffer, uint32_t length) {
    conditional_reset();
    for (uint32_t k = 0; k < length; k++) {
        // Discard magic six white space characters CR, LF, Tab, VT, FF, and SP when they occur before the start line.
        // If we have seen nothing but white space so far ...
        if (num_crlf == octets_seen + k) {
            if ((buffer[k] == 32) || ((buffer[k] >= 9) && (buffer[k] <= 13))) {
                if (num_crlf < MAX_LEADING_WHITESPACE) {
                    num_crlf++;
                    continue;
                }
                else {
                    complete = true;
                    return SCAN_ABORT;
                }
            }
            if (num_crlf > 0) {
                num_flush = k;           // current octet not flushed with white space
                complete = true;
                return SCAN_DISCARD;
            }
        }

        // If we get this far then the leading white space issue is behind us and num_crlf was reset to zero
        if (buffer[k] == '\n') {
            num_crlf++;
            num_flush = k+1;
            complete = true;
            return SCAN_FOUND;
        }
        if (num_crlf == 1) {
            // CR not followed by LF
            complete = true;
            return SCAN_ABORT;
        }
        if (buffer[k] == '\r') {
            num_crlf = 1;
        }
    }
    octets_seen += length;
    return SCAN_NOTFOUND;
}

ScanResult NHttpChunkSplitter::split(const uint8_t* buffer, uint32_t length) {
    conditional_reset();
    if (header_complete) {
        // Previously read the chunk header. Now just flush the length.
        num_flush = expected_length;
        complete = true;
        return SCAN_FOUND;
    }
    for (uint32_t k = 0; k < length; k++) {
        if (buffer[k] == '\n') {
            if (octets_seen + k == num_crlf) {
                // \r\n or \n leftover from previous chunk
                complete = true;
                num_flush = k+1;
                return SCAN_DISCARD;
            }
            if (!length_started) {
                // chunk header specifies no length
                complete = true;
                return SCAN_ABORT;
            }
            // flush completed chunk header
            header_complete = true;
            num_flush = k+1;
            return SCAN_DISCARD;
        }
        if (num_crlf == 1) {
            // CR not followed by LF
            complete = true;
            return SCAN_ABORT;
        }
        if (buffer[k] == '\r') {
            num_crlf = 1;
            continue;
        }
        if (buffer[k] == ';') {
            semicolon = true;
        }
        if (semicolon) {
            // we don't look at chunk header extensions
            continue;
        }
        if (as_hex[buffer[k]] == -1) {
            // illegal character present in chunk length
            complete = true;
            return SCAN_ABORT;
        }
        length_started = true;
        if (digits_seen >= 8) {
            // overflow protection: must fit into 32 bits
            complete = true;
            return SCAN_ABORT;
        }
        expected_length = expected_length * 16 + as_hex[buffer[k]];
        if (expected_length > 0) {
            // leading zeroes don't count
            digits_seen++;
        }
    }
    octets_seen += length;
    return SCAN_NOTFOUND;
}

void NHttpChunkSplitter::conditional_reset() {
    if (complete) {
        expected_length = 0;
        length_started = false;
        digits_seen = 0;
        semicolon = false;
        header_complete = false;
    }
    NHttpSplitter::conditional_reset();
}

ScanResult NHttpHeaderSplitter::split(const uint8_t* buffer, uint32_t length) {
    conditional_reset();
    if (peek_status == SCAN_FOUND) {
        return SCAN_FOUND;
    }
    buffer += peek_octets;
    length -= peek_octets;
    for (uint32_t k = 0; k < length; k++) {
        if (buffer[k] == '\n') {
            num_crlf++;
            if ((first_lf == 0) && (num_crlf < octets_seen + k + 1)) {
                first_lf = num_crlf;
            }
            else {
                num_flush = k + 1 + peek_octets;
                complete = true;
                return SCAN_FOUND;
            }
        }
        else if (buffer[k] == '\r') {
            if (num_crlf == first_lf) {
                num_crlf++;
            }
            else {
                num_crlf = 1;
                first_lf = 0;
            }
        }
        else {
            num_crlf = 0;
            first_lf = 0;
        }
    }
    peek_octets = 0;
    octets_seen += length;
    return SCAN_NOTFOUND;
}

ScanResult NHttpHeaderSplitter::peek(const uint8_t* buffer, uint32_t length) {
    assert(octets_seen == 0);
    peek_status = split(buffer, length);
    peek_octets = length;
    return peek_status;
}

void NHttpHeaderSplitter::conditional_reset() {
    if (complete) {
        peek_octets = 0;
        peek_status = SCAN_NOTFOUND;
        first_lf = 0;
    }
    NHttpSplitter::conditional_reset();
}

ScanResult NHttpTrailerSplitter::split(const uint8_t* buffer, uint32_t length) {
    conditional_reset();
    for (uint32_t k = 0; k < length; k++) {
        if (buffer[k] == '\n') {
            num_crlf++;
            if ((first_lf == 0) && (num_crlf < octets_seen + k + 1)) {
                first_lf = num_crlf;
            }
            else {
                num_flush = k + 1;
                complete = true;
                return SCAN_FOUND;
            }
        }
        else if (buffer[k] == '\r') {
            if (num_crlf == first_lf) {
                num_crlf++;
            }
            else {
                num_crlf = 1;
                first_lf = 0;
            }
        }
        else {
            num_crlf = 0;
            first_lf = 0;
        }
    }
    octets_seen += length;
    return SCAN_NOTFOUND;
}

void NHttpTrailerSplitter::conditional_reset() {
    if (complete) {
        first_lf = 0;
    }
    NHttpSplitter::conditional_reset();
}


