//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2010-2013 Sourcefire, Inc.
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

#ifndef UTIL_UTF_H
#define UTIL_UTF_H

// Some UTF-{16,32}{le,be} normalization functions

#include "main/snort_types.h"

// return codes
#define DECODE_UTF_SUCCESS  0  // FIXIT-L replace with bool
#define DECODE_UTF_FAILURE -1

// Character set types 
#define CHARSET_DEFAULT 0  // FIXIT-L these should be an enum
#define CHARSET_UTF7    1
#define CHARSET_UTF16LE 2
#define CHARSET_UTF16BE 3
#define CHARSET_UTF32LE 4
#define CHARSET_UTF32BE 5
#define CHARSET_UNKNOWN 255

// Since payloads don't have to end on 2/4-byte boundaries, callers to
// DecodeUTF are responsible for keeping a decode_utf_state_t. This carries
// state between subsequent calls.
struct decode_utf_state_t
{
    int state;
    int charset;
};

// Init & Terminate functions for decode_utf_state_t
SO_PUBLIC int init_decode_utf_state(decode_utf_state_t*);
SO_PUBLIC int term_decode_utf_state(decode_utf_state_t*);

// setters & getters
SO_PUBLIC int set_decode_utf_state_charset(decode_utf_state_t*, int charset);
SO_PUBLIC int get_decode_utf_state_charset(decode_utf_state_t*);

// UTF-Decoding function prototypes
SO_PUBLIC int DecodeUTF(
    char* src, unsigned int src_len, char* dst, unsigned int dst_len,
    int* bytes_copied, decode_utf_state_t*);

#endif

