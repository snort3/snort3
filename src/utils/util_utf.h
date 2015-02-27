//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

/* return codes */
#define DECODE_UTF_SUCCESS 0
#define DECODE_UTF_FAILURE -1

/* character set types */
#define CHARSET_DEFAULT 0
#define CHARSET_UTF7 1
#define CHARSET_UTF16LE 2
#define CHARSET_UTF16BE 3
#define CHARSET_UTF32LE 4
#define CHARSET_UTF32BE 5
#define CHARSET_UNKNOWN 255

/* Since payloads don't have to end on 2/4-byte boundaries, callers to
   DecodeUTF are responsible for keeping a decode_utf_state_t. This carries
   state between subsequent calls. */
typedef struct decode_utf_state
{
    int state;
    int charset;
} decode_utf_state_t;

/* Init & Terminate functions for decode_utf_state_t. */
int init_decode_utf_state(decode_utf_state_t*);
int term_decode_utf_state(decode_utf_state_t*);

/* setters & getters */
int set_decode_utf_state_charset(decode_utf_state_t* dstate, int charset);
int get_decode_utf_state_charset(decode_utf_state_t* dstate);

/* UTF-Decoding function prototypes */
int DecodeUTF(char* src, unsigned int src_len, char* dst, unsigned int dst_len, int* bytes_copied,
    decode_utf_state_t* dstate);

#endif /* UTIL_UTF_H */

