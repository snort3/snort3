//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef DETECTION_UTIL_H
#define DETECTION_UTIL_H

// this is a legacy junk-drawer file that needs to be refactored
// it provides file and alt data pointers, event trace foo, and
// some http stuff.

#include <assert.h>

#include "main/snort_types.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "detection/detect.h"
#include "protocols/packet.h"

#define DECODE_BLEN 65535

// FIXIT-L this is now used only by http_inspect and new_http_inspect
// and should be relocated accordingly
enum HTTP_BUFFER
{
    HTTP_BUFFER_NONE,
    HTTP_BUFFER_CLIENT_BODY,
    HTTP_BUFFER_COOKIE,
    HTTP_BUFFER_HEADER,
    HTTP_BUFFER_METHOD,
    HTTP_BUFFER_RAW_COOKIE,
    HTTP_BUFFER_RAW_HEADER,
    HTTP_BUFFER_RAW_URI,
    HTTP_BUFFER_STAT_CODE,
    HTTP_BUFFER_STAT_MSG,
    HTTP_BUFFER_URI,
    HTTP_BUFFER_MAX
};

// FIXIT-L this is now used only by http_inspect
// and should be relocated accordingly
struct HttpBuffer
{
    const uint8_t* buf;
    unsigned length;
    uint32_t encode_type;
};

struct DataPointer
{
    uint8_t* data;
    unsigned len;
};

struct DataBuffer
{
    uint8_t data[DECODE_BLEN];
    unsigned len;
};

extern SO_PUBLIC const char* http_buffer_name[HTTP_BUFFER_MAX];

extern SO_PUBLIC THREAD_LOCAL DataPointer g_file_data;

#define SetDetectLimit(pktPtr, altLen) \
{ \
    pktPtr->alt_dsize = altLen; \
}

#define IsLimitedDetect(pktPtr) (pktPtr->packet_flags & PKT_HTTP_DECODE)

static inline void set_file_data(uint8_t* p, unsigned n)
{
    g_file_data.data = p;
    g_file_data.len = n;
}

// FIXIT-L event trace should be placed in its own files
void EventTrace_Init(void);
void EventTrace_Term(void);

void EventTrace_Log(const Packet*, const OptTreeNode*, int action);

static inline int EventTrace_IsEnabled(void)
{
    return ( snort_conf->event_trace_max > 0 );
}

static inline void DetectReset()
{
    g_file_data.len = 0;
}

#endif

