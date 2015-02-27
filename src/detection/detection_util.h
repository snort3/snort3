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
/*
** Description
** This file contains the utility functions used by rule options.
*/

#ifndef DETECTION_UTIL_H
#define DETECTION_UTIL_H

#include <assert.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "protocols/packet.h"
#include "detect.h"
#include "snort.h"
#include "snort_debug.h"

#define DECODE_BLEN 65535

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

extern SO_PUBLIC THREAD_LOCAL uint32_t http_mask;
extern SO_PUBLIC THREAD_LOCAL HttpBuffer http_buffer[HTTP_BUFFER_MAX];
extern SO_PUBLIC const char* http_buffer_name[HTTP_BUFFER_MAX];

extern SO_PUBLIC THREAD_LOCAL DataPointer g_alt_data;
extern SO_PUBLIC THREAD_LOCAL DataPointer g_file_data;

static inline void ClearHttpBuffers(void)
{
    http_mask = 0;
}

static inline uint32_t GetHttpBufferMask(void)
{
    return http_mask;
}

static inline const HttpBuffer* GetHttpBuffer(HTTP_BUFFER b)
{
    if ( !((1 << b) & http_mask) )
        return NULL;

    return http_buffer + b;
}

static inline void SetHttpBufferEncoding(
    HTTP_BUFFER b, const uint8_t* buf, unsigned len, uint32_t enc)
{
    HttpBuffer* hb = http_buffer + b;
    assert(b < HTTP_BUFFER_MAX && buf);

    hb->buf = buf;
    hb->length = len;
    hb->encode_type = enc;
    http_mask |= (1 << b);
}

static inline void SetHttpBuffer(HTTP_BUFFER b, const uint8_t* buf, unsigned len)
{
    SetHttpBufferEncoding(b, buf, len, 0);
}

#define SetDetectLimit(pktPtr, altLen) \
{ \
    pktPtr->alt_dsize = altLen; \
}

#define IsLimitedDetect(pktPtr) (pktPtr->packet_flags & PKT_HTTP_DECODE)

static inline void set_alt_data(uint8_t* p, unsigned n)
{
    g_alt_data.data = p;
    g_alt_data.len = n;
}

static inline void set_file_data(uint8_t* p, unsigned n)
{
    g_file_data.data = p;
    g_file_data.len = n;
}

void EventTrace_Init(void);
void EventTrace_Term(void);

void EventTrace_Log(const Packet*, OptTreeNode*, int action);

static inline int EventTrace_IsEnabled(void)
{
    return ( snort_conf->event_trace_max > 0 );
}

static inline void DetectReset()
{
    g_alt_data.len = 0;
    g_file_data.len = 0;
    ClearHttpBuffers();
}

#endif

