/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2002-2013 Sourcefire, Inc.
 ** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **
 ** Description
 ** This file contains the utility functions used by rule options.
 **
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
#include "treenodes.h"

#ifndef DECODE_BLEN
#define DECODE_BLEN 65535

#define MAX_URI 8192

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
#endif

enum DetectFlagType
{
    FLAG_ALT_DECODE         = 0x0001,
    FLAG_ALT_DETECT         = 0x0002,
    FLAG_DETECT_ALL         = 0xffff
};

struct HttpBuffer
{
    const uint8_t* buf;
    uint16_t length;
    uint32_t encode_type;
};

struct DataPointer
{
    uint8_t *data;
    uint16_t len;
};

struct DataBuffer
{
    uint8_t data[DECODE_BLEN];
    uint16_t len;
};

extern THREAD_LOCAL uint8_t base64_decode_buf[DECODE_BLEN];
extern THREAD_LOCAL uint32_t base64_decode_size;

extern THREAD_LOCAL uint8_t mime_present;

extern THREAD_LOCAL uint8_t doe_buf_flags;
extern THREAD_LOCAL const uint8_t *doe_ptr;

extern THREAD_LOCAL uint16_t detect_flags;

extern THREAD_LOCAL uint32_t http_mask;
extern THREAD_LOCAL HttpBuffer http_buffer[HTTP_BUFFER_MAX];
extern const char* http_buffer_name[HTTP_BUFFER_MAX];

extern THREAD_LOCAL DataPointer DetectBuffer;
extern THREAD_LOCAL DataPointer file_data_ptr;
extern THREAD_LOCAL DataBuffer DecodeBuffer;

static inline void ClearHttpBuffers (void)
{
    http_mask = 0;
}

static inline uint32_t GetHttpBufferMask (void)
{
    return http_mask;
}

static inline const HttpBuffer* GetHttpBuffer (HTTP_BUFFER b)
{
    if ( !((1 << b) & http_mask) )
        return NULL;

    return http_buffer + b;
}

static inline void SetHttpBufferEncoding (
    HTTP_BUFFER b, const uint8_t* buf, unsigned len, uint32_t enc)
{
    HttpBuffer* hb = http_buffer + b;
    assert(b < HTTP_BUFFER_MAX && buf);

    hb->buf = buf;
    hb->length = len;
    hb->encode_type = enc;
    http_mask |= (1 << b);
}

static inline void SetHttpBuffer (HTTP_BUFFER b, const uint8_t* buf, unsigned len)
{
    SetHttpBufferEncoding(b, buf, len, 0);
}

#define SetDetectLimit(pktPtr, altLen) \
{ \
    pktPtr->alt_dsize = altLen; \
}

#define IsLimitedDetect(pktPtr) (pktPtr->packet_flags & PKT_HTTP_DECODE)

/*
 * Function: setFileDataPtr
 *
 * Purpose: Sets the file data pointer used by
 *          file_data rule option.
 *
 * Arguments: ptr => pointer to the body data
 *
 * Returns: void
 *
 */

static inline void setFileDataPtr(uint8_t *ptr, uint16_t decode_size)
{
    file_data_ptr.data = ptr;
    file_data_ptr.len = decode_size;
}

void EventTrace_Init(void);
void EventTrace_Term(void);

void EventTrace_Log(const Packet*, OptTreeNode*, int action);

static inline int EventTrace_IsEnabled (void)
{
    return ( snort_conf->event_trace_max > 0 );
}

static inline void DetectFlag_Enable(DetectFlagType df)
{   
    detect_flags |= df;
}
    
static inline void DetectFlag_Disable(DetectFlagType df)
{   
    detect_flags &= ~df;
}

static inline int Is_DetectFlag(DetectFlagType df)
{
    return ( (detect_flags & df) != 0 );
}

static inline uint16_t Get_DetectFlags(void)
{
    return detect_flags;
}

static inline void Reset_DetectFlags(uint16_t dflags)
{
    detect_flags = dflags;
}

static inline int GetAltDetect(uint8_t **bufPtr, uint16_t *altLenPtr)
{
    if ( Is_DetectFlag(FLAG_ALT_DETECT) )
    {
        *bufPtr = DetectBuffer.data;
        *altLenPtr = DetectBuffer.len;
        return 1;
    }

    return 0;
}

static inline void SetAltDetect(uint8_t *buf, uint16_t altLen)
{
    DetectFlag_Enable(FLAG_ALT_DETECT);
    DetectBuffer.data = buf;
    DetectBuffer.len = altLen;
}

static inline void SetAltDecode(uint16_t altLen)
{
    DetectFlag_Enable(FLAG_ALT_DECODE);
    DecodeBuffer.len = altLen;
}

static inline void DetectReset(uint8_t *buf, uint16_t altLen)
{
    DetectBuffer.data = buf;
    DetectBuffer.len = altLen;

    DetectFlag_Disable(FLAG_DETECT_ALL);

    /* Reset the values */

    file_data_ptr.data  = NULL;
    file_data_ptr.len = 0;
    base64_decode_size = 0;
    doe_buf_flags = 0;
    mime_present = 0;
    DecodeBuffer.len = 0;
}

int IsGzipData(Flow*);  // FIXIT these from HI
int IsJSNormData(Flow*);

#endif

