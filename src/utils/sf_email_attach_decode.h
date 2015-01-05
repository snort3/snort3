/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 1998-2013 Sourcefire, Inc.
**
** Writen by Bhagyashree Bantwal <bbantwal@sourcefire.com>
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
*/

#ifndef SF_EMAIL_ATTACH_DECODE_H
#define SF_EMAIL_ATTACH_DECODE_H

#include "snort_types.h"
#include "util_unfold.h"
#include "sf_base64decode.h"
#include "snort_bounds.h"

#define MAX_BUF 65535
#define DECODE_SUCCESS  0
#define DECODE_EXCEEDED  1 /* Decode Complete when we reach the max depths */
#define DECODE_FAIL    -1

typedef enum {

    DECODE_NONE = 0,
    DECODE_B64,
    DECODE_QP,
    DECODE_UU,
    DECODE_BITENC,
    DECODE_ALL

} DecodeType;

typedef struct s_Base64_DecodeState
{
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int encode_depth;
    int decode_depth;
} Base64_DecodeState;

typedef struct s_QP_DecodeState
{
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int encode_depth;
    int decode_depth;
} QP_DecodeState;

typedef struct s_UU_DecodeState
{
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int encode_depth;
    int decode_depth;
    uint8_t begin_found;
    uint8_t end_found;
} UU_DecodeState;

typedef struct s_BitEnc_DecodeState
{
    uint32_t bytes_read;
    int depth;
} BitEnc_DecodeState;

typedef struct s_Email_DecodeState
{
    DecodeType decode_type;
    uint8_t decode_present;
    uint32_t prev_encoded_bytes;
    unsigned char *prev_encoded_buf;
    uint32_t decoded_bytes;
    uint8_t *encodeBuf;
    uint8_t *decodeBuf;
    uint8_t *decodePtr;
    Base64_DecodeState b64_state;
    QP_DecodeState qp_state;
    UU_DecodeState uu_state;
    BitEnc_DecodeState bitenc_state;

} Email_DecodeState;

// end :: start + length
int EmailDecode(const uint8_t *start, const uint8_t *end, Email_DecodeState *);


static inline int getCodeDepth(int code_depth, int64_t file_depth)
{
   if (file_depth < 0 )
       return code_depth;
   else if (( file_depth > MAX_BUF) || (!file_depth) )
       return 0;
   else if (file_depth > code_depth)
       return (int)file_depth;
   else
       return code_depth;
}

static inline void SetEmailDecodeState(Email_DecodeState *ds, void *data, int max_depth, 
        int b64_depth, int qp_depth, int uu_depth, int bitenc_depth, int64_t file_depth)
{
    if ( max_depth & 7 )
    {
        max_depth += (8 - (max_depth & 7));
    }

    ds->decode_type = DECODE_NONE;
    ds->decode_present = 0;
    ds->prev_encoded_bytes = 0;
    ds->prev_encoded_buf = NULL;
    ds->decoded_bytes = 0;

    ds->encodeBuf = (uint8_t *)data;
    ds->decodeBuf = (uint8_t *)data + max_depth;
    ds->decodePtr = ds->decodeBuf;

    ds->b64_state.encode_depth = ds->b64_state.decode_depth = getCodeDepth(b64_depth, file_depth);
    ds->b64_state.encode_bytes_read = ds->b64_state.decode_bytes_read = 0;

    ds->qp_state.encode_depth = ds->qp_state.decode_depth = getCodeDepth(qp_depth, file_depth);
    ds->qp_state.encode_bytes_read = ds->qp_state.decode_bytes_read = 0;

    ds->uu_state.encode_depth = ds->uu_state.decode_depth = getCodeDepth(uu_depth, file_depth);
    ds->uu_state.encode_bytes_read = ds->uu_state.decode_bytes_read = 0;
    ds->uu_state.begin_found = 0;
    ds->uu_state.end_found = 0;

    ds->bitenc_state.depth = getCodeDepth(bitenc_depth, file_depth);
    ds->bitenc_state.bytes_read = 0;

}

static inline Email_DecodeState* NewEmailDecodeState(
    int max_depth, int b64_depth, int qp_depth, 
    int uu_depth, int bitenc_depth, int64_t file_depth)
{
    Email_DecodeState* ds = (Email_DecodeState*)calloc(1, sizeof(*ds) + (2*max_depth));
    uint8_t* data = ((uint8_t*)ds) + sizeof(*ds);

    if ( ds )
        SetEmailDecodeState(
            ds, data, max_depth, b64_depth, qp_depth, 
            uu_depth, bitenc_depth, file_depth);

    return ds;
}

static inline void DeleteEmailDecodeState(Email_DecodeState* ds)
{
    free(ds);
}

static inline void updateMaxDepth(int64_t file_depth, int *max_depth)
{
    if((!file_depth) || (file_depth > MAX_BUF))
    {
        *max_depth = MAX_BUF;
    }
    else if (file_depth > (*max_depth))
    {
       *max_depth = (int)file_depth;
    }
}
static inline void ClearPrevEncodeBuf(Email_DecodeState *ds)
{
    ds->prev_encoded_bytes = 0;
    ds->prev_encoded_buf = NULL;
}

static inline void ResetBytesRead(Email_DecodeState *ds)
{
    ds->uu_state.begin_found = ds->uu_state.end_found = 0;
    ClearPrevEncodeBuf(ds);
    ds->b64_state.encode_bytes_read = ds->b64_state.decode_bytes_read = 0;
    ds->qp_state.encode_bytes_read = ds->qp_state.decode_bytes_read = 0;
    ds->uu_state.encode_bytes_read = ds->uu_state.decode_bytes_read = 0;
    ds->bitenc_state.bytes_read = 0;
}

static inline void ResetDecodedBytes(Email_DecodeState *ds)
{
    ds->decodePtr = NULL;
    ds->decoded_bytes = 0;
    ds->decode_present = 0;
}


static inline void ResetEmailDecodeState(Email_DecodeState *ds)
{
    if ( ds == NULL )
        return;

    ds->uu_state.begin_found = ds->uu_state.end_found = 0;
    ResetDecodedBytes(ds);
    ClearPrevEncodeBuf(ds);

}

static inline void ClearEmailDecodeState(Email_DecodeState *ds)
{
    if(ds == NULL)
        return;

    ds->decode_type = DECODE_NONE;
    ResetEmailDecodeState(ds);
}

static inline int limitDetection(int depth, int decoded_bytes)
{
    if (!depth)
        return decoded_bytes;
    else if (depth < 0)
        return 0;
    else if (depth < decoded_bytes)
        return depth;
    else
        return decoded_bytes;
}

static inline int getDetectionSize(int b64_depth, int qp_depth, int uu_depth, int bitenc_depth, Email_DecodeState *ds)
{
    int iRet = 0;

    switch(ds->decode_type)
    {
        case DECODE_B64:
            iRet = limitDetection(b64_depth, ds->decoded_bytes);
            break;
        case DECODE_QP:
            iRet = limitDetection(qp_depth, ds->decoded_bytes);
            break;
        case DECODE_UU:
            iRet = limitDetection(uu_depth, ds->decoded_bytes);
            break;
        case DECODE_BITENC:
            iRet = limitDetection(bitenc_depth, ds->decoded_bytes);
            break;
        default:
            break;
    }

    return iRet;
}
#endif 
