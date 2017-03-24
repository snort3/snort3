//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#ifndef HI_CLIENT_H
#define HI_CLIENT_H

#include "flow/flow.h"

#include "hi_main.h"

#define URI_END  99
#define POST_END 100
#define NO_URI   101

// Special processing for the HTTP X-Forwarded-For request header
#define XFF_MODE_MASK      (0x000f)
#define XFF_EXFF_MASK      (0x000c)

#define TRUE_CLIENT_IP_HDR (0x01)
#define XFF_HDR            (0x02)
#define HDRS_BOTH          (0x03)
#define XFF_HEADERS        (0x04)  // Using xff_headers list
#define XFF_HEADERS_ACTIVE (0x08)  // Looking for highest precedence xff header
#define XFF_INIT (XFF_HEADERS | XFF_HEADERS_ACTIVE)

#define XFF_TOP_PRECEDENCE (1)
#define XFF_BOT_PRECEDENCE (255)

typedef struct s_COOKIE_PTR
{
    const uint8_t* cookie;
    const uint8_t* cookie_end;
    struct s_COOKIE_PTR* next;
} COOKIE_PTR;

typedef struct s_CONTLEN_PTR
{
    const uint8_t* cont_len_start;
    const uint8_t* cont_len_end;
    uint32_t len;
} CONTLEN_PTR;

typedef struct s_CONT_ENCODING_PTR
{
    const uint8_t* cont_encoding_start;
    const uint8_t* cont_encoding_end;
    uint16_t compress_fmt;
} CONT_ENCODING_PTR;

typedef struct s_HEADER_FIELD_PTR
{
    COOKIE_PTR* cookie;
    CONTLEN_PTR* content_len;
    CONT_ENCODING_PTR* content_encoding;
} HEADER_FIELD_PTR;

/* These numbers were chosen to avoid conflicting with
 * the return codes in hi_return_codes.h */

/**
 **  This structure holds pointers to the different sections of an HTTP
 **  request.  We need to track where whitespace begins and ends, so we
 **  can evaluate the placement of the URI correctly.
 **
 **  For example,
 **
 **  GET     / HTTP/1.0
 **     ^   ^
 **   start end
 **
 **  The end space pointers are set to NULL if there is space until the end
 **  of the buffer.
 */

typedef struct s_URI_PTR
{
    const uint8_t* uri;                /* the beginning of the URI */
    const uint8_t* uri_end;            /* the end of the URI */
    const uint8_t* norm;               /* ptr to first normalization occurence */
    const uint8_t* ident;              /* ptr to beginning of the HTTP identifier */
    const uint8_t* first_sp_start;     /* beginning of first space delimiter */
    const uint8_t* first_sp_end;       /* end of first space delimiter */
    const uint8_t* second_sp_start;    /* beginning of second space delimiter */
    const uint8_t* second_sp_end;      /* end of second space delimiter */
    const uint8_t* param;              /* '?' (beginning of parameter field) */
    const uint8_t* delimiter;          /* HTTP URI delimiter (\r\n\) */
    const uint8_t* last_dir;           /* ptr to last dir, so we catch long dirs */
    const uint8_t* proxy;              /* ptr to the absolute URI */
}  URI_PTR;

typedef struct s_HEADER_PTR
{
    URI_PTR header;
    COOKIE_PTR cookie;
    CONTLEN_PTR content_len;
    CONT_ENCODING_PTR content_encoding;
    bool is_chunked;
} HEADER_PTR;

typedef struct s_HI_CLIENT_REQ
{
    const uint8_t* uri;
    const uint8_t* uri_norm;
    const uint8_t* post_raw;
    const uint8_t* post_norm;
    const uint8_t* header_raw;
    const uint8_t* header_norm;
    COOKIE_PTR cookie;
    const uint8_t* cookie_norm;
    const uint8_t* method_raw;

    unsigned int uri_size;
    unsigned int uri_norm_size;
    unsigned int post_raw_size;
    unsigned int post_norm_size;
    unsigned int header_raw_size;
    unsigned int header_norm_size;
    unsigned int cookie_norm_size;
    unsigned int method_size;

    const uint8_t* pipeline_req;
    uint8_t method;
    uint16_t uri_encode_type;
    uint16_t header_encode_type;
    uint16_t cookie_encode_type;
    uint16_t post_encode_type;
    const uint8_t* content_type;
}  HI_CLIENT_REQ;

typedef struct s_HI_CLIENT
{
    HI_CLIENT_REQ request;
    int (* state)(void*, unsigned char, int);
}  HI_CLIENT;

typedef struct s_HI_CLIENT_HDR_ARGS
{
    HEADER_PTR* hdr_ptr;
    HEADER_FIELD_PTR* hdr_field_ptr;
    HttpSessionData* sd;
    int strm_ins;
    int hst_name_hdr;
    uint8_t true_clnt_xff;
    uint8_t top_precedence;
    uint8_t new_precedence;
} HI_CLIENT_HDR_ARGS;

int hi_client_inspection(Packet* p, void* session, HttpSessionData* hsd, int stream_ins);
int hi_client_init();

char** hi_client_get_field_names();

extern const uint8_t* proxy_start;
extern const uint8_t* proxy_end;

struct HI_SESSION;

int CheckLongDir(HI_SESSION* session, URI_PTR* uri_ptr, const uint8_t* ptr);

/**  This makes passing function arguments much more readable and easier
**  to follow.
*/
typedef int (* LOOKUP_FCN)(
    HI_SESSION*, const uint8_t* start, const uint8_t* end, const uint8_t**, URI_PTR*);

int NextNonWhiteSpace(HI_SESSION*, const uint8_t*, const uint8_t*, const uint8_t**, URI_PTR*);

/*
**  The lookup table contains functions for different HTTP delimiters
**  (like whitespace and the HTTP delimiter \r and \n).
*/
extern LOOKUP_FCN lookup_table[256];

#endif

