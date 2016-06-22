//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

/**
**  @file       hi_client_norm.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      HTTP client normalization routines
**
**  We deal with the normalization of HTTP client requests headers and
**  URI.
**
**  In this file, we handle all the different HTTP request URI evasions.  The
**  list is:
**      - ASCII decoding
**      - UTF-8 decoding
**      - IIS Unicode decoding
**      - Directory traversals (self-referential and traversal)
**      - Multiple Slashes
**      - Double decoding
**      - %U decoding
**      - Bare Byte Unicode decoding
**
**      Base 36 is deprecated and essentially a noop
**      - Base36 decoding
**
**  NOTES:
**      - Initial development.  DJR
*/

#include "hi_client_norm.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>

#include "hi_norm.h"
#include "hi_util.h"
#include "hi_return_codes.h"
#include "utils/safec.h"

int hi_split_header_cookie(
    HI_SESSION*, u_char* header, int* i_header_len,
    u_char* cookie_header, int* i_cookie_len,
    const u_char* raw_header, int i_raw_header_len,
    COOKIE_PTR* cookie)
{
    int iRet = HI_SUCCESS;
    COOKIE_PTR* last_cookie = NULL;
    COOKIE_PTR* first_cookie = cookie;
    const u_char* raw_header_end = raw_header + i_raw_header_len;
    int this_cookie_len = 0;
    const u_char* this_header_start = raw_header;
    const u_char* this_header_end;
    int this_header_len = 0;
    size_t header_rem = *i_header_len;
    size_t cookie_rem = *i_cookie_len;

    if (!cookie || !i_header_len || !i_cookie_len)
        return HI_INVALID_ARG;

    /* Can't use hi_util_in_bounds header because == is okay */
    if (cookie->cookie_end > raw_header + i_raw_header_len)
        return HI_OUT_OF_BOUNDS;

    *i_header_len = 0;
    *i_cookie_len = 0;

    do
    {
        this_cookie_len = cookie->cookie_end - cookie->cookie;
        this_header_end = cookie->cookie;
        this_header_len = this_header_end - this_header_start;

        /* Trim the header and only copy what we can store in the buf */
        if (*i_header_len + this_header_len > MAX_URI)
        {
            this_header_len = MAX_URI - *i_header_len;
        }
        /* Copy out the headers from start to beginning of the cookie */
        if (this_header_len > 0)
        {
            if (header_rem >= (unsigned)this_header_len)
            {
                memcpy_s(header + *i_header_len, header_rem, this_header_start, this_header_len);
                *i_header_len += this_header_len;
                header_rem -= this_header_len;
            }
        }
        else
        {
            DebugFormat(DEBUG_HTTPINSPECT,
                "HttpInspect: no leading header: %ld to %d\n",
                this_header_end - this_header_start, this_header_len);
        }

        /* Trim the cookie and only copy what we can store in the buf */
        if (*i_cookie_len + this_cookie_len > MAX_URI)
        {
            this_cookie_len = MAX_URI - *i_cookie_len;
        }
        /* And copy the cookie */
        if (this_cookie_len > 0)
        {
            if (cookie_rem >= (unsigned)this_cookie_len)
            {
                memcpy_s(cookie_header + *i_cookie_len, cookie_rem, cookie->cookie, this_cookie_len);
                *i_cookie_len += this_cookie_len;
                cookie_rem -= this_header_len;
            }
        }
        else
        {
            DebugFormat(DEBUG_HTTPINSPECT, "HttpInspect: trimming cookie: %ld to %d\n",
                cookie->cookie_end - cookie->cookie, this_cookie_len);
        }

        /* update for the next one */
        this_header_start = cookie->cookie_end;
        cookie = cookie->next;
        if (last_cookie && (last_cookie != first_cookie))
        {
            snort_free(last_cookie);
        }
        last_cookie = cookie;
        if (!cookie)
        {
            this_header_len = raw_header + i_raw_header_len - this_header_start;
        }
        else
        {
            this_header_len = cookie->cookie - this_header_start;
        }
#ifdef DEBUG_MSGS
        this_header_end = this_header_start + this_header_len;
#endif

        if ((*i_header_len == MAX_URI) ||
            (*i_cookie_len == MAX_URI))
        {
            last_cookie = NULL;
        }
    }
    while (last_cookie);

    /* Clear out the 'first' cookie since we're done with it
       Eliminates unexptected 'reuse' in the case of pipeline'd requests. */
    memset(first_cookie, 0, sizeof(COOKIE_PTR));

    if (this_header_len && hi_util_in_bounds(raw_header, raw_header_end, this_header_start))
    {
        /* Trim the header and only copy what we can store in the buf */
        if (*i_header_len + this_header_len > MAX_URI)
        {
            this_header_len = MAX_URI - *i_header_len;
        }

        /* Copy the remaining headers after the last cookie */
        if (this_header_len > 0)
        {
            if (header_rem >= (unsigned)this_header_len)
            {
                memcpy_s(header + *i_header_len, header_rem, this_header_start, this_header_len);
                *i_header_len += this_header_len;
                header_rem -= this_header_len;
            }
        }
        else
        {
            DebugFormat(DEBUG_HTTPINSPECT,
                "HttpInspect: no leading header: %ld to %d\n",
                this_header_end - this_header_start, this_header_len);
        }
    }

    return iRet;
}

int hi_client_norm(HI_SESSION* session)
{
    static THREAD_LOCAL u_char UriBuf[MAX_URI];
    static THREAD_LOCAL u_char HeaderBuf[MAX_URI];
    static THREAD_LOCAL u_char CookieBuf[MAX_URI];
    static THREAD_LOCAL u_char RawHeaderBuf[MAX_URI];
    static THREAD_LOCAL u_char RawCookieBuf[MAX_URI];
    static THREAD_LOCAL u_char PostBuf[MAX_URI];
    HI_CLIENT_REQ* ClientReq;
    int iRet;
    int iUriBufSize = MAX_URI;
    int iRawHeaderBufSize = MAX_URI;
    int iRawCookieBufSize = MAX_URI;
    int iHeaderBufSize = MAX_URI;
    int iCookieBufSize = MAX_URI;
    int iPostBufSize = MAX_URI;
    uint16_t encodeType = 0;
    u_int updated_uri_size = 0;
    const u_char* updated_uri_start = NULL;

    if (!session || !session->server_conf)
    {
        return HI_INVALID_ARG;
    }

    ClientReq = &session->client.request;
    ClientReq->uri_encode_type = 0;
    ClientReq->header_encode_type = 0;
    ClientReq->cookie_encode_type = 0;
    ClientReq->post_encode_type = 0;

    /* Handle URI normalization */
    if (ClientReq->uri_norm)
    {
        updated_uri_start = ClientReq->uri;
        updated_uri_size = ClientReq->uri_size;
        session->norm_flags &= ~HI_BODY;
        if (proxy_start && (ClientReq->uri == proxy_start))
        {
            if (hi_util_in_bounds(ClientReq->uri, (ClientReq->uri + ClientReq->uri_size),
                proxy_end))
            {
                updated_uri_start = proxy_end;
                updated_uri_size = (ClientReq->uri_size) - (proxy_end - proxy_start);
            }
        }
        proxy_start = proxy_end = NULL;
        iRet = hi_norm_uri(session, UriBuf, &iUriBufSize,
            updated_uri_start, updated_uri_size, &encodeType);
        if (iRet == HI_NONFATAL_ERR)
        {
            /* There was a non-fatal problem normalizing */
            ClientReq->uri_norm = NULL;
            ClientReq->uri_norm_size = 0;
            ClientReq->uri_encode_type = 0;
        }
        else
        {
            /* Client code is expecting these to be set to non-NULL if
             * normalization occurred. */
            ClientReq->uri_norm      = UriBuf;
            ClientReq->uri_norm_size = iUriBufSize;
            ClientReq->uri_encode_type = encodeType;
        }
        encodeType = 0;
    }
    else
    {
        if (proxy_start && (ClientReq->uri == proxy_start))
        {
            if (hi_util_in_bounds(ClientReq->uri, (ClientReq->uri + ClientReq->uri_size),
                proxy_end))
            {
                ClientReq->uri_norm = proxy_end;
                ClientReq->uri_norm_size = (ClientReq->uri_size) - (proxy_end - proxy_start);
            }
        }
        proxy_start = proxy_end = NULL;
    }

    if (ClientReq->cookie.cookie)
    {
        /* There is an HTTP header with a cookie, look for the cookie &
         * separate the two buffers */
        iRet = hi_split_header_cookie(session,
            RawHeaderBuf, &iRawHeaderBufSize,
            RawCookieBuf, &iRawCookieBufSize,
            ClientReq->header_raw, ClientReq->header_raw_size,
            &ClientReq->cookie);
        if ( iRet == HI_SUCCESS )
        {
            ClientReq->cookie.cookie = RawCookieBuf;
            ClientReq->cookie.cookie_end = RawCookieBuf + iRawCookieBufSize;
        }
    }
    else
    {
        if (ClientReq->header_raw_size)
        {
            if (ClientReq->header_raw_size > MAX_URI)
            {
                ClientReq->header_raw_size = MAX_URI;
            }
            /* Limiting to MAX_URI above should cause this to always return SAFEMEM_SUCCESS */
            memcpy_s(RawHeaderBuf, iRawHeaderBufSize,
                ClientReq->header_raw, ClientReq->header_raw_size);
        }
        iRawHeaderBufSize = ClientReq->header_raw_size;
        iRawCookieBufSize = 0;
    }

    if (ClientReq->header_norm && session->server_conf->normalize_headers)
    {
        session->norm_flags &= ~HI_BODY;

        // FIXIT-M the usefulness of this one size fits all normalization
        // is questionable.  A specific issue is that a header such as
        // "Referer: http://www.foo.com/home" will trigger multislash
        // normalization and alert.

        iRet = hi_norm_uri(session, HeaderBuf, &iHeaderBufSize,
            RawHeaderBuf, iRawHeaderBufSize, &encodeType);
        if (iRet == HI_NONFATAL_ERR)
        {
            /* There was a non-fatal problem normalizing */
            ClientReq->header_norm = NULL;
            ClientReq->header_norm_size = 0;
            ClientReq->header_encode_type = 0;
        }
        else
        {
            /* Client code is expecting these to be set to non-NULL if
             * normalization occurred. */
            ClientReq->header_norm      = HeaderBuf;
            ClientReq->header_norm_size = iHeaderBufSize;
            ClientReq->header_encode_type = encodeType;
        }
        encodeType = 0;
    }
    else
    {
        /* Client code is expecting these to be set to non-NULL if
         * normalization occurred. */
        if (iRawHeaderBufSize)
        {
            ClientReq->header_norm      = RawHeaderBuf;
            ClientReq->header_norm_size = iRawHeaderBufSize;
            ClientReq->header_encode_type = 0;
        }
    }

    if (ClientReq->cookie.cookie && session->server_conf->normalize_cookies)
    {
        session->norm_flags &= ~HI_BODY;
        iRet = hi_norm_uri(session, CookieBuf, &iCookieBufSize,
            RawCookieBuf, iRawCookieBufSize, &encodeType);
        if (iRet == HI_NONFATAL_ERR)
        {
            /* There was a non-fatal problem normalizing */
            ClientReq->cookie_norm = NULL;
            ClientReq->cookie_norm_size = 0;
            ClientReq->cookie_encode_type = 0;
        }
        else
        {
            /* Client code is expecting these to be set to non-NULL if
             * normalization occurred. */
            ClientReq->cookie_norm      = CookieBuf;
            ClientReq->cookie_norm_size = iCookieBufSize;
            ClientReq->cookie_encode_type = encodeType;
        }
        encodeType = 0;
    }
    else
    {
        /* Client code is expecting these to be set to non-NULL if
         * normalization occurred. */
        if (iRawCookieBufSize)
        {
            ClientReq->cookie_norm      = RawCookieBuf;
            ClientReq->cookie_norm_size = iRawCookieBufSize;
            ClientReq->cookie_encode_type = 0;
        }
    }

    /* Handle normalization of post methods.
     * Note: posts go into a different buffer. */
    if (ClientReq->post_norm)
    {
        session->norm_flags |= HI_BODY;
        iRet = hi_norm_uri(session, PostBuf, &iPostBufSize,
            ClientReq->post_raw, ClientReq->post_raw_size, &encodeType);
        if (iRet == HI_NONFATAL_ERR)
        {
            ClientReq->post_norm = NULL;
            ClientReq->post_norm_size = 0;
            ClientReq->post_encode_type = 0;
        }
        else
        {
            ClientReq->post_norm      = PostBuf;
            ClientReq->post_norm_size = iPostBufSize;
            ClientReq->post_encode_type = encodeType;
        }
        encodeType = 0;
    }

    /*
    printf("** uri_norm = |");
    for(iCtr = 0; iCtr < ClientReq->uri_norm_size; iCtr++)
    {
        if(!isascii((int)ClientReq->uri_norm[iCtr]) ||
           !isprint((int)ClientReq->uri_norm[iCtr]))
        {
            printf(".[%.2x]", ClientReq->uri_norm[iCtr]);
            continue;
        }
        printf("%c", ClientReq->uri_norm[iCtr]);
    }
    printf("| size = %u\n", ClientReq->uri_norm_size);
    */

    return HI_SUCCESS;
}

