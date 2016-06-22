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

#include "hi_server_norm.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>

#include "hi_norm.h"
#include "hi_util.h"
#include "hi_return_codes.h"

#include "detection/detection_util.h"
#include "utils/safec.h"
#include "utils/util_utf.h"

int hi_server_norm(HI_SESSION* session, HttpSessionData* hsd)
{
    static THREAD_LOCAL u_char HeaderBuf[MAX_URI];
    static THREAD_LOCAL u_char CookieBuf[MAX_URI];
    static THREAD_LOCAL u_char RawHeaderBuf[MAX_URI];
    static THREAD_LOCAL u_char RawCookieBuf[MAX_URI];
    HI_SERVER_RESP* ServerResp;
    int iRet;
    int iRawHeaderBufSize = MAX_URI;
    int iRawCookieBufSize = MAX_URI;
    int iHeaderBufSize = MAX_URI;
    int iCookieBufSize = MAX_URI;
    uint16_t encodeType = 0;

    if (!session || !session->server_conf)
    {
        return HI_INVALID_ARG;
    }

    ServerResp = &session->server.response;
    ServerResp->header_encode_type = 0;
    ServerResp->cookie_encode_type = 0;

    if (ServerResp->cookie.cookie)
    {
        /* There is an HTTP header with a cookie, look for the cookie &
         * separate the two buffers */
        iRet = hi_split_header_cookie(session,
            RawHeaderBuf, &iRawHeaderBufSize,
            RawCookieBuf, &iRawCookieBufSize,
            ServerResp->header_raw, ServerResp->header_raw_size,
            &ServerResp->cookie);
        if ( iRet == HI_SUCCESS)
        {
            ServerResp->cookie.cookie = RawCookieBuf;
            ServerResp->cookie.cookie_end = RawCookieBuf + iRawCookieBufSize;
        }
    }
    else
    {
        if (ServerResp->header_raw_size)
        {
            if (ServerResp->header_raw_size > MAX_URI)
            {
                ServerResp->header_raw_size = MAX_URI;
            }
            /* Limiting to MAX_URI above should cause this to always return SAFEMEM_SUCCESS */
            memcpy_s(RawHeaderBuf, iRawHeaderBufSize,
                ServerResp->header_raw, ServerResp->header_raw_size);
        }
        iRawHeaderBufSize = ServerResp->header_raw_size;
        iRawCookieBufSize = 0;
    }

    if (ServerResp->header_norm && session->server_conf->normalize_headers)
    {
        session->norm_flags &= ~HI_BODY;
        iRet = hi_norm_uri(session, HeaderBuf, &iHeaderBufSize,
            RawHeaderBuf, iRawHeaderBufSize, &encodeType);
        if (iRet == HI_NONFATAL_ERR)
        {
            /* There was a non-fatal problem normalizing */
            ServerResp->header_norm = NULL;
            ServerResp->header_norm_size = 0;
            ServerResp->header_encode_type = 0;
        }
        else
        {
            /* Client code is expecting these to be set to non-NULL if
             * normalization occurred. */
            ServerResp->header_norm      = HeaderBuf;
            ServerResp->header_norm_size = iHeaderBufSize;
            ServerResp->header_encode_type = encodeType;
        }
        encodeType = 0;
    }
    else
    {
        /* Client code is expecting these to be set to non-NULL if
         * normalization occurred. */
        if (iRawHeaderBufSize)
        {
            ServerResp->header_norm      = RawHeaderBuf;
            ServerResp->header_norm_size = iRawHeaderBufSize;
            ServerResp->header_encode_type = 0;
        }
    }

    if (ServerResp->cookie.cookie && session->server_conf->normalize_cookies)
    {
        session->norm_flags &= ~HI_BODY;
        iRet = hi_norm_uri(session, CookieBuf, &iCookieBufSize,
            RawCookieBuf, iRawCookieBufSize, &encodeType);
        if (iRet == HI_NONFATAL_ERR)
        {
            /* There was a non-fatal problem normalizing */
            ServerResp->cookie_norm = NULL;
            ServerResp->cookie_norm_size = 0;
            ServerResp->cookie_encode_type = 0;
        }
        else
        {
            /* Client code is expecting these to be set to non-NULL if
             * normalization occurred. */
            ServerResp->cookie_norm      = CookieBuf;
            ServerResp->cookie_norm_size = iCookieBufSize;
            ServerResp->cookie_encode_type = encodeType;
        }
        encodeType = 0;
    }
    else
    {
        /* Client code is expecting these to be set to non-NULL if
         * normalization occurred. */
        if (iRawCookieBufSize)
        {
            ServerResp->cookie_norm      = RawCookieBuf;
            ServerResp->cookie_norm_size = iRawCookieBufSize;
            ServerResp->cookie_encode_type = 0;
        }
    }

    if (session->server_conf->normalize_utf && (ServerResp->body_size > 0))
    {
        int bytes_copied, result, charset;

        if (hsd)
        {
            charset = get_decode_utf_state_charset(&(hsd->utf_state));

            if (charset == CHARSET_UNKNOWN)
            {
                /* Got a text content type but no charset.
                 * Look for potential BOM (Byte Order Mark) */
                if (ServerResp->body_size >= 4)
                {
                    uint8_t size = 0;

                    if (!memcmp(ServerResp->body, "\x00\x00\xFE\xFF", 4))
                    {
                        charset = CHARSET_UTF32BE;
                        size = 4;
                    }
                    else if (!memcmp(ServerResp->body, "\xFF\xFE\x00\x00", 4))
                    {
                        charset = CHARSET_UTF32LE;
                        size = 4;
                    }
                    else if (!memcmp(ServerResp->body, "\xFE\xFF", 2))
                    {
                        charset = CHARSET_UTF16BE;
                        size = 2;
                    }
                    else if (!memcmp(ServerResp->body, "\xFF\xFE", 2))
                    {
                        charset = CHARSET_UTF16LE;
                        size = 2;
                    }
                    else
                        charset = CHARSET_DEFAULT; // ensure we don't try again

                    ServerResp->body += size;
                    ServerResp->body_size -= size;
                }
                else
                    charset = CHARSET_DEFAULT; // ensure we don't try again

                set_decode_utf_state_charset(&(hsd->utf_state), charset);
            }

            /* Normalize server responses with utf-16le, utf-16be, utf-32le,
               or utf-32be charsets.*/
            switch (charset)
            {
            case CHARSET_UTF16LE:
            case CHARSET_UTF16BE:
            case CHARSET_UTF32LE:
            case CHARSET_UTF32BE:
                result = DecodeUTF((char*)ServerResp->body, ServerResp->body_size,
                    (char*)HttpDecodeBuf.data, sizeof(HttpDecodeBuf.data),
                    &bytes_copied,
                    &(hsd->utf_state));

                if (result == DECODE_UTF_FAILURE)
                {
                    hi_set_event(GID_HTTP_SERVER, HI_SERVER_UTF_NORM_FAIL);
                }
                SetHttpDecode((uint16_t)bytes_copied);
                ServerResp->body = HttpDecodeBuf.data;
                ServerResp->body_size = HttpDecodeBuf.len;
                break;
            default:
                break;
            }
        }
    }

    if (session->server_conf->normalize_javascript && (ServerResp->body_size > 0))
    {
        int js_present, status, index;
        char* ptr, * start, * end;
        JSState js;

        js.allowed_spaces = session->server_conf->max_js_ws;
        js.allowed_levels = MAX_ALLOWED_OBFUSCATION;
        js.alerts = 0;

        js_present = status = index = 0;
        start = (char*)ServerResp->body;
        ptr = start;
        end = start + ServerResp->body_size;

        while (ptr < end)
        {
            char* angle_bracket, * js_start;
            int type_js, bytes_copied, script_found;
            bytes_copied = 0;
            type_js = 0;
            hi_current_search = &hi_js_search[0];

            script_found = hi_javascript_search_mpse->find(
                (const char*)ptr, (end-ptr), HI_SearchStrFound);

            if (script_found > 0)
            {
                js_start = ptr + hi_search_info.index;
                angle_bracket = (char*)SnortStrnStr((const char*)(js_start), (end - js_start),
                    ">");
                if (!angle_bracket)
                    break;

                if (angle_bracket > js_start)
                {
                    hi_current_search = &hi_html_search[0];
                    script_found = hi_htmltype_search_mpse->find(
                        (const char*)js_start, (angle_bracket-js_start), HI_SearchStrFound);

                    js_start = angle_bracket;
                    if (script_found > 0)
                    {
                        switch (hi_search_info.id)
                        {
                        case HTML_JS:
                            js_present = 1;
                            type_js = 1;
                            break;
                        default:
                            type_js = 0;
                            break;
                        }
                    }
                    else
                    {
                        //if no type or language is found we assume its a javascript
                        js_present = 1;
                        type_js = 1;
                    }
                }
                //Save before the <script> begins
                if (js_start > ptr)
                {
                    if ((unsigned long)(js_start - ptr) > sizeof(HttpDecodeBuf.data) - index)
                        break;

                    memmove_s(HttpDecodeBuf.data + index,
                        sizeof(HttpDecodeBuf.data) - index, ptr, js_start - ptr);

                    index += js_start - ptr;
                }

                ptr = js_start;
                if (!type_js)
                    continue;

                if (session->server_conf->iis_unicode.on)
                {
                    JSNormalizeDecode(js_start, (uint16_t)(end-js_start),
                        (char*)HttpDecodeBuf.data+index, (uint16_t)(sizeof(HttpDecodeBuf.data) -
                        index),
                        &ptr, &bytes_copied, &js, session->server_conf->iis_unicode_map);
                }
                else
                {
                    JSNormalizeDecode(js_start, (uint16_t)(end-js_start),
                        (char*)HttpDecodeBuf.data+index, (uint16_t)(sizeof(HttpDecodeBuf.data) -
                        index),
                        &ptr, &bytes_copied, &js, NULL);
                }
                index += bytes_copied;
            }
            else
                break;
        }

        if (js_present)
        {
            if ( ptr < end && (sizeof(HttpDecodeBuf.data) - index >= (unsigned long)(end - ptr)))
            {
                memmove_s(HttpDecodeBuf.data + index,
                    sizeof(HttpDecodeBuf.data) - index, ptr, end - ptr);

                index += end - ptr;
            }
            SetHttpDecode((uint16_t)index);
            ServerResp->body = HttpDecodeBuf.data;
            ServerResp->body_size = index;
            if (js.alerts)
            {
                if (js.alerts & ALERT_LEVELS_EXCEEDED)
                {
                    hi_set_event(GID_HTTP_SERVER, HI_SERVER_JS_OBFUSCATION_EXCD);
                }
                if (js.alerts & ALERT_SPACES_EXCEEDED)
                {
                    hi_set_event(GID_HTTP_SERVER, HI_SERVER_JS_EXCESS_WS);
                }
                if (js.alerts & ALERT_MIXED_ENCODINGS)
                {
                    hi_set_event(GID_HTTP_SERVER, HI_SERVER_MIXED_ENCODINGS);
                }
            }

            if (hsd)
                hsd->log_flags |= HTTP_LOG_JSNORM_DATA;
        }
    }

    return HI_SUCCESS;
}

