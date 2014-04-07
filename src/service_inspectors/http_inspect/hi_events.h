/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

#ifndef HI_EVENTS_H
#define HI_EVENTS_H

#include "hi_include.h"

#define GID_HTTP_CLIENT  119
#define GID_HTTP_SERVER  120 

/*
**  Client Events
*/
typedef enum _HI_CLI_EVENTS 
{
    HI_CLIENT_ASCII =       1,
    HI_CLIENT_DOUBLE_DECODE  , 
    HI_CLIENT_U_ENCODE       , 
    HI_CLIENT_BARE_BYTE      , 
    /* Base36 is deprecated - leave here so events keep the same number */
    HI_CLIENT_BASE36         ,
    HI_CLIENT_UTF_8          , 
    HI_CLIENT_IIS_UNICODE    , 
    HI_CLIENT_MULTI_SLASH    , 
    HI_CLIENT_IIS_BACKSLASH  , 
    HI_CLIENT_SELF_DIR_TRAV  , 
    HI_CLIENT_DIR_TRAV       ,
    HI_CLIENT_APACHE_WS      ,
    HI_CLIENT_IIS_DELIMITER  ,
    HI_CLIENT_NON_RFC_CHAR   ,
    HI_CLIENT_OVERSIZE_DIR   ,
    HI_CLIENT_LARGE_CHUNK    ,
    HI_CLIENT_PROXY_USE      ,
    HI_CLIENT_WEBROOT_DIR    ,
    HI_CLIENT_LONG_HDR       ,
    HI_CLIENT_MAX_HEADERS    ,
    HI_CLIENT_MULTIPLE_CONTLEN,
    HI_CLIENT_CHUNK_SIZE_MISMATCH,
    HI_CLIENT_INVALID_TRUEIP ,
    HI_CLIENT_MULTIPLE_HOST_HDRS,
    HI_CLIENT_LONG_HOSTNAME  ,
    HI_CLIENT_EXCEEDS_SPACES ,
    HI_CLIENT_CONSECUTIVE_SMALL_CHUNKS,
    HI_CLIENT_UNBOUNDED_POST,
    HI_CLIENT_MULTIPLE_TRUEIP_IN_SESSION,
    HI_CLIENT_BOTH_TRUEIP_XFF_HDRS,
    HI_CLIENT_UNKNOWN_METHOD,
    HI_CLIENT_SIMPLE_REQUEST,
    HI_CLIENT_UNESCAPED_SPACE_URI,
    HI_CLIENT_PIPELINE_MAX,
    HI_CLIENT_EVENT_NUM
} HI_CLI_EVENTS;

typedef enum _HI_EVENTS
{
    HI_ANOM_SERVER =         1,
    HI_SERVER_INVALID_STATCODE,
    HI_SERVER_NO_CONTLEN,
    HI_SERVER_UTF_NORM_FAIL,
    HI_SERVER_UTF7,
    HI_SERVER_DECOMPR_FAILED,
    HI_SERVER_CONSECUTIVE_SMALL_CHUNKS,
    HI_CLISRV_MSG_SIZE_EXCEPTION,
    HI_SERVER_JS_OBFUSCATION_EXCD,
    HI_SERVER_JS_EXCESS_WS,
    HI_SERVER_MIXED_ENCODINGS,
    HI_SERVER_EVENT_NUM
}HI_EVENTS;

/*
**  These defines are the alert names for each event
*/
#define HI_CLIENT_ASCII_STR                          \
    "(http_inspect) ascii encoding"
#define HI_CLIENT_DOUBLE_DECODE_STR                  \
    "(http_inspect) double decoding attack"
#define HI_CLIENT_U_ENCODE_STR                       \
    "(http_inspect) u encoding"
#define HI_CLIENT_BARE_BYTE_STR                      \
    "(http_inspect) bare byte unicode encoding"
/* Base36 is deprecated - leave here so events keep the same number */
#define HI_CLIENT_BASE36_STR                         \
    "(http_inspect) base36 encoding"
#define HI_CLIENT_UTF_8_STR                          \
    "(http_inspect) utf-8 encoding"
#define HI_CLIENT_IIS_UNICODE_STR                    \
    "(http_inspect) iis unicode codepoint encoding"
#define HI_CLIENT_MULTI_SLASH_STR                    \
    "(http_inspect) multi_slash encoding"
#define HI_CLIENT_IIS_BACKSLASH_STR                  \
    "(http_inspect) iis backslash evasion"
#define HI_CLIENT_SELF_DIR_TRAV_STR                  \
    "(http_inspect) self directory traversal"
#define HI_CLIENT_DIR_TRAV_STR                       \
    "(http_inspect) directory traversal"
#define HI_CLIENT_APACHE_WS_STR                      \
    "(http_inspect) apache whitespace (tab)"
#define HI_CLIENT_IIS_DELIMITER_STR                  \
    "(http_inspect) non-rfc http delimiter"
#define HI_CLIENT_NON_RFC_CHAR_STR                   \
    "(http_inspect) non-rfc defined char"
#define HI_CLIENT_OVERSIZE_DIR_STR                   \
    "(http_inspect) oversize request-uri directory"
#define HI_CLIENT_LARGE_CHUNK_STR                    \
    "(http_inspect) oversize chunk encoding"
#define HI_CLIENT_PROXY_USE_STR                      \
    "(http_inspect) unauthorized proxy use detected"
#define HI_CLIENT_WEBROOT_DIR_STR                    \
    "(http_inspect) webroot directory traversal"
#define HI_CLIENT_LONG_HDR_STR                       \
    "(http_inspect) long header"
#define HI_CLIENT_MAX_HEADERS_STR                    \
    "(http_inspect) max header fields"
#define HI_CLIENT_MULTIPLE_CONTLEN_STR               \
    "(http_inspect) multiple content length"
#define HI_CLIENT_CHUNK_SIZE_MISMATCH_STR            \
    "(http_inspect) chunk size mismatch detected"
#define HI_CLIENT_MULTIPLE_HOST_HDRS_STR             \
    "(http_inspect) multiple host hdrs detected"
#define HI_CLIENT_INVALID_TRUEIP_STR                 \
    "(http_inspect) invalid ip in true-client-ip/xff header"
#define HI_CLIENT_LONG_HOSTNAME_STR                  \
    "(http_inspect) hostname exceeds 255 characters"
#define HI_CLIENT_EXCEEDS_SPACES_STR                 \
    "(http_inspect) header parsing space saturation"
#define HI_CLIENT_CONSECUTIVE_SMALL_CHUNKS_STR       \
    "(http_inspect) client consecutive small chunk sizes"
#define HI_CLIENT_UNBOUNDED_POST_STR                 \
    "(http_inspect) post w/o content-length or chunks"
#define HI_CLIENT_MULTIPLE_TRUEIP_IN_SESSION_STR     \
    "(http_inspect) multiple true ips in a session"
#define HI_CLIENT_BOTH_TRUEIP_XFF_HDRS_STR           \
    "(http_inspect) both true_client_ip and xff hdrs present"
#define HI_CLIENT_UNKNOWN_METHOD_STR                 \
    "(http_inspect) unknown method"
#define HI_CLIENT_SIMPLE_REQUEST_STR                 \
    "(http_inspect) simple request"
#define HI_CLIENT_UNESCAPED_SPACE_URI_STR            \
    "(http_inspect) unescaped space in http uri"
#define HI_CLIENT_PIPELINE_MAX_STR                   \
    "(http_inspect) too many pipelined requests"

/*
**  Server Events
*/

#define HI_ANOM_SERVER_STR                           \
    "(http_inspect) anomalous http server on undefined http port"
#define HI_SERVER_INVALID_STATCODE_STR               \
    "(http_inspect) invalid status code in http response"
#define HI_SERVER_NO_CONTLEN_STR                     \
    "(http_inspect) no content-length or transfer-encoding in http response"
#define HI_SERVER_UTF_NORM_FAIL_STR                  \
    "(http_inspect) http response has utf charset which failed to normalize"
#define HI_SERVER_UTF7_STR                           \
    "(http_inspect) http response has utf-7 charset"
#define HI_SERVER_DECOMPR_FAILED_STR                 \
    "(http_inspect) http response gzip decompression failed"
#define HI_SERVER_CONSECUTIVE_SMALL_CHUNKS_STR       \
    "(http_inspect) server consecutive small chunk sizes"
#define HI_CLISRV_MSG_SIZE_EXCEPTION_STR             \
    "(http_inspect) invalid content-length or chunk size"
#define HI_SERVER_JS_OBFUSCATION_EXCD_STR            \
    "(http_inspect) javascript obfuscation levels exceeds 1"
#define HI_SERVER_JS_EXCESS_WS_STR                   \
    "(http_inspect) javascript whitespaces exceeds max allowed"
#define HI_SERVER_MIXED_ENCODINGS_STR                \
    "(http_inspect) multiple encodings within javascript obfuscated data"

#endif

