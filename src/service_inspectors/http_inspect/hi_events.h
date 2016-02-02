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

#ifndef HI_EVENTS_H
#define HI_EVENTS_H

#include "hi_include.h"

#define GID_HTTP_CLIENT  119
#define GID_HTTP_SERVER  120

// Client Events
typedef enum _HI_CLI_EVENTS
{
    HI_CLIENT_ASCII =       1,
    HI_CLIENT_DOUBLE_DECODE,
    HI_CLIENT_U_ENCODE,
    HI_CLIENT_BARE_BYTE,
    /* Base36 is deprecated - leave here so events keep the same number */
    HI_CLIENT_BASE36,
    HI_CLIENT_UTF_8,
    HI_CLIENT_IIS_UNICODE,
    HI_CLIENT_MULTI_SLASH,
    HI_CLIENT_IIS_BACKSLASH,
    HI_CLIENT_SELF_DIR_TRAV,
    HI_CLIENT_DIR_TRAV,
    HI_CLIENT_APACHE_WS,
    HI_CLIENT_IIS_DELIMITER,
    HI_CLIENT_NON_RFC_CHAR,
    HI_CLIENT_OVERSIZE_DIR,
    HI_CLIENT_LARGE_CHUNK,
    HI_CLIENT_PROXY_USE,
    HI_CLIENT_WEBROOT_DIR,
    HI_CLIENT_LONG_HDR,
    HI_CLIENT_MAX_HEADERS,
    HI_CLIENT_MULTIPLE_CONTLEN,
    HI_CLIENT_CHUNK_SIZE_MISMATCH,
    HI_CLIENT_INVALID_TRUEIP,
    HI_CLIENT_MULTIPLE_HOST_HDRS,
    HI_CLIENT_LONG_HOSTNAME,
    HI_CLIENT_EXCEEDS_SPACES,
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

// Server Events
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
    HI_SERVER_SWF_ZLIB_FAILURE,
    HI_SERVER_SWF_LZMA_FAILURE,
    HI_SERVER_PDF_DEFL_FAILURE,
    HI_SERVER_PDF_UNSUP_COMP_TYPE,
    HI_SERVER_PDF_CASC_COMP,
    HI_SERVER_PDF_PARSE_FAILURE,
    HI_SERVER_EVENT_NUM
} HI_EVENTS;

// Client alert text for each event
#define HI_CLIENT_ASCII_STR                          \
    "ascii encoding"
#define HI_CLIENT_DOUBLE_DECODE_STR                  \
    "double decoding attack"
#define HI_CLIENT_U_ENCODE_STR                       \
    "u encoding"
#define HI_CLIENT_BARE_BYTE_STR                      \
    "bare byte unicode encoding"
/* Base36 is deprecated - leave here so events keep the same number */
#define HI_CLIENT_BASE36_STR                         \
    "base36 encoding"
#define HI_CLIENT_UTF_8_STR                          \
    "UTF-8 encoding"
#define HI_CLIENT_IIS_UNICODE_STR                    \
    "IIS unicode codepoint encoding"
#define HI_CLIENT_MULTI_SLASH_STR                    \
    "multi_slash encoding"
#define HI_CLIENT_IIS_BACKSLASH_STR                  \
    "IIS backslash evasion"
#define HI_CLIENT_SELF_DIR_TRAV_STR                  \
    "self directory traversal"
#define HI_CLIENT_DIR_TRAV_STR                       \
    "directory traversal"
#define HI_CLIENT_APACHE_WS_STR                      \
    "apache whitespace (tab)"
#define HI_CLIENT_IIS_DELIMITER_STR                  \
    "non-RFC http delimiter"
#define HI_CLIENT_NON_RFC_CHAR_STR                   \
    "non-RFC defined char"
#define HI_CLIENT_OVERSIZE_DIR_STR                   \
    "oversize request-URI directory"
#define HI_CLIENT_LARGE_CHUNK_STR                    \
    "oversize chunk encoding"
#define HI_CLIENT_PROXY_USE_STR                      \
    "unauthorized proxy use detected"
#define HI_CLIENT_WEBROOT_DIR_STR                    \
    "webroot directory traversal"
#define HI_CLIENT_LONG_HDR_STR                       \
    "long header"
#define HI_CLIENT_MAX_HEADERS_STR                    \
    "max header fields"
#define HI_CLIENT_MULTIPLE_CONTLEN_STR               \
    "multiple content length"
#define HI_CLIENT_CHUNK_SIZE_MISMATCH_STR            \
    "chunk size mismatch detected"
#define HI_CLIENT_MULTIPLE_HOST_HDRS_STR             \
    "multiple host hdrs detected"
#define HI_CLIENT_INVALID_TRUEIP_STR                 \
    "invalid ip in true-client-IP/XFF header"
#define HI_CLIENT_LONG_HOSTNAME_STR                  \
    "hostname exceeds 255 characters"
#define HI_CLIENT_EXCEEDS_SPACES_STR                 \
    "header parsing space saturation"
#define HI_CLIENT_CONSECUTIVE_SMALL_CHUNKS_STR       \
    "client consecutive small chunk sizes"
#define HI_CLIENT_UNBOUNDED_POST_STR                 \
    "post w/o content-length or chunks"
#define HI_CLIENT_MULTIPLE_TRUEIP_IN_SESSION_STR     \
    "multiple true IPs in a session"
#define HI_CLIENT_BOTH_TRUEIP_XFF_HDRS_STR           \
    "both true-client-IP and XFF hdrs present"
#define HI_CLIENT_UNKNOWN_METHOD_STR                 \
    "unknown method"
#define HI_CLIENT_SIMPLE_REQUEST_STR                 \
    "simple request"
#define HI_CLIENT_UNESCAPED_SPACE_URI_STR            \
    "unescaped space in http URI"
#define HI_CLIENT_PIPELINE_MAX_STR                   \
    "too many pipelined requests"

// Server alert text for each event
#define HI_ANOM_SERVER_STR                           \
    "anomalous http server on undefined HTTP port"
#define HI_SERVER_INVALID_STATCODE_STR               \
    "invalid status code in HTTP response"
#define HI_SERVER_NO_CONTLEN_STR                     \
    "no content-length or transfer-encoding in HTTP response"
#define HI_SERVER_UTF_NORM_FAIL_STR                  \
    "HTTP response has UTF charset which failed to normalize"
#define HI_SERVER_UTF7_STR                           \
    "HTTP response has UTF-7 charset"
#define HI_SERVER_DECOMPR_FAILED_STR                 \
    "HTTP response gzip decompression failed"
#define HI_SERVER_CONSECUTIVE_SMALL_CHUNKS_STR       \
    "server consecutive small chunk sizes"
#define HI_CLISRV_MSG_SIZE_EXCEPTION_STR             \
    "invalid content-length or chunk size"
#define HI_SERVER_JS_OBFUSCATION_EXCD_STR            \
    "javascript obfuscation levels exceeds 1"
#define HI_SERVER_JS_EXCESS_WS_STR                   \
    "javascript whitespaces exceeds max allowed"
#define HI_SERVER_MIXED_ENCODINGS_STR                \
    "multiple encodings within javascript obfuscated data"
#define HI_SERVER_SWF_ZLIB_FAILURE_STR               \
    "HTTP response SWF file zlib decompression failure"
#define HI_SERVER_SWF_LZMA_FAILURE_STR               \
    "HTTP response SWF file LZMA decompression failure"
#define HI_SERVER_PDF_DEFL_FAILURE_STR               \
    "HTTP response PDF file deflate decompression failure"
#define HI_SERVER_PDF_UNSUP_COMP_TYPE_STR            \
    "HTTP response PDF file unsupported compression type"
#define HI_SERVER_PDF_CASC_COMP_STR                  \
    "HTTP response PDF file cascaded compression"
#define HI_SERVER_PDF_PARSE_FAILURE_STR              \
    "HTTP response PDF file parse failure"

void hi_set_event(unsigned gid, unsigned sid);
void hi_clear_events();
void hi_queue_events();

#endif

