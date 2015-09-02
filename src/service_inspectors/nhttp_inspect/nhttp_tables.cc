//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_tables.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>

#include "framework/module.h"

#include "nhttp_enum.h"
#include "nhttp_str_to_code.h"
#include "nhttp_normalizers.h"
#include "nhttp_head_norm.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_header.h"
#include "nhttp_module.h"
#include "nhttp_uri_norm.h"
#include "nhttp_cutter.h"

using namespace NHttpEnums;

const StrCode NHttpMsgRequest::method_list[] =
{
    { METH_OPTIONS,            "OPTIONS" },
    { METH_GET,                "GET" },
    { METH_HEAD,               "HEAD" },
    { METH_POST,               "POST" },
    { METH_PUT,                "PUT" },
    { METH_DELETE,             "DELETE" },
    { METH_TRACE,              "TRACE" },
    { METH_CONNECT,            "CONNECT" },
    { METH_PROPFIND,           "PROPFIND" },
    { METH_PROPPATCH,          "PROPPATCH" },
    { METH_MKCOL,              "MKCOL" },
    { METH_COPY,               "COPY" },
    { METH_MOVE,               "MOVE" },
    { METH_LOCK,               "LOCK" },
    { METH_UNLOCK,             "UNLOCK" },
    { METH_VERSION_CONTROL,    "VERSION-CONTROL" },
    { METH_REPORT,             "REPORT" },
    { METH_CHECKOUT,           "CHECKOUT" },
    { METH_CHECKIN,            "CHECKIN" },
    { METH_UNCHECKOUT,         "UNCHECKOUT" },
    { METH_MKWORKSPACE,        "MKWORKSPACE" },
    { METH_UPDATE,             "UPDATE" },
    { METH_LABEL,              "LABEL" },
    { METH_MERGE,              "MERGE" },
    { METH_BASELINE_CONTROL,   "BASELINE-CONTROL" },
    { METH_MKACTIVITY,         "MKACTIVITY" },
    { METH_ORDERPATCH,         "ORDERPATCH" },
    { METH_ACL,                "ACL" },
    { METH_PATCH,              "PATCH" },
    { METH_SEARCH,             "SEARCH" },
    { METH_BCOPY,              "BCOPY" },
    { METH_BDELETE,            "BDELETE" },
    { METH_BMOVE,              "BMOVE" },
    { METH_BPROPFIND,          "BPROPFIND" },
    { METH_BPROPPATCH,         "BPROPPATCH" },
    { METH_NOTIFY,             "NOTIFY" },
    { METH_POLL,               "POLL" },
    { METH_SUBSCRIBE,          "SUBSCRIBE" },
    { METH_UNSUBSCRIBE,        "UNSUBSCRIBE" },
    { METH_X_MS_ENUMATTS,      "X-MS-ENUMATTS" },
    { METH_BIND,               "BIND" },
    { METH_LINK,               "LINK" },
    { METH_MKCALENDAR,         "MKCALENDAR" },
    { METH_MKREDIRECTREF,      "MKREDIRECTREF" },
    { METH_REBIND,             "REBIND" },
    { METH_UNBIND,             "UNBIND" },
    { METH_UNLINK,             "UNLINK" },
    { METH_UPDATEREDIRECTREF,  "UPDATEREDIRECTREF" },
    { 0,                       nullptr }
};

const StrCode NHttpUri::scheme_list[] =
{
    { SCH_HTTP,                "http" },
    { SCH_HTTPS,               "https" },
    { SCH_FTP,                 "ftp" },
    { SCH_GOPHER,              "gopher" },
    { SCH_FILE,                "file" },
    { 0,                       nullptr }
};

const StrCode NHttpMsgHeadShared::header_list[] =
{
    { HEAD_CACHE_CONTROL,        "cache-control" },
    { HEAD_CONNECTION,           "connection" },
    { HEAD_DATE,                 "date" },
    { HEAD_PRAGMA,               "pragma" },
    { HEAD_TRAILER,              "trailer" },
    { HEAD_COOKIE,               "cookie" },
    { HEAD_SET_COOKIE,           "set-cookie" },
    { HEAD_TRANSFER_ENCODING,    "transfer-encoding" },
    { HEAD_UPGRADE,              "upgrade" },
    { HEAD_VIA,                  "via" },
    { HEAD_WARNING,              "warning" },
    { HEAD_ACCEPT,               "accept" },
    { HEAD_ACCEPT_CHARSET,       "accept-charset" },
    { HEAD_ACCEPT_ENCODING,      "accept-encoding" },
    { HEAD_ACCEPT_LANGUAGE,      "accept-language" },
    { HEAD_AUTHORIZATION,        "authorization" },
    { HEAD_EXPECT,               "expect" },
    { HEAD_FROM,                 "from" },
    { HEAD_HOST,                 "host" },
    { HEAD_IF_MATCH,             "if-match" },
    { HEAD_IF_MODIFIED_SINCE,    "if-modified-since" },
    { HEAD_IF_NONE_MATCH,        "if-none-match" },
    { HEAD_IF_RANGE,             "if-range" },
    { HEAD_IF_UNMODIFIED_SINCE,  "if-unmodified-since" },
    { HEAD_MAX_FORWARDS,         "max-forwards" },
    { HEAD_PROXY_AUTHORIZATION,  "proxy-authorization" },
    { HEAD_RANGE,                "range" },
    { HEAD_REFERER,              "referer" },
    { HEAD_TE,                   "te" },
    { HEAD_USER_AGENT,           "user-agent" },
    { HEAD_ACCEPT_RANGES,        "accept-ranges" },
    { HEAD_AGE,                  "age" },
    { HEAD_ETAG,                 "etag" },
    { HEAD_LOCATION,             "location" },
    { HEAD_PROXY_AUTHENTICATE,   "proxy-authenticate" },
    { HEAD_RETRY_AFTER,          "retry-after" },
    { HEAD_SERVER,               "server" },
    { HEAD_VARY,                 "vary" },
    { HEAD_WWW_AUTHENTICATE,     "www-authenticate" },
    { HEAD_ALLOW,                "allow" },
    { HEAD_CONTENT_ENCODING,     "content-encoding" },
    { HEAD_CONTENT_LANGUAGE,     "content-language" },
    { HEAD_CONTENT_LENGTH,       "content-length" },
    { HEAD_CONTENT_LOCATION,     "content-location" },
    { HEAD_CONTENT_MD5,          "content-md5" },
    { HEAD_CONTENT_RANGE,        "content-range" },
    { HEAD_CONTENT_TYPE,         "content-type" },
    { HEAD_EXPIRES,              "expires" },
    { HEAD_LAST_MODIFIED,        "last-modified" },
    { HEAD_X_FORWARDED_FOR,      "x-forwarded-for" },
    { HEAD_TRUE_CLIENT_IP,       "true-client-ip" },
    { 0,                         nullptr }
};

const StrCode NHttpMsgHeadShared::trans_code_list[] =
{
    { TRANSCODE_CHUNKED,         "chunked" },
    { TRANSCODE_IDENTITY,        "identity" },
    { TRANSCODE_GZIP,            "gzip" },
    { TRANSCODE_COMPRESS,        "compress" },
    { TRANSCODE_DEFLATE,         "deflate" },
    { 0,                         nullptr }
};

const HeaderNormalizer NHttpMsgHeadShared::NORMALIZER_NIL
{ NORM_NULL, false, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };

const HeaderNormalizer NHttpMsgHeadShared::NORMALIZER_BASIC
{ NORM_FIELD, false, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };

const HeaderNormalizer NHttpMsgHeadShared::NORMALIZER_CAT
{ NORM_FIELD, true, norm_remove_lws, nullptr, nullptr, nullptr, nullptr, nullptr };

const HeaderNormalizer NHttpMsgHeadShared::NORMALIZER_COOKIE
{ NORM_FIELD, true, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };

const HeaderNormalizer NHttpMsgHeadShared::NORMALIZER_DECIMAL
{ NORM_INT64, false, norm_decimal_integer, nullptr, nullptr, nullptr, nullptr, nullptr };

const HeaderNormalizer NHttpMsgHeadShared::NORMALIZER_TRANSCODE
{ NORM_ENUM64, true, norm_remove_lws, nullptr, norm_to_lower, nullptr, norm_seq_str_code,
  NHttpMsgHeadShared::trans_code_list };

#if defined(__clang__)
// Designated initializers are not supported in C++11. However we're going to play compilation
// roulette and hopes this works.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
#endif

/* *INDENT-OFF* */
const HeaderNormalizer* const NHttpMsgHeadShared::header_norms[HEAD__MAX_VALUE] = { [0] = &NORMALIZER_NIL,
    [HEAD__OTHER] = &NORMALIZER_BASIC,
    [HEAD_CACHE_CONTROL] = &NORMALIZER_BASIC,
    [HEAD_CONNECTION] = &NORMALIZER_BASIC,
    [HEAD_DATE] = &NORMALIZER_BASIC,
    [HEAD_PRAGMA] = &NORMALIZER_BASIC,
    [HEAD_TRAILER] = &NORMALIZER_BASIC,
    [HEAD_COOKIE] = &NORMALIZER_COOKIE,
    [HEAD_SET_COOKIE] = &NORMALIZER_COOKIE,
    [HEAD_TRANSFER_ENCODING] = &NORMALIZER_TRANSCODE,
    [HEAD_UPGRADE] = &NORMALIZER_BASIC,
    [HEAD_VIA] = &NORMALIZER_BASIC,
    [HEAD_WARNING] = &NORMALIZER_BASIC,
    [HEAD_ACCEPT] = &NORMALIZER_BASIC,
    [HEAD_ACCEPT_CHARSET] = &NORMALIZER_BASIC,
    [HEAD_ACCEPT_ENCODING] = &NORMALIZER_CAT,
    [HEAD_ACCEPT_LANGUAGE] = &NORMALIZER_CAT,
    [HEAD_AUTHORIZATION] = &NORMALIZER_BASIC,
    [HEAD_EXPECT] = &NORMALIZER_BASIC,
    [HEAD_FROM] = &NORMALIZER_BASIC,
    [HEAD_HOST] = &NORMALIZER_BASIC,
    [HEAD_IF_MATCH] = &NORMALIZER_BASIC,
    [HEAD_IF_MODIFIED_SINCE] = &NORMALIZER_BASIC,
    [HEAD_IF_NONE_MATCH] = &NORMALIZER_BASIC,
    [HEAD_IF_RANGE] = &NORMALIZER_BASIC,
    [HEAD_IF_UNMODIFIED_SINCE] = &NORMALIZER_BASIC,
    [HEAD_MAX_FORWARDS] = &NORMALIZER_BASIC,
    [HEAD_PROXY_AUTHORIZATION] = &NORMALIZER_BASIC,
    [HEAD_RANGE] = &NORMALIZER_BASIC,
    [HEAD_REFERER] = &NORMALIZER_BASIC,
    [HEAD_TE] = &NORMALIZER_BASIC,
    [HEAD_USER_AGENT] = &NORMALIZER_BASIC,
    [HEAD_ACCEPT_RANGES] = &NORMALIZER_BASIC,
    [HEAD_AGE] = &NORMALIZER_BASIC,
    [HEAD_ETAG] = &NORMALIZER_BASIC,
    [HEAD_LOCATION] = &NORMALIZER_BASIC,
    [HEAD_PROXY_AUTHENTICATE] = &NORMALIZER_BASIC,
    [HEAD_RETRY_AFTER] = &NORMALIZER_BASIC,
    [HEAD_SERVER] = &NORMALIZER_BASIC,
    [HEAD_VARY] = &NORMALIZER_BASIC,
    [HEAD_WWW_AUTHENTICATE] = &NORMALIZER_BASIC,
    [HEAD_ALLOW] = &NORMALIZER_BASIC,
    [HEAD_CONTENT_ENCODING] = &NORMALIZER_BASIC,
    [HEAD_CONTENT_LANGUAGE] = &NORMALIZER_BASIC,
    [HEAD_CONTENT_LENGTH] = &NORMALIZER_DECIMAL,
    [HEAD_CONTENT_LOCATION] = &NORMALIZER_BASIC,
    [HEAD_CONTENT_MD5] = &NORMALIZER_BASIC,
    [HEAD_CONTENT_RANGE] = &NORMALIZER_BASIC,
    [HEAD_CONTENT_TYPE] = &NORMALIZER_BASIC,
    [HEAD_EXPIRES] = &NORMALIZER_BASIC,
    [HEAD_LAST_MODIFIED] = &NORMALIZER_BASIC,
    [HEAD_X_FORWARDED_FOR] = &NORMALIZER_CAT,
    [HEAD_TRUE_CLIENT_IP] = &NORMALIZER_BASIC
};
/* *INDENT-ON* */

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

const RuleMap NHttpModule::nhttp_events[] =
{
    { EVENT_ASCII,                      "ascii encoding" },
    { EVENT_DOUBLE_DECODE,              "double decoding attack" },
    { EVENT_U_ENCODE,                   "u encoding" },
    { EVENT_BARE_BYTE,                  "bare byte unicode encoding" },
    { EVENT_OBSOLETE_1,                 "obsolete event--should not appear" },
    { EVENT_UTF_8,                      "UTF-8 encoding" },
    { EVENT_IIS_UNICODE,                "IIS unicode codepoint encoding" },
    { EVENT_MULTI_SLASH,                "multi_slash encoding" },
    { EVENT_IIS_BACKSLASH,              "IIS backslash evasion" },
    { EVENT_SELF_DIR_TRAV,              "self directory traversal" },
    { EVENT_DIR_TRAV,                   "directory traversal" },
    { EVENT_APACHE_WS,                  "apache whitespace (tab)" },
    { EVENT_IIS_DELIMITER,              "non-RFC http delimiter" },
    { EVENT_NON_RFC_CHAR,               "non-RFC defined char" },
    { EVENT_OVERSIZE_DIR,               "oversize request-uri directory" },
    { EVENT_LARGE_CHUNK,                "oversize chunk encoding" },
    { EVENT_PROXY_USE,                  "unauthorized proxy use detected" },
    { EVENT_WEBROOT_DIR,                "webroot directory traversal" },
    { EVENT_LONG_HDR,                   "long header" },
    { EVENT_MAX_HEADERS,                "max header fields" },
    { EVENT_MULTIPLE_CONTLEN,           "multiple content length" },
    { EVENT_CHUNK_SIZE_MISMATCH,        "chunk size mismatch detected" },
    { EVENT_INVALID_TRUEIP,             "invalid IP in true-client-IP/XFF header" },
    { EVENT_MULTIPLE_HOST_HDRS,         "multiple host hdrs detected" },
    { EVENT_LONG_HOSTNAME,              "hostname exceeds 255 characters" },
    { EVENT_EXCEEDS_SPACES,             "header parsing space saturation" },
    { EVENT_CONSECUTIVE_SMALL_CHUNKS,   "client consecutive small chunk sizes" },
    { EVENT_UNBOUNDED_POST,             "post w/o content-length or chunks" },
    { EVENT_MULTIPLE_TRUEIP_IN_SESSION, "multiple true ips in a session" },
    { EVENT_BOTH_TRUEIP_XFF_HDRS,       "both true-client-IP and XFF hdrs present" },
    { EVENT_UNKNOWN_METHOD,             "unknown method" },
    { EVENT_SIMPLE_REQUEST,             "simple request" },
    { EVENT_UNESCAPED_SPACE_URI,        "unescaped space in HTTP URI" },
    { EVENT_PIPELINE_MAX,               "too many pipelined requests" },
    { EVENT_ANOM_SERVER,                "anomalous http server on undefined HTTP port" },
    { EVENT_INVALID_STATCODE,           "invalid status code in HTTP response" },
    { EVENT_NO_CONTLEN,                 "no content-length or transfer-encoding in HTTP response" },
    { EVENT_UTF_NORM_FAIL,              "HTTP response has UTF charset which failed to normalize" },
    { EVENT_UTF7,                       "HTTP response has UTF-7 charset" },
    { EVENT_DECOMPR_FAILED,             "HTTP response gzip decompression failed" },
    { EVENT_CONSECUTIVE_SMALL_CHUNKS_S, "server consecutive small chunk sizes" },
    { EVENT_MSG_SIZE_EXCEPTION,         "invalid content-length or chunk size" },
    { EVENT_JS_OBFUSCATION_EXCD,        "javascript obfuscation levels exceeds 1" },
    { EVENT_JS_EXCESS_WS,               "javascript whitespaces exceeds max allowed" },
    { EVENT_MIXED_ENCODINGS,            "multiple encodings within javascript obfuscated data" },
    { EVENT_SWF_ZLIB_FAILURE,           "SWF file zlib decompression failure" },
    { EVENT_SWF_LZMA_FAILURE,           "SWF file LZMA decompression failure" },
    { EVENT_PDF_DEFL_FAILURE,           "PDF file deflate decompression failure" },
    { EVENT_PDF_UNSUP_COMP_TYPE,        "PDF file unsupported compression type" },
    { EVENT_PDF_CASC_COMP,              "PDF file cascaded compression" },
    { EVENT_PDF_PARSE_FAILURE,          "PDF file parse failure" },
    { EVENT_LOSS_OF_SYNC,               "HTTP misformatted or not really HTTP" },
    { EVENT_CHUNK_ZEROS,                "Chunk length has excessive leading zeros" },
    { EVENT_WS_BETWEEN_MSGS,            "White space before or between messages" },
    { EVENT_URI_MISSING,                "Request message without URI" },
    { EVENT_CTRL_IN_REASON,             "Control character in reason phrase" },
    { EVENT_IMPROPER_WS,                "Illegal extra whitespace in start line" },
    { EVENT_BAD_VERS,                   "Corrupted HTTP version" },
    { EVENT_UNKNOWN_VERS,               "Unknown HTTP version" },
    { EVENT_BAD_HEADER,                 "Format error in HTTP header" },
    { EVENT_CHUNK_OPTIONS,              "Chunk header options present" },
    { EVENT_URI_BAD_FORMAT,             "URI badly formatted" },
    { EVENT_URI_BAD_PORT,               "URI bad port number" },
    { EVENT_BROKEN_CHUNK,               "HTTP chunk misformatted" },
    { EVENT_CHUNK_WHITESPACE,           "White space following chunk length" },
    { 0, nullptr }
};

const int8_t NHttpEnums::as_hex[256] =
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,

    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,

    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,

    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,

    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,

    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,

    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,

    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

const bool NHttpEnums::token_char[256] =
{
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false,  true, false,  true,  true,  true,  true,  true, false, false,  true,  true, false,  true,  true, false,
     true,  true,  true,  true,  true,  true,  true,  true,  true,  true, false, false, false, false, false, false,

    false,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
     true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true, false, false, false,  true,  true,

     true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
     true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true, false,  true, false,  true, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false
};

const bool NHttpEnums::is_sp_tab[256] =
{
    false, false, false, false, false, false, false, false, false,  true, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

     true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false
};

