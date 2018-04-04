//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// http_tables.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_header.h"
#include "http_msg_request.h"

using namespace HttpEnums;

const StrCode HttpMsgRequest::method_list[] =
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

const StrCode HttpMsgHeadShared::header_list[] =
{
    { HEAD_CACHE_CONTROL,             "cache-control" },
    { HEAD_CONNECTION,                "connection" },
    { HEAD_DATE,                      "date" },
    { HEAD_PRAGMA,                    "pragma" },
    { HEAD_TRAILER,                   "trailer" },
    { HEAD_COOKIE,                    "cookie" },
    { HEAD_SET_COOKIE,                "set-cookie" },
    { HEAD_TRANSFER_ENCODING,         "transfer-encoding" },
    { HEAD_UPGRADE,                   "upgrade" },
    { HEAD_VIA,                       "via" },
    { HEAD_WARNING,                   "warning" },
    { HEAD_ACCEPT,                    "accept" },
    { HEAD_ACCEPT_CHARSET,            "accept-charset" },
    { HEAD_ACCEPT_ENCODING,           "accept-encoding" },
    { HEAD_ACCEPT_LANGUAGE,           "accept-language" },
    { HEAD_AUTHORIZATION,             "authorization" },
    { HEAD_EXPECT,                    "expect" },
    { HEAD_FROM,                      "from" },
    { HEAD_HOST,                      "host" },
    { HEAD_IF_MATCH,                  "if-match" },
    { HEAD_IF_MODIFIED_SINCE,         "if-modified-since" },
    { HEAD_IF_NONE_MATCH,             "if-none-match" },
    { HEAD_IF_RANGE,                  "if-range" },
    { HEAD_IF_UNMODIFIED_SINCE,       "if-unmodified-since" },
    { HEAD_MAX_FORWARDS,              "max-forwards" },
    { HEAD_PROXY_AUTHORIZATION,       "proxy-authorization" },
    { HEAD_RANGE,                     "range" },
    { HEAD_REFERER,                   "referer" },
    { HEAD_TE,                        "te" },
    { HEAD_USER_AGENT,                "user-agent" },
    { HEAD_ACCEPT_RANGES,             "accept-ranges" },
    { HEAD_AGE,                       "age" },
    { HEAD_ETAG,                      "etag" },
    { HEAD_LOCATION,                  "location" },
    { HEAD_PROXY_AUTHENTICATE,        "proxy-authenticate" },
    { HEAD_RETRY_AFTER,               "retry-after" },
    { HEAD_SERVER,                    "server" },
    { HEAD_VARY,                      "vary" },
    { HEAD_WWW_AUTHENTICATE,          "www-authenticate" },
    { HEAD_ALLOW,                     "allow" },
    { HEAD_CONTENT_ENCODING,          "content-encoding" },
    { HEAD_CONTENT_LANGUAGE,          "content-language" },
    { HEAD_CONTENT_LENGTH,            "content-length" },
    { HEAD_CONTENT_LOCATION,          "content-location" },
    { HEAD_CONTENT_MD5,               "content-md5" },
    { HEAD_CONTENT_RANGE,             "content-range" },
    { HEAD_CONTENT_TYPE,              "content-type" },
    { HEAD_EXPIRES,                   "expires" },
    { HEAD_LAST_MODIFIED,             "last-modified" },
    { HEAD_X_FORWARDED_FOR,           "x-forwarded-for" },
    { HEAD_TRUE_CLIENT_IP,            "true-client-ip" },
    { HEAD_X_WORKING_WITH,            "x-working-with" },
    { HEAD_CONTENT_TRANSFER_ENCODING, "content-transfer-encoding" },
    { HEAD_MIME_VERSION,              "mime-version" },
    { HEAD_PROXY_AGENT,               "proxy-agent" },
    { 0,                              nullptr }
};

const StrCode HttpMsgHeadShared::content_code_list[] =
{
    { CONTENTCODE_GZIP,          "gzip" },
    { CONTENTCODE_DEFLATE,       "deflate" },
    { CONTENTCODE_COMPRESS,      "compress" },
    { CONTENTCODE_EXI,           "exi" },
    { CONTENTCODE_PACK200_GZIP,  "pack200-gzip" },
    { CONTENTCODE_X_GZIP,        "x-gzip" },
    { CONTENTCODE_X_COMPRESS,    "x-compress" },
    { CONTENTCODE_IDENTITY,      "identity" },
    { CONTENTCODE_CHUNKED,       "chunked" },
    { CONTENTCODE_BR,            "br" },
    { CONTENTCODE_BZIP2,         "bzip2" },
    { CONTENTCODE_LZMA,          "lzma" },
    { CONTENTCODE_PEERDIST,      "peerdist" },
    { CONTENTCODE_SDCH,          "sdch" },
    { CONTENTCODE_XPRESS,        "xpress" },
    { CONTENTCODE_XZ,            "xz" },
    { 0,                         nullptr }
};

const StrCode HttpMsgHeadShared::charset_code_list[] =
{
    { CHARSET_DEFAULT,       "charset=utf-8" },
    { CHARSET_UTF7,          "charset=utf-7" },
    { CHARSET_UTF16LE,       "charset=utf-16le" },
    { CHARSET_UTF16BE,       "charset=utf-16be" },
    { CHARSET_UTF32LE,       "charset=utf-32le" },
    { CHARSET_UTF32BE,       "charset=utf-32be" },
    { 0,                     nullptr }
};

const StrCode HttpMsgHeadShared::charset_code_opt_list[] =
{
    { CHARSET_UNKNOWN,       "charset=utf-" },
    { CHARSET_IRRELEVANT,    "charset=" },
    { 0,                     nullptr }
};

const HeaderNormalizer HttpMsgHeadShared::NORMALIZER_BASIC
    { EVENT__NONE, INF__NONE, false, nullptr, nullptr, nullptr };

const HeaderNormalizer HttpMsgHeadShared::NORMALIZER_NO_REPEAT
    { EVENT_REPEATED_HEADER, INF_REPEATED_HEADER, false, nullptr, nullptr, nullptr };

const HeaderNormalizer HttpMsgHeadShared::NORMALIZER_CASE_INSENSITIVE
    { EVENT__NONE, INF__NONE, false, norm_to_lower, nullptr, nullptr };

const HeaderNormalizer HttpMsgHeadShared::NORMALIZER_NUMBER
    { EVENT_REPEATED_HEADER, INF_REPEATED_HEADER, false, norm_remove_lws, nullptr, nullptr };

const HeaderNormalizer HttpMsgHeadShared::NORMALIZER_TOKEN_LIST
    { EVENT__NONE, INF__NONE, false, norm_remove_lws, norm_to_lower, nullptr };

const HeaderNormalizer HttpMsgHeadShared::NORMALIZER_METHOD_LIST
    { EVENT__NONE, INF__NONE, false, norm_remove_lws, nullptr, nullptr };

// FIXIT-L implement a date normalization function that converts the three legal formats into a
// single standard format. For now we do nothing special for dates. This object is a placeholder
// to keep track of which headers have date values.
const HeaderNormalizer HttpMsgHeadShared::NORMALIZER_DATE
    { EVENT__NONE, INF__NONE, false, nullptr, nullptr, nullptr };

// FIXIT-M implement a URI normalization function, probably by extending existing URI capabilities
// to cover relative formats
const HeaderNormalizer HttpMsgHeadShared::NORMALIZER_URI
    { EVENT__NONE, INF__NONE, false, nullptr, nullptr, nullptr };

const HeaderNormalizer HttpMsgHeadShared::NORMALIZER_CONTENT_LENGTH
    { EVENT_MULTIPLE_CONTLEN, INF_MULTIPLE_CONTLEN, true, norm_remove_lws, nullptr, nullptr };

const HeaderNormalizer HttpMsgHeadShared::NORMALIZER_CHARSET
    { EVENT__NONE, INF__NONE, false, norm_remove_quotes_lws, norm_to_lower, nullptr };

#if defined(__clang__)
// Designated initializers are not supported in C++11. However we're going to play compilation
// roulette and hopes this works.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
#endif

/* *INDENT-OFF* */
const HeaderNormalizer* const HttpMsgHeadShared::header_norms[HEAD__MAX_VALUE] = {
    [0] = &NORMALIZER_BASIC,
    [HEAD__OTHER] = &NORMALIZER_BASIC,
    [HEAD_CACHE_CONTROL] = &NORMALIZER_TOKEN_LIST,
    [HEAD_CONNECTION] = &NORMALIZER_TOKEN_LIST,
    [HEAD_DATE] = &NORMALIZER_DATE,
    [HEAD_PRAGMA] = &NORMALIZER_TOKEN_LIST,
    [HEAD_TRAILER] = &NORMALIZER_TOKEN_LIST,
    [HEAD_COOKIE] = &NORMALIZER_BASIC,
    [HEAD_SET_COOKIE] = &NORMALIZER_BASIC,
    [HEAD_TRANSFER_ENCODING] = &NORMALIZER_TOKEN_LIST,
    [HEAD_UPGRADE] = &NORMALIZER_BASIC,
    [HEAD_VIA] = &NORMALIZER_BASIC,
    [HEAD_WARNING] = &NORMALIZER_BASIC,
    [HEAD_ACCEPT] = &NORMALIZER_TOKEN_LIST,
    [HEAD_ACCEPT_CHARSET] = &NORMALIZER_TOKEN_LIST,
    [HEAD_ACCEPT_ENCODING] = &NORMALIZER_TOKEN_LIST,
    [HEAD_ACCEPT_LANGUAGE] = &NORMALIZER_TOKEN_LIST,
    [HEAD_AUTHORIZATION] = &NORMALIZER_BASIC,
    [HEAD_EXPECT] = &NORMALIZER_CASE_INSENSITIVE,
    [HEAD_FROM] = &NORMALIZER_BASIC,
    [HEAD_HOST] = &NORMALIZER_NO_REPEAT,
    [HEAD_IF_MATCH] = &NORMALIZER_BASIC,
    [HEAD_IF_MODIFIED_SINCE] = &NORMALIZER_DATE,
    [HEAD_IF_NONE_MATCH] = &NORMALIZER_BASIC,
    [HEAD_IF_RANGE] = &NORMALIZER_BASIC,
    [HEAD_IF_UNMODIFIED_SINCE] = &NORMALIZER_DATE,
    [HEAD_MAX_FORWARDS] = &NORMALIZER_BASIC,
    [HEAD_PROXY_AUTHORIZATION] = &NORMALIZER_BASIC,
    [HEAD_RANGE] = &NORMALIZER_BASIC,
    [HEAD_REFERER] = &NORMALIZER_URI,
    [HEAD_TE] = &NORMALIZER_TOKEN_LIST,
    [HEAD_USER_AGENT] = &NORMALIZER_BASIC,
    [HEAD_ACCEPT_RANGES] = &NORMALIZER_TOKEN_LIST,
    [HEAD_AGE] = &NORMALIZER_NUMBER,
    [HEAD_ETAG] = &NORMALIZER_BASIC,
    [HEAD_LOCATION] = &NORMALIZER_URI,
    [HEAD_PROXY_AUTHENTICATE] = &NORMALIZER_BASIC,
    [HEAD_RETRY_AFTER] = &NORMALIZER_BASIC,  // may be date or number
    [HEAD_SERVER] = &NORMALIZER_BASIC,
    [HEAD_VARY] = &NORMALIZER_TOKEN_LIST,
    [HEAD_WWW_AUTHENTICATE] = &NORMALIZER_BASIC,
    [HEAD_ALLOW] = &NORMALIZER_METHOD_LIST,
    [HEAD_CONTENT_ENCODING] = &NORMALIZER_TOKEN_LIST,
    [HEAD_CONTENT_LANGUAGE] = &NORMALIZER_TOKEN_LIST,
    [HEAD_CONTENT_LENGTH] = &NORMALIZER_CONTENT_LENGTH,
    [HEAD_CONTENT_LOCATION] = &NORMALIZER_URI,
    [HEAD_CONTENT_MD5] = &NORMALIZER_BASIC,
    [HEAD_CONTENT_RANGE] = &NORMALIZER_BASIC,
    [HEAD_CONTENT_TYPE] = &NORMALIZER_CHARSET,
    [HEAD_EXPIRES] = &NORMALIZER_DATE,
    [HEAD_LAST_MODIFIED] = &NORMALIZER_DATE,
    [HEAD_X_FORWARDED_FOR] = &NORMALIZER_BASIC,
    [HEAD_TRUE_CLIENT_IP] = &NORMALIZER_BASIC,
    [HEAD_X_WORKING_WITH] = &NORMALIZER_BASIC,
    [HEAD_CONTENT_TRANSFER_ENCODING] = &NORMALIZER_TOKEN_LIST,
    [HEAD_MIME_VERSION] = &NORMALIZER_BASIC,
    [HEAD_PROXY_AGENT] = &NORMALIZER_BASIC,
};
/* *INDENT-ON* */

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

const snort::RuleMap HttpModule::http_events[] =
{
    { EVENT_ASCII,                      "ascii encoding" },
    { EVENT_DOUBLE_DECODE,              "double decoding attack" },
    { EVENT_U_ENCODE,                   "u encoding" },
    { EVENT_BARE_BYTE,                  "bare byte unicode encoding" },
    { EVENT_OBSOLETE_BASE_36,           "obsolete event--deleted" },
    { EVENT_UTF_8,                      "UTF-8 encoding" },
    { EVENT_CODE_POINT_IN_URI,          "unicode map code point encoding in URI" },
    { EVENT_MULTI_SLASH,                "multi_slash encoding" },
    { EVENT_BACKSLASH_IN_URI,           "backslash used in URI path" },
    { EVENT_SELF_DIR_TRAV,              "self directory traversal" },
    { EVENT_DIR_TRAV,                   "directory traversal" },
    { EVENT_APACHE_WS,                  "apache whitespace (tab)" },
    { EVENT_LF_WITHOUT_CR,              "HTTP header line terminated by LF without a CR" },
    { EVENT_NON_RFC_CHAR,               "non-RFC defined char" },
    { EVENT_OVERSIZE_DIR,               "oversize request-uri directory" },
    { EVENT_LARGE_CHUNK,                "oversize chunk encoding" },
    { EVENT_PROXY_USE,                  "unauthorized proxy use detected" },
    { EVENT_WEBROOT_DIR,                "webroot directory traversal" },
    { EVENT_LONG_HDR,                   "long header" },
    { EVENT_MAX_HEADERS,                "max header fields" },
    { EVENT_MULTIPLE_CONTLEN,           "multiple content length" },
    { EVENT_OBSOLETE_CHUNK_SIZE_MISMATCH, "obsolete event--deleted" },
    { EVENT_INVALID_TRUEIP,             "invalid IP in true-client-IP/XFF header" },
    { EVENT_MULTIPLE_HOST_HDRS,         "multiple host hdrs detected" },
    { EVENT_LONG_HOSTNAME,              "hostname exceeds 255 characters" },
    { EVENT_EXCEEDS_SPACES,             "too much whitespace in header (not implemented yet)" },
    { EVENT_CONSECUTIVE_SMALL_CHUNKS,   "client consecutive small chunk sizes" },
    { EVENT_UNBOUNDED_POST,             "POST or PUT w/o content-length or chunks" },
    { EVENT_MULTIPLE_TRUEIP_IN_SESSION, "multiple true ips in a session" },
    { EVENT_BOTH_TRUEIP_XFF_HDRS,       "both true-client-IP and XFF hdrs present" },
    { EVENT_UNKNOWN_METHOD,             "unknown method" },
    { EVENT_SIMPLE_REQUEST,             "simple request" },
    { EVENT_UNESCAPED_SPACE_URI,        "unescaped space in HTTP URI" },
    { EVENT_PIPELINE_MAX,               "too many pipelined requests" },
    { EVENT_ANOM_SERVER,                "anomalous http server on undefined HTTP port" },
    { EVENT_INVALID_STATCODE,           "invalid status code in HTTP response" },
    { EVENT_UNUSED_1,                   "unused event number--should not appear" },
    { EVENT_UTF_NORM_FAIL,              "HTTP response has UTF charset that failed to normalize" },
    { EVENT_UTF7,                       "HTTP response has UTF-7 charset" },
    { EVENT_DECOMPR_FAILED,             "HTTP response gzip decompression failed" },
    { EVENT_CONSECUTIVE_SMALL_CHUNKS_S, "server consecutive small chunk sizes" },
    { EVENT_UNUSED_2,                   "unused event number--should not appear" },
    { EVENT_JS_OBFUSCATION_EXCD,        "javascript obfuscation levels exceeds 1" },
    { EVENT_JS_EXCESS_WS,               "javascript whitespaces exceeds max allowed" },
    { EVENT_MIXED_ENCODINGS,            "multiple encodings within javascript obfuscated data" },
    { EVENT_SWF_ZLIB_FAILURE,           "SWF file zlib decompression failure" },
    { EVENT_SWF_LZMA_FAILURE,           "SWF file LZMA decompression failure" },
    { EVENT_PDF_DEFL_FAILURE,           "PDF file deflate decompression failure" },
    { EVENT_PDF_UNSUP_COMP_TYPE,        "PDF file unsupported compression type" },
    { EVENT_PDF_CASC_COMP,              "PDF file cascaded compression" },
    { EVENT_PDF_PARSE_FAILURE,          "PDF file parse failure" },
    { EVENT_LOSS_OF_SYNC,               "not HTTP traffic" },
    { EVENT_CHUNK_ZEROS,                "chunk length has excessive leading zeros" },
    { EVENT_WS_BETWEEN_MSGS,            "white space before or between messages" },
    { EVENT_URI_MISSING,                "request message without URI" },
    { EVENT_CTRL_IN_REASON,             "control character in reason phrase" },
    { EVENT_IMPROPER_WS,                "illegal extra whitespace in start line" },
    { EVENT_BAD_VERS,                   "corrupted HTTP version" },
    { EVENT_UNKNOWN_VERS,               "unknown HTTP version" },
    { EVENT_BAD_HEADER,                 "format error in HTTP header" },
    { EVENT_CHUNK_OPTIONS,              "chunk header options present" },
    { EVENT_URI_BAD_FORMAT,             "URI badly formatted" },
    { EVENT_UNKNOWN_PERCENT,            "unrecognized type of percent encoding in URI" },
    { EVENT_BROKEN_CHUNK,               "HTTP chunk misformatted" },
    { EVENT_CHUNK_WHITESPACE,           "white space adjacent to chunk length" },
    { EVENT_HEAD_NAME_WHITESPACE,       "white space within header name" },
    { EVENT_GZIP_OVERRUN,               "excessive gzip compression" },
    { EVENT_GZIP_FAILURE,               "gzip decompression failed" },
    { EVENT_ZERO_NINE_CONTINUE,         "HTTP 0.9 requested followed by another request" },
    { EVENT_ZERO_NINE_NOT_FIRST,        "HTTP 0.9 request following a normal request" },
    { EVENT_BOTH_CL_AND_TE,             "message has both Content-Length and Transfer-Encoding" },
    { EVENT_BAD_CODE_BODY_HEADER,       "status code implying no body combined with Transfer-"
                                        "Encoding or nonzero Content-Length" },
    { EVENT_BAD_TE_HEADER,              "Transfer-Encoding not ending with chunked" },
    { EVENT_PADDED_TE_HEADER,           "Transfer-Encoding with encodings before chunked" },
    { EVENT_MISFORMATTED_HTTP,          "misformatted HTTP traffic" },
    { EVENT_UNSUPPORTED_ENCODING,       "unsupported Content-Encoding used" },
    { EVENT_UNKNOWN_ENCODING,           "unknown Content-Encoding used" },
    { EVENT_STACKED_ENCODINGS,          "multiple Content-Encodings applied" },
    { EVENT_RESPONSE_WO_REQUEST,        "server response before client request" },
    { EVENT_PDF_SWF_OVERRUN,            "PDF/SWF decompression of server response too big" },
    { EVENT_BAD_CHAR_IN_HEADER_NAME,    "nonprinting character in HTTP message header name" },
    { EVENT_BAD_CONTENT_LENGTH,         "bad Content-Length value in HTTP header" },
    { EVENT_HEADER_WRAPPING,            "HTTP header line wrapped" },
    { EVENT_CR_WITHOUT_LF,              "HTTP header line terminated by CR without a LF" },
    { EVENT_CHUNK_BAD_SEP,              "chunk terminated by nonstandard separator" },
    { EVENT_CHUNK_BARE_LF,              "chunk length terminated by LF without CR" },
    { EVENT_MULTIPLE_100_RESPONSES,     "more than one response with 100 status code" },
    { EVENT_UNEXPECTED_100_RESPONSE,    "100 status code not in response to Expect header" },
    { EVENT_UNKNOWN_1XX_STATUS,         "1XX status code other than 100 or 101" },
    { EVENT_EXPECT_WITHOUT_BODY,        "Expect header sent without a message body" },
    { EVENT_CHUNKED_ONE_POINT_ZERO,     "HTTP 1.0 message with Transfer-Encoding header" },
    { EVENT_CTE_HEADER,                 "Content-Transfer-Encoding used as HTTP header" },
    { EVENT_ILLEGAL_TRAILER,            "illegal field in chunked message trailers" },
    { EVENT_REPEATED_HEADER,            "header field inappropriately appears twice or has two "
                                        "values" },
    { EVENT_CONTENT_ENCODING_CHUNKED,   "invalid value chunked in Content-Encoding header" },
    { EVENT_206_WITHOUT_RANGE,          "206 response sent to a request without a Range header" },
    { EVENT_VERSION_NOT_UPPERCASE,      "'HTTP' in version field not all upper case" },
    { EVENT_BAD_HEADER_WHITESPACE,      "white space embedded in critical header value" },
    { EVENT_GZIP_EARLY_END,             "gzip compressed data followed by unexpected non-gzip "
                                        "data" },
    { 0, nullptr }
};

const PegInfo HttpModule::peg_names[PEG_COUNT_MAX+1] =
{
    { CountType::SUM, "flows", "HTTP connections inspected" },
    { CountType::SUM, "scans", "TCP segments scanned looking for HTTP messages" },
    { CountType::SUM, "reassembles", "TCP segments combined into HTTP messages" },
    { CountType::SUM, "inspections", "total message sections inspected" },
    { CountType::SUM, "requests", "HTTP request messages inspected" },
    { CountType::SUM, "responses", "HTTP response messages inspected" },
    { CountType::SUM, "get_requests", "GET requests inspected" },
    { CountType::SUM, "head_requests", "HEAD requests inspected" },
    { CountType::SUM, "post_requests", "POST requests inspected" },
    { CountType::SUM, "put_requests", "PUT requests inspected" },
    { CountType::SUM, "delete_requests", "DELETE requests inspected" },
    { CountType::SUM, "connect_requests", "CONNECT requests inspected" },
    { CountType::SUM, "options_requests", "OPTIONS requests inspected" },
    { CountType::SUM, "trace_requests", "TRACE requests inspected" },
    { CountType::SUM, "other_requests", "other request methods inspected" },
    { CountType::SUM, "request_bodies", "POST, PUT, and other requests with message bodies" },
    { CountType::SUM, "chunked", "chunked message bodies" },
    { CountType::SUM, "uri_normalizations", "URIs needing to be normalization" },
    { CountType::SUM, "uri_path", "URIs with path problems" },
    { CountType::SUM, "uri_coding", "URIs with character coding problems" },
    { CountType::NOW, "concurrent_sessions", "total concurrent http sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent http sessions" },
    { CountType::END, nullptr, nullptr }
};

const int8_t HttpEnums::as_hex[256] =
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

const bool HttpEnums::token_char[256] =
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

const bool HttpEnums::is_sp_tab[256] =
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

const bool HttpEnums::is_cr_lf[256] =
{
    false, false, false, false, false, false, false, false, false, false,  true, false, false,  true, false, false,
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
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false
};

const bool HttpEnums::is_sp_tab_lf[256] =
{
    false, false, false, false, false, false, false, false, false,  true,  true, false, false, false, false, false,
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

const bool HttpEnums::is_sp_tab_cr_lf[256] =
{
    false, false, false, false, false, false, false, false, false,  true,  true, false, false,  true, false, false,
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

const bool HttpEnums::is_sp_tab_cr_lf_vt_ff[256] =
{
    false, false, false, false, false, false, false, false, false,  true,  true,  true,  true,  true, false, false,
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

const bool HttpEnums::is_sp_tab_quote_dquote[256] =
{
    false, false, false, false, false, false, false, false, false,  true, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

     true, false,  true, false, false, false, false,  true, false, false, false, false, false, false, false, false,
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

const bool HttpEnums::is_sp_comma[256] =
{
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

     true, false, false, false, false, false, false, false, false, false, false, false,  true, false, false, false,
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

const bool HttpEnums::is_print_char[256] =
{
    false, false, false, false, false, false, false, false, false,  true,  true, false, false,  true, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

     true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
     true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,

     true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
     true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,

     true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
     true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false
};

