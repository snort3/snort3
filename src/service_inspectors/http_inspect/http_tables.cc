//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "http_enum.h"
#include "http_msg_header.h"
#include "http_msg_request.h"

using namespace HttpEnums;
using namespace snort;

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
    { HEAD_CACHE_CONTROL,              "cache-control" },
    { HEAD_CONNECTION,                 "connection" },
    { HEAD_DATE,                       "date" },
    { HEAD_PRAGMA,                     "pragma" },
    { HEAD_TRAILER,                    "trailer" },
    { HEAD_COOKIE,                     "cookie" },
    { HEAD_SET_COOKIE,                 "set-cookie" },
    { HEAD_TRANSFER_ENCODING,          "transfer-encoding" },
    { HEAD_UPGRADE,                    "upgrade" },
    { HEAD_VIA,                        "via" },
    { HEAD_WARNING,                    "warning" },
    { HEAD_ACCEPT,                     "accept" },
    { HEAD_ACCEPT_CHARSET,             "accept-charset" },
    { HEAD_ACCEPT_ENCODING,            "accept-encoding" },
    { HEAD_ACCEPT_LANGUAGE,            "accept-language" },
    { HEAD_AUTHORIZATION,              "authorization" },
    { HEAD_EXPECT,                     "expect" },
    { HEAD_FROM,                       "from" },
    { HEAD_HOST,                       "host" },
    { HEAD_IF_MATCH,                   "if-match" },
    { HEAD_IF_MODIFIED_SINCE,          "if-modified-since" },
    { HEAD_IF_NONE_MATCH,              "if-none-match" },
    { HEAD_IF_RANGE,                   "if-range" },
    { HEAD_IF_UNMODIFIED_SINCE,        "if-unmodified-since" },
    { HEAD_MAX_FORWARDS,               "max-forwards" },
    { HEAD_PROXY_AUTHORIZATION,        "proxy-authorization" },
    { HEAD_RANGE,                      "range" },
    { HEAD_REFERER,                    "referer" },
    { HEAD_TE,                         "te" },
    { HEAD_USER_AGENT,                 "user-agent" },
    { HEAD_ACCEPT_RANGES,              "accept-ranges" },
    { HEAD_AGE,                        "age" },
    { HEAD_ETAG,                       "etag" },
    { HEAD_LOCATION,                   "location" },
    { HEAD_PROXY_AUTHENTICATE,         "proxy-authenticate" },
    { HEAD_RETRY_AFTER,                "retry-after" },
    { HEAD_SERVER,                     "server" },
    { HEAD_VARY,                       "vary" },
    { HEAD_WWW_AUTHENTICATE,           "www-authenticate" },
    { HEAD_ALLOW,                      "allow" },
    { HEAD_CONTENT_ENCODING,           "content-encoding" },
    { HEAD_CONTENT_LANGUAGE,           "content-language" },
    { HEAD_CONTENT_LENGTH,             "content-length" },
    { HEAD_CONTENT_LOCATION,           "content-location" },
    { HEAD_CONTENT_MD5,                "content-md5" },
    { HEAD_CONTENT_RANGE,              "content-range" },
    { HEAD_CONTENT_TYPE,               "content-type" },
    { HEAD_EXPIRES,                    "expires" },
    { HEAD_LAST_MODIFIED,              "last-modified" },
    { HEAD_X_FORWARDED_FOR,            "x-forwarded-for" },
    { HEAD_TRUE_CLIENT_IP,             "true-client-ip" },
    { HEAD_X_WORKING_WITH,             "x-working-with" },
    { HEAD_CONTENT_TRANSFER_ENCODING,  "content-transfer-encoding" },
    { HEAD_MIME_VERSION,               "mime-version" },
    { HEAD_PROXY_AGENT,                "proxy-agent" },
    { HEAD_CONTENT_DISPOSITION,        "content-disposition" },
    { HEAD_HTTP2_SETTINGS,             "http2-settings" },
    { HEAD_RESTRICT_ACCESS_TO_TENANTS, "restrict-access-to-tenants" },
    { HEAD_RESTRICT_ACCESS_CONTEXT,    "restrict-access-context" },
    { 0,                               nullptr }
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

const StrCode HttpMsgHeadShared::content_type_list[] =
{
    { CT_APPLICATION_PDF,          "application/pdf" },
    { CT_APPLICATION_OCTET_STREAM, "application/octet-stream" },
    { CT_APPLICATION_JAVASCRIPT,   "application/javascript" },
    { CT_APPLICATION_ECMASCRIPT,   "application/ecmascript" },
    { CT_APPLICATION_X_JAVASCRIPT, "application/x-javascript" },
    { CT_APPLICATION_X_ECMASCRIPT, "application/x-ecmascript" },
    { CT_APPLICATION_XHTML_XML,    "application/xhtml+xml" },
    { CT_TEXT_JAVASCRIPT,          "text/javascript" },
    { CT_TEXT_JAVASCRIPT_1_0,      "text/javascript1.0" },
    { CT_TEXT_JAVASCRIPT_1_1,      "text/javascript1.1" },
    { CT_TEXT_JAVASCRIPT_1_2,      "text/javascript1.2" },
    { CT_TEXT_JAVASCRIPT_1_3,      "text/javascript1.3" },
    { CT_TEXT_JAVASCRIPT_1_4,      "text/javascript1.4" },
    { CT_TEXT_JAVASCRIPT_1_5,      "text/javascript1.5" },
    { CT_TEXT_ECMASCRIPT,          "text/ecmascript" },
    { CT_TEXT_X_JAVASCRIPT,        "text/x-javascript" },
    { CT_TEXT_X_ECMASCRIPT,        "text/x-ecmascript" },
    { CT_TEXT_JSCRIPT,             "text/jscript" },
    { CT_TEXT_LIVESCRIPT,          "text/livescript" },
    { CT_TEXT_HTML,                "text/html" },
    { 0,                           nullptr }
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

const StrCode HttpMsgHeadShared::upgrade_list[] =
{
    { UP_H2C,                "h2c" },
    { UP_H2,                 "h2" },
    { UP_HTTP20,             "http/2.0" },
    { 0,                     nullptr }
};

const StrCode HttpMsgHeadShared::transfer_encoding_list[] =
{
    { TE_CHUNKED,            "chunked" },
    { TE_IDENTITY,           "identity" },
    { 0,                     nullptr }
};

const RuleMap HttpModule::http_events[] =
{
    { EVENT_ASCII,                      "URI has percent-encoding of an unreserved character" },
    { EVENT_DOUBLE_DECODE,              "URI contains double-encoded hexadecimal characters" },
    { EVENT_U_ENCODE,                   "URI has non-standard %u-style Unicode encoding" },
    { EVENT_BARE_BYTE,                  "URI has Unicode encodings containing bytes that were not percent-encoded" },
    { EVENT_UTF_8,                      "URI has two-byte or three-byte UTF-8 encoding" },
    { EVENT_CODE_POINT_IN_URI,          "URI has unicode map code point encoding" },
    { EVENT_MULTI_SLASH,                "URI path contains consecutive slash characters" },
    { EVENT_BACKSLASH_IN_URI,           "backslash character appears in the path portion of a URI" },
    { EVENT_SELF_DIR_TRAV,              "URI path contains /./ pattern repeating the current directory" },
    { EVENT_DIR_TRAV,                   "URI path contains /../ pattern moving up a directory" },
    { EVENT_APACHE_WS,                  "Tab character in HTTP start line" },
    { EVENT_LF_WITHOUT_CR,              "HTTP start line or header line terminated by LF without a CR" },
    { EVENT_NON_RFC_CHAR,               "Normalized URI includes character from bad_characters list" },
    { EVENT_OVERSIZE_DIR,               "URI path contains a segment that is longer than the "
                                        "oversize_dir_length parameter" },
    { EVENT_LARGE_CHUNK,                "chunk length exceeds configured maximum_chunk_length" },
    { EVENT_WEBROOT_DIR,                "URI path includes /../ that goes above the root directory" },
    { EVENT_LONG_HDR,                   "HTTP header line exceeds maximum_header_length option bytes" },
    { EVENT_MAX_HEADERS,                "HTTP message has more than maximum_headers option header fields" },
    { EVENT_MULTIPLE_CONTLEN,           "HTTP message has more than one Content-Length header value" },
    { EVENT_MULTIPLE_HOST_HDRS,         "Host header field appears more than once or has multiple values" },
    { EVENT_LONG_HOSTNAME,              "length of HTTP Host header field value exceeds maximum_host_length option" },
    { EVENT_UNBOUNDED_POST,             "HTTP POST or PUT request without content-length or chunks" },
    { EVENT_UNKNOWN_METHOD,             "HTTP request method is not known to Snort" },
    { EVENT_SIMPLE_REQUEST,             "HTTP request uses primitive HTTP format known as HTTP/0.9" },
    { EVENT_UNESCAPED_SPACE_URI,        "HTTP request URI has space character that is not percent-encoded" },
    { EVENT_PIPELINE_MAX,               "HTTP connection has more than maximum_pipelined_requests simultaneous "
                                        "pipelined requests that have not been answered" },
    { EVENT_INVALID_STATCODE,           "invalid status code in HTTP response" },
    { EVENT_UTF_NORM_FAIL,              "HTTP response has UTF character set that failed to normalize" },
    { EVENT_UTF7,                       "HTTP response has UTF-7 character set" },
    { EVENT_JS_OBFUSCATION_EXCD,        "more than one level of JavaScript obfuscation" },
    { EVENT_JS_EXCESS_WS,               "consecutive JavaScript whitespaces exceed maximum allowed" },
    { EVENT_MIXED_ENCODINGS,            "multiple encodings within JavaScript obfuscated data" },
    { EVENT_SWF_ZLIB_FAILURE,           "SWF file zlib decompression failure" },
    { EVENT_SWF_LZMA_FAILURE,           "SWF file LZMA decompression failure" },
    { EVENT_PDF_DEFL_FAILURE,           "PDF file deflate decompression failure" },
    { EVENT_PDF_UNSUP_COMP_TYPE,        "PDF file unsupported compression type" },
    { EVENT_PDF_CASC_COMP,              "PDF file with more than one compression applied" },
    { EVENT_PDF_PARSE_FAILURE,          "PDF file parse failure" },
    { EVENT_LOSS_OF_SYNC,               "not HTTP traffic or unrecoverable HTTP protocol error" },
    { EVENT_CHUNK_ZEROS,                "chunk length has excessive leading zeros" },
    { EVENT_WS_BETWEEN_MSGS,            "white space before or between HTTP messages" },
    { EVENT_URI_MISSING,                "request message without URI" },
    { EVENT_CTRL_IN_REASON,             "control character in HTTP response reason phrase" },
    { EVENT_IMPROPER_WS,                "illegal extra whitespace in start line" },
    { EVENT_BAD_VERS,                   "corrupted HTTP version" },
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
    { EVENT_UNSUPPORTED_ENCODING,       "unsupported Content-Encoding used" },
    { EVENT_UNKNOWN_ENCODING,           "unknown Content-Encoding used" },
    { EVENT_STACKED_ENCODINGS,          "multiple Content-Encodings applied" },
    { EVENT_RESPONSE_WO_REQUEST,        "server response before client request" },
    { EVENT_FILE_DECOMPR_OVERRUN,       "PDF/SWF/ZIP decompression of server response too big" },
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
    { EVENT_REPEATED_HEADER,            "header field inappropriately appears twice or has two values" },
    { EVENT_CONTENT_ENCODING_CHUNKED,   "invalid value chunked in Content-Encoding header" },
    { EVENT_206_WITHOUT_RANGE,          "206 response sent to a request without a Range header" },
    { EVENT_VERSION_NOT_UPPERCASE,      "'HTTP' in version field not all upper case" },
    { EVENT_BAD_HEADER_WHITESPACE,      "white space embedded in critical header value" },
    { EVENT_GZIP_EARLY_END,             "gzip compressed data followed by unexpected non-gzip data" },
    { EVENT_EXCESS_REPEAT_PARAMS,       "excessive HTTP parameter key repeats" },
    { EVENT_H2_NON_IDENTITY_TE,         "HTTP/2 Transfer-Encoding header other than identity" },
    { EVENT_H2_DATA_OVERRUNS_CL,        "HTTP/2 message body overruns Content-Length header value" },
    { EVENT_H2_DATA_UNDERRUNS_CL,       "HTTP/2 message body smaller than Content-Length header value" },
    { EVENT_CONNECT_REQUEST_BODY,       "HTTP CONNECT request with a message body" },
    { EVENT_EARLY_C2S_TRAFFIC_AFTER_CONNECT, "HTTP client-to-server traffic after CONNECT request "
                                        "but before CONNECT response" },
    { EVENT_200_CONNECT_RESP_WITH_CL,   "HTTP CONNECT 2XX response with Content-Length header" },
    { EVENT_200_CONNECT_RESP_WITH_TE,   "HTTP CONNECT 2XX response with Transfer-Encoding header" },
    { EVENT_100_CONNECT_RESP,           "HTTP CONNECT response with 1XX status code" },
    { EVENT_EARLY_CONNECT_RESPONSE,     "HTTP CONNECT response before request message completed" },
    { EVENT_MALFORMED_CD_FILENAME,      "malformed HTTP Content-Disposition filename parameter" },
    { EVENT_TRUNCATED_MSG_BODY_CL,      "HTTP Content-Length message body was truncated" },
    { EVENT_TRUNCATED_MSG_BODY_CHUNK,   "HTTP chunked message body was truncated" },
    { EVENT_LONG_SCHEME,                "HTTP URI scheme longer than 10 characters" },
    { EVENT_HTTP2_UPGRADE_REQUEST,      "HTTP/1 client requested HTTP/2 upgrade" },
    { EVENT_HTTP2_UPGRADE_RESPONSE,     "HTTP/1 server granted HTTP/2 upgrade" },
    { EVENT_JS_CODE_IN_EXTERNAL,        "JavaScript code under the external script tags" },
    { EVENT_JS_SHORTENED_TAG,           "script opening tag in a short form" },
    { EVENT_ACCEPT_ENCODING_CONSECUTIVE_COMMAS, "Consecutive commas in HTTP Accept-Encoding header" },
    { EVENT_INVALID_SUBVERSION,         "HTTP/1 version other than 1.0 or 1.1" },
    { EVENT_VERSION_0,                  "HTTP version in start line is 0" },
    { EVENT_VERSION_HIGHER_THAN_1,      "HTTP version in start line is higher than 1" },
    { EVENT_GZIP_FEXTRA,                "HTTP gzip body with the FEXTRA flag set" },
    { EVENT_BAD_STAT_LINE,              "invalid status line" },
    { EVENT_HEADERS_TOO_LONG,           "HTTP message headers longer than 63780 bytes" },
    { EVENT_BAD_REQ_LINE,               "invalid request line" },
    { EVENT_TOO_MUCH_LEADING_WS,        "too many white space characters when start line is expected" },
    { EVENT_STAT_TOO_LONG,              "HTTP message status line longer than 63780 bytes" },
    { EVENT_PARTIAL_START,              "partial start line" },
    { EVENT_REQ_TOO_LONG,               "HTTP message request line longer than 63780 bytes" },
    { EVENT_UNEXPECTED_H2_PREFACE,      "HTTP/2 preface received instead of an HTTP/1 method" },
    { EVENT_DISALLOWED_METHOD,          "HTTP request method is not on allowed methods list or is on "
                                        "disallowed methods list" },
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
    { CountType::SUM, "script_detections", "early inspections of scripts in HTTP responses" },
    { CountType::SUM, "partial_inspections", "early inspections done for script detection" },
    { CountType::SUM, "excess_parameters", "repeat parameters exceeding max" },
    { CountType::SUM, "parameters", "HTTP parameters inspected" },
    { CountType::SUM, "connect_tunnel_cutovers", "CONNECT tunnel flow cutovers to wizard" },
    { CountType::SUM, "ssl_srch_abandoned_early", "total SSL search abandoned too soon" },
    { CountType::SUM, "pipelined_flows", "total HTTP connections containing pipelined requests" },
    { CountType::SUM, "pipelined_requests", "total requests placed in a pipeline" },
    { CountType::SUM, "total_bytes", "total HTTP data bytes inspected" },
    { CountType::SUM, "js_inline_scripts", "total number of inline JavaScripts processed" },
    { CountType::SUM, "js_external_scripts", "total number of external JavaScripts processed" },
    { CountType::SUM, "js_pdf_scripts", "total number of PDF files processed" },
    { CountType::SUM, "skip_mime_attach", "total number of HTTP requests with too many MIME attachments to inspect" },
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

// Characters allowed in the scheme portion of a URI: 0-9, a-z, A-Z, plus, minus, and period.
const bool HttpEnums::scheme_char[256] =
{
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,

    false, false, false, false, false, false, false, false, false, false, false,  true, false,  true,  true, false,
     true,  true,  true,  true,  true,  true,  true,  true,  true,  true, false, false, false, false, false, false,

    false,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
     true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true, false, false, false, false, false,

    false,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
     true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true, false, false, false, false, false,

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

