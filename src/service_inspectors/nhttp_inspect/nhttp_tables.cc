/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      Static constant tables for converting protocol strings to enum codes. Members of HttpMsgHeader.
//


#include <string.h>
#include <sys/types.h>

#include "snort.h"
#include "flow/flow.h"
#include "nhttp_enum.h"
#include "nhttp_scratchpad.h"
#include "nhttp_strtocode.h"
#include "nhttp_headnorm.h"
#include "nhttp_flowdata.h"
#include "nhttp_msgheader.h"

using namespace NHttpEnums;

const StrCode NHttpMsgHeader::methodList[] =
   {{ METH_GET,                "GET"},
    { METH_HEAD,               "HEAD"},
    { METH_POST,               "POST"},
    { METH_PUT,                "PUT"},
    { METH_DELETE,             "DELETE"},
    { METH_TRACE,              "TRACE"},
    { METH_CONNECT,            "CONNECT"},
    { METH_PROPFIND,           "PROPFIND"},
    { METH_PROPPATCH,          "PROPPATCH"},
    { METH_MKCOL,              "MKCOL"},
    { METH_COPY,               "COPY"},
    { METH_MOVE,               "MOVE"},
    { METH_LOCK,               "LOCK"},
    { METH_UNLOCK,             "UNLOCK"},
    { METH_VERSION_CONTROL,    "VERSION-CONTROL"},
    { METH_REPORT,             "REPORT"},
    { METH_CHECKOUT,           "CHECKOUT"},
    { METH_CHECKIN,            "CHECKIN"},
    { METH_UNCHECKOUT,         "UNCHECKOUT"},
    { METH_MKWORKSPACE,        "MKWORKSPACE"},
    { METH_UPDATE,             "UPDATE"},
    { METH_LABEL,              "LABEL"},
    { METH_MERGE,              "MERGE"},
    { METH_BASELINE_CONTROL,   "BASELINE-CONTROL"},
    { METH_MKACTIVITY,         "MKACTIVITY"},
    { METH_ORDERPATCH,         "ORDERPATCH"},
    { METH_ACL,                "ACL"},
    { METH_PATCH,              "PATCH"},
    { METH_SEARCH,             "SEARCH"},
    { METH_BCOPY,              "BCOPY"},
    { METH_BDELETE,            "BDELETE"},
    { METH_BMOVE,              "BMOVE"},
    { METH_BPROPFIND,          "BPROPFIND"},
    { METH_BPROPPATCH,         "BPROPPATCH"},
    { METH_NOTIFY,             "NOTIFY"},
    { METH_POLL,               "POLL"},
    { METH_SUBSCRIBE,          "SUBSCRIBE"},
    { METH_UNSUBSCRIBE,        "UNSUBSCRIBE"},
    { METH_X_MS_ENUMATTS,      "X-MS-ENUMATTS"},
    { METH_BIND,               "BIND"},
    { METH_LINK,               "LINK"},
    { METH_MKCALENDAR,         "MKCALENDAR"},
    { METH_MKREDIRECTREF,      "MKREDIRECTREF"},
    { METH_REBIND,             "REBIND"},
    { METH_UNBIND,             "UNBIND"},
    { METH_UNLINK,             "UNLINK"},
    { METH_UPDATEREDIRECTREF,  "UPDATEREDIRECTREF"},
    { 0,                       nullptr} };

const StrCode NHttpMsgHeader::headerList[] =
   {{ HEAD_CACHE_CONTROL,        "cache-control"},
    { HEAD_CONNECTION,           "connection"},
    { HEAD_DATE,                 "date"},
    { HEAD_PRAGMA,               "pragma"},
    { HEAD_TRAILER,              "trailer"},
    { HEAD_COOKIE,               "cookie"},
    { HEAD_SET_COOKIE,           "set-cookie"},
    { HEAD_TRANSFER_ENCODING,    "transfer-encoding"},
    { HEAD_UPGRADE,              "upgrade"},
    { HEAD_VIA,                  "via"},
    { HEAD_WARNING,              "warning"},
    { HEAD_ACCEPT,               "accept"},
    { HEAD_ACCEPT_CHARSET,       "accept-charset"},
    { HEAD_ACCEPT_ENCODING,      "accept-encoding"},
    { HEAD_ACCEPT_LANGUAGE,      "accept-language"},
    { HEAD_AUTHORIZATION,        "authorization"},
    { HEAD_EXPECT,               "expect"},
    { HEAD_FROM,                 "from"},
    { HEAD_HOST,                 "host"},
    { HEAD_IF_MATCH,             "if-match"},
    { HEAD_IF_MODIFIED_SINCE,    "if-modified-since"},
    { HEAD_IF_NONE_MATCH,        "if-none-match"},
    { HEAD_IF_RANGE,             "if-range"},
    { HEAD_IF_UNMODIFIED_SINCE,  "if-unmodified-since"},
    { HEAD_MAX_FORWARDS,         "max-forwards"},
    { HEAD_PROXY_AUTHORIZATION,  "proxy-authorization"},
    { HEAD_RANGE,                "range"},
    { HEAD_REFERER,              "referer"},
    { HEAD_TE,                   "te"},
    { HEAD_USER_AGENT,           "user-agent"},
    { HEAD_ACCEPT_RANGES,        "accept-ranges"},
    { HEAD_AGE,                  "age"},
    { HEAD_ETAG,                 "etag"},
    { HEAD_LOCATION,             "location"},
    { HEAD_PROXY_AUTHENTICATE,   "proxy-authenticate"},
    { HEAD_RETRY_AFTER,          "retry-after"},
    { HEAD_SERVER,               "server"},
    { HEAD_VARY,                 "vary"},
    { HEAD_WWW_AUTHENTICATE,     "www-authenticate"},
    { HEAD_ALLOW,                "allow"},
    { HEAD_CONTENT_ENCODING,     "content-encoding"},
    { HEAD_CONTENT_LANGUAGE,     "content-language"},
    { HEAD_CONTENT_LENGTH,       "content-length"},
    { HEAD_CONTENT_LOCATION,     "content-location"},
    { HEAD_CONTENT_MD5,          "content-md5"},
    { HEAD_CONTENT_RANGE,        "content-range"},
    { HEAD_CONTENT_TYPE,         "content-type"},
    { HEAD_EXPIRES,              "expires"},
    { HEAD_LAST_MODIFIED,        "last-modified"},
    { 0,                         nullptr} };

const StrCode NHttpMsgHeader::transCodeList[] =
   {{ TRANSCODE_CHUNKED,         "chunked"},
    { TRANSCODE_IDENTITY,        "identity"},
    { TRANSCODE_GZIP,            "gzip"},
    { TRANSCODE_COMPRESS,        "compress"},
    { TRANSCODE_DEFLATE,         "deflate"},
    { 0,                         nullptr} };

const HeaderNormalizer NHttpMsgHeader::NORMALIZER_NIL {NORM_NULL, false, false, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
const HeaderNormalizer NHttpMsgHeader::NORMALIZER_BASIC {NORM_FIELD, false, false, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
const HeaderNormalizer NHttpMsgHeader::NORMALIZER_CAT {NORM_FIELD, true, false, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
const HeaderNormalizer NHttpMsgHeader::NORMALIZER_NOREPEAT {NORM_FIELD, false, true, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
const HeaderNormalizer NHttpMsgHeader::NORMALIZER_DECIMAL {NORM_INTEGER, false, true, normDecimalInteger, nullptr, nullptr, nullptr, nullptr, nullptr};
const HeaderNormalizer NHttpMsgHeader::NORMALIZER_TRANSCODE {NORM_INTEGER, true, false, normSeqStrCode, NHttpMsgHeader::transCodeList, nullptr, nullptr, nullptr, nullptr};

const HeaderNormalizer* const NHttpMsgHeader::headerNorms[HEAD__MAXVALUE] = { [0] = &NORMALIZER_NIL,
    [HEAD__OTHER] = &NORMALIZER_BASIC,
    [HEAD_CACHE_CONTROL] = &NORMALIZER_BASIC,
    [HEAD_CONNECTION] = &NORMALIZER_BASIC,
    [HEAD_DATE] = &NORMALIZER_BASIC,
    [HEAD_PRAGMA] = &NORMALIZER_BASIC,
    [HEAD_TRAILER] = &NORMALIZER_BASIC,
    [HEAD_COOKIE] = &NORMALIZER_BASIC,
    [HEAD_SET_COOKIE] = &NORMALIZER_BASIC,
    [HEAD_TRANSFER_ENCODING] = &NORMALIZER_TRANSCODE,
    [HEAD_UPGRADE] = &NORMALIZER_BASIC,
    [HEAD_VIA] = &NORMALIZER_BASIC,
    [HEAD_WARNING] = &NORMALIZER_BASIC,
    [HEAD_ACCEPT] = &NORMALIZER_BASIC,
    [HEAD_ACCEPT_CHARSET] = &NORMALIZER_BASIC,
    [HEAD_ACCEPT_ENCODING] = &NORMALIZER_BASIC,
    [HEAD_ACCEPT_LANGUAGE] = &NORMALIZER_BASIC,
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
    [HEAD_LAST_MODIFIED] = &NORMALIZER_BASIC
};

    const int32_t NHttpMsgHeader::numNorms = HEAD__MAXVALUE-1;


