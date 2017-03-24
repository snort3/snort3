//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// thirdparty_appid_types.h author Sourcefire Inc.

#ifndef THIRDPARTY_APPID_TYPES_H
#define THIRDPARTY_APPID_TYPES_H

#include <cstdint>

#define TP_SESSION_FLAG_DPI        0x00000001
#define TP_SESSION_FLAG_MUTABLE    0x00000002
#define TP_SESSION_FLAG_FUTUREFLOW 0x00000004
#define TP_SESSION_FLAG_ATTRIBUTE  0x00000008
#define TP_SESSION_FLAG_TUNNELING  0x00000010

#define HTTP_XFF_FIELD_X_FORWARDED_FOR ""
#define HTTP_XFF_FIELD_TRUE_CLIENT_IP ""
#define HTTP_MAX_XFF_FIELDS 255

enum TPState
{
    TP_STATE_INIT,
    TP_STATE_TERMINATED,
    TP_STATE_INSPECTING,
    TP_STATE_MONITORING,
    TP_STATE_CLASSIFIED,
    TP_STATE_HA = 21
};

enum TPSessionAttr
{
    TP_ATTR_CONTINUE_MONITORING     = (1 << 0),
    TP_ATTR_COPY_RESPONSE_CONTENT   = (1 << 1),
    TP_ATTR_COPY_RESPONSE_LOCATION  = (1 << 2),
    TP_ATTR_COPY_RESPONSE_BODY      = (1 << 3),
};

struct XffFieldValue
{
    char* field;
    char* value;
};

struct ThirdPartyAppIDAttributeData
{
    char* spdyRequestPath;
    char* spdyRequestScheme;
    char* spdyRequestHost;
    char* httpRequestUrl;
    char* httpRequestUri;
    uint16_t httpRequestUriLen;
    uint16_t httpRequestUriOffset;
    uint16_t httpRequestUriEndOffset;
    char* httpRequestHost;
    uint16_t httpRequestHostLen;
    char* httpRequestCookie;
    uint16_t httpRequestCookieLen;
    uint16_t httpRequestCookieOffset;
    uint16_t httpRequestCookieEndOffset;
    char* httpRequestVia;
    char* httpResponseVia;
    char* httpResponseUpgrade;
    char* httpRequestUserAgent;
    uint16_t httpRequestUserAgentLen;
    char* httpResponseVersion;
    char* httpResponseCode;
    uint16_t httpResponseCodeLen;
    char* httpResponseContent;
    uint16_t httpResponseContentLen;
    char* httpResponseLocation;
    uint16_t httpResponseLocationLen;
    char* httpResponseBody;
    uint16_t httpResponseBodyLen;
    char* httpRequestBody;
    uint16_t httpRequestBodyLen;
    char* httpResponseServer;
    char* httpRequestXWorkingWith;
    char* tlsHost;
    char* tlsCname;
    char* tlsOrgUnit;
    char* httpRequestReferer;
    uint16_t httpRequestRefererLen;
    char* ftpCommandUser;
    struct XffFieldValue xffFieldValue[HTTP_MAX_XFF_FIELDS];
    uint8_t numXffFields;
    uint16_t httpRequestUserAgentOffset;
    uint16_t httpRequestUserAgentEndOffset;
    uint16_t httpRequestHostOffset;
    uint16_t httpRequestHostEndOffset;
    uint16_t httpRequestRefererOffset;
    uint16_t httpRequestRefererEndOffset;
    uint16_t spdyRequestHostOffset;
    uint16_t spdyRequestHostEndOffset;
    uint16_t spdyRequestPathOffset;
    uint16_t spdyRequestPathEndOffset;
};

#endif

