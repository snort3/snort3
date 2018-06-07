//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// tp_appid_types.h author Sourcefire Inc.

#ifndef TP_APPID_TYPES_H
#define TP_APPID_TYPES_H

#include <cstdint>
#include <string>

#include "http_xff_fields.h"

using std::string;

enum TPFlags
{
    TP_SESSION_FLAG_DPI        = 0x00000001,
    TP_SESSION_FLAG_MUTABLE    = 0x00000002,
    TP_SESSION_FLAG_FUTUREFLOW = 0x00000004,
    TP_SESSION_FLAG_ATTRIBUTE  = 0x00000008,
    TP_SESSION_FLAG_TUNNELING  = 0x00000010
};

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

#define TPAD_GET(func)                                          \
    string* func(bool caller_owns_it = 0)                       \
    {                                                           \
        string* tmp = func ## _buf;                             \
        if (caller_owns_it)                                     \
            func ## _buf = nullptr;                             \
        return tmp;                                             \
    }

#define TPAD_SET_OFFSET(func)                                   \
    void set_ ## func(const char* buf, size_t len, uint16_t offset, uint16_t endOffset)                                                         \
    {                                                           \
        if (func ## _buf)                                       \
            delete func ## _buf;                                \
        func ## _buf=new string(buf,len);                       \
        func ## _offset=offset;                                 \
        func ## _end_offset=endOffset;                          \
    }

#define TPAD_SET(func)                                          \
    void set_ ## func(const char* buf, size_t len)              \
    {                                                           \
        if (func ## _buf)                                       \
            delete func ## _buf;                                \
        func ## _buf=new string(buf,len);                       \
    }

// The ThirdPartyAppIDAttributeData class acts as a per packet cache for
// various fields coming out of that packet, that need to be analyzed
// simultaneously.
//
// Consumers of these fields should grab the pointers and avoid an extra copy,
// if speed is of the essence. Once they grab a string* pointer from
// ThirdPartyAppIDAttributeData, then they own it. That is, the consumers
// are responsible for deleting the pointers they grabbed.
//
// If you get it, you own it.
//
// However, currently tp_appid_utils.cc retrieves these, but the
// AppIdHttpSession::set() functions make copies anyway.
// Therefore, for now there is no need for any caller to own these
// pointers yet. We therefore allow callers to just peek at the string*
// buffers inside this class, without owning them. Hence the "caller_owns_it"
// flag in the get functions below.
//
class ThirdPartyAppIDAttributeData
{
    string* spdy_request_path_buf = nullptr;
    string* spdy_request_scheme_buf = nullptr;
    string* spdy_request_host_buf = nullptr;
    string* http_request_url_buf = nullptr;
    string* http_request_uri_buf = nullptr;
    string* http_request_host_buf = nullptr;
    string* http_request_cookie_buf = nullptr;
    string* http_request_via_buf = nullptr;
    string* http_response_via_buf = nullptr;
    string* http_response_upgrade_buf = nullptr;
    string* http_request_user_agent_buf = nullptr;
    string* http_response_version_buf = nullptr;
    string* http_response_code_buf = nullptr;
    string* http_response_content_buf = nullptr;
    string* http_response_location_buf = nullptr;
    string* http_response_body_buf = nullptr;
    string* http_request_body_buf = nullptr;
    string* http_response_server_buf = nullptr;
    string* http_request_x_working_with_buf = nullptr;
    string* tls_host_buf = nullptr;
    string* tls_cname_buf = nullptr;
    string* tls_org_unit_buf = nullptr;
    string* http_request_referer_buf = nullptr;
    string* ftp_command_user_buf = nullptr;

    uint16_t http_request_uri_offset = 0;
    uint16_t http_request_uri_end_offset = 0;

    uint16_t http_request_cookie_offset = 0;
    uint16_t http_request_cookie_end_offset = 0;

    uint16_t http_request_user_agent_offset = 0;
    uint16_t http_request_user_agent_end_offset = 0;

    uint16_t http_request_host_offset = 0;
    uint16_t http_request_host_end_offset = 0;

    uint16_t http_request_referer_offset = 0;
    uint16_t http_request_referer_end_offset = 0;

    uint16_t spdy_request_host_offset = 0;
    uint16_t spdy_request_host_end_offset = 0;

    uint16_t spdy_request_path_offset = 0;
    uint16_t spdy_request_path_end_offset = 0;

    // FIXIT-L: make these private too. Figure out how these get set in tp.

public:
    XffFieldValue xffFieldValue[HTTP_MAX_XFF_FIELDS];
    uint8_t numXffFields = 0;

    ThirdPartyAppIDAttributeData() { }

    ~ThirdPartyAppIDAttributeData()
    {
        // Only delete the pointers that we own (i.e. non null pointers).
        if (spdy_request_path_buf) delete spdy_request_path_buf;
        if (spdy_request_scheme_buf) delete spdy_request_scheme_buf;
        if (spdy_request_host_buf) delete spdy_request_host_buf;
        if (http_request_url_buf) delete http_request_url_buf;
        if (http_request_uri_buf) delete http_request_uri_buf;
        if (http_request_host_buf) delete http_request_host_buf;
        if (http_request_cookie_buf) delete http_request_cookie_buf;
        if (http_request_via_buf) delete http_request_via_buf;
        if (http_response_via_buf) delete http_response_via_buf;
        if (http_response_upgrade_buf) delete http_response_upgrade_buf;
        if (http_request_user_agent_buf) delete http_request_user_agent_buf;
        if (http_response_version_buf) delete http_response_version_buf;
        if (http_response_code_buf) delete http_response_code_buf;
        if (http_response_content_buf) delete http_response_content_buf;
        if (http_response_location_buf) delete http_response_location_buf;
        if (http_response_body_buf) delete http_response_body_buf;
        if (http_request_body_buf) delete http_request_body_buf;
        if (http_response_server_buf) delete http_response_server_buf;
        if (http_request_x_working_with_buf) delete http_request_x_working_with_buf;
        if (tls_host_buf) delete tls_host_buf;
        if (tls_cname_buf) delete tls_cname_buf;
        if (tls_org_unit_buf) delete tls_org_unit_buf;
        if (http_request_referer_buf) delete http_request_referer_buf;
        if (ftp_command_user_buf) delete ftp_command_user_buf;
    }

    // Note: calling these 2 times in a row, the 2nd time it returns null.
    TPAD_GET(spdy_request_path)
    TPAD_GET(spdy_request_scheme)
    TPAD_GET(spdy_request_host)
    TPAD_GET(http_request_url)
    TPAD_GET(http_request_uri)
    TPAD_GET(http_request_host)
    TPAD_GET(http_request_cookie)
    TPAD_GET(http_request_via)
    TPAD_GET(http_response_via)
    TPAD_GET(http_response_upgrade)
    TPAD_GET(http_request_user_agent)
    TPAD_GET(http_response_version)
    TPAD_GET(http_response_code)
    TPAD_GET(http_response_content)
    TPAD_GET(http_response_location)
    TPAD_GET(http_response_body)
    TPAD_GET(http_request_body)
    TPAD_GET(http_response_server)
    TPAD_GET(http_request_x_working_with)
    TPAD_GET(tls_host)
    TPAD_GET(tls_cname)
    TPAD_GET(tls_org_unit)
    TPAD_GET(http_request_referer)
    TPAD_GET(ftp_command_user)

    uint16_t http_request_uri_begin() { return http_request_uri_offset; }
    uint16_t http_request_uri_end() { return http_request_uri_end_offset; }

    uint16_t http_request_cookie_begin() { return http_request_cookie_offset; }
    uint16_t http_request_cookie_end() { return http_request_cookie_end_offset; }

    uint16_t http_request_user_agent_begin() { return http_request_user_agent_offset; }
    uint16_t http_request_user_agent_end() { return http_request_user_agent_end_offset; }

    uint16_t http_request_host_begin() { return http_request_host_offset; }
    uint16_t http_request_host_end() { return http_request_host_end_offset; }

    uint16_t http_request_referer_begin() { return http_request_referer_offset; }
    uint16_t http_request_referer_end() { return http_request_referer_end_offset; }

    uint16_t spdy_request_host_begin() { return spdy_request_host_offset; }
    uint16_t spdy_request_host_end() { return spdy_request_host_end_offset; }

    uint16_t spdy_request_path_begin() { return spdy_request_path_offset; }
    uint16_t spdy_request_path_end() { return spdy_request_path_end_offset; }

    // set functions
    TPAD_SET_OFFSET(spdy_request_path)
    TPAD_SET(spdy_request_scheme)
    TPAD_SET_OFFSET(spdy_request_host)
    TPAD_SET(http_request_url)
    TPAD_SET_OFFSET(http_request_uri)
    TPAD_SET_OFFSET(http_request_host)
    TPAD_SET_OFFSET(http_request_cookie)
    TPAD_SET(http_request_via)
    TPAD_SET(http_response_via)
    TPAD_SET(http_response_upgrade)
    TPAD_SET_OFFSET(http_request_user_agent)
    TPAD_SET(http_response_version)
    TPAD_SET(http_response_code)
    TPAD_SET(http_response_content)
    TPAD_SET(http_response_location)
    TPAD_SET(http_response_body)
    TPAD_SET(http_request_body)
    TPAD_SET(http_response_server)
    TPAD_SET(http_request_x_working_with)
    TPAD_SET(tls_host)
    TPAD_SET(tls_cname)
    TPAD_SET(tls_org_unit)
    TPAD_SET_OFFSET(http_request_referer)
    TPAD_SET(ftp_command_user)
};

#endif

