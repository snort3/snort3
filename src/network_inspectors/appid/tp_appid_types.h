//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#define MAX_ATTR_LEN 2048

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
    TP_ATTR_UNAME_KNOWN             = (1 << 4),
};

static void set_attr(string*& attr, const char* buf, size_t len, bool flush, size_t max_len)
{
    if (!attr)
        attr = new string(buf, len > max_len ? max_len : len);
    else if (flush)
    {
        delete attr;
        attr = new string(buf, len > max_len ? max_len : len);
    }
    else if (attr->size() < max_len)
    {
        size_t max_copy_len = max_len - attr->size();
        attr->append(buf, len > max_copy_len ? max_copy_len : len);
    }
    // else, skip copy because the buffer is filled up to its limit
}

#define TPAD_GET(func)                                          \
    string* func(bool caller_owns_it = false)                   \
    {                                                           \
        string* tmp = func ## _buf;                             \
        if (caller_owns_it)                                     \
            func ## _buf = nullptr;                             \
        return tmp;                                             \
    }

#define TPAD_SET(func)                                                  \
    void set_ ## func(const char* buf, size_t len, bool last_fragment, size_t max_len = MAX_ATTR_LEN) \
    {                                                                   \
        set_attr(func ## _buf, buf, len, func ## _flush, max_len);      \
        func ## _flush = last_fragment;                                 \
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
    string* http_request_user_agent_buf = nullptr;
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
    string* quic_sni_buf = nullptr;

    // will be set to true after last fragment for a metadata field is received
    bool spdy_request_path_flush = true;
    bool spdy_request_scheme_flush = true;
    bool spdy_request_host_flush = true;
    bool http_request_url_flush = true;
    bool http_request_uri_flush = true;
    bool http_request_host_flush = true;
    bool http_request_cookie_flush = true;
    bool http_request_via_flush = true;
    bool http_response_via_flush = true;
    bool http_request_user_agent_flush = true;
    bool http_response_code_flush = true;
    bool http_response_content_flush = true;
    bool http_response_location_flush = true;
    bool http_response_body_flush = true;
    bool http_request_body_flush = true;
    bool http_response_server_flush = true;
    bool http_request_x_working_with_flush = true;
    bool tls_host_flush = true;
    bool tls_cname_flush = true;
    bool tls_org_unit_flush = true;
    bool http_request_referer_flush = true;
    bool ftp_command_user_flush = true;
    bool quic_sni_flush = true;

    // FIXIT-L: make these private too. Figure out how these get set in tp.

public:
    ThirdPartyAppIDAttributeData() = default;

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
        if (http_request_user_agent_buf) delete http_request_user_agent_buf;
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
        if (quic_sni_buf) delete quic_sni_buf;
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
    TPAD_GET(http_request_user_agent)
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
    TPAD_GET(quic_sni)

    // set functions
    TPAD_SET(spdy_request_path)
    TPAD_SET(spdy_request_scheme)
    TPAD_SET(spdy_request_host)
    TPAD_SET(http_request_url)
    TPAD_SET(http_request_uri)
    TPAD_SET(http_request_host)
    TPAD_SET(http_request_cookie)
    TPAD_SET(http_request_via)
    TPAD_SET(http_response_via)
    TPAD_SET(http_request_user_agent)
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
    TPAD_SET(http_request_referer)
    TPAD_SET(ftp_command_user)
    TPAD_SET(quic_sni)
};

#endif

