//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// appid_http_session.h author davis mcpherson <davmcphe@cisco.com>
// Created on: April 19, 2017

#ifndef APPID_HTTP_SESSION_H
#define APPID_HTTP_SESSION_H

#include <string>
#include <vector>

#include "application_ids.h"
#include "flow/flow.h"
#include "sfip/sf_ip.h"

class AppIdSession;
class ChpMatchDescriptor;
class HttpPatternMatchers;
enum HttpFieldIds : uint8_t;

#define RESPONSE_CODE_PACKET_THRESHHOLD 0

// These values are used in Lua code as raw numbers. Do NOT reassign new values.
#define APP_TYPE_SERVICE    0x1
#define APP_TYPE_CLIENT     0x2
#define APP_TYPE_PAYLOAD    0x4

struct HttpField
{
    std::string field;
    uint16_t start_offset = 0;
    uint16_t end_offset = 0;
};

struct XffFieldValue
{
    char* field;
    char* value;
};

class AppIdHttpSession
{
public:
    AppIdHttpSession(AppIdSession&);
    virtual ~AppIdHttpSession();

    int process_http_packet(int);
    void update_http_xff_address(struct XffFieldValue* xff_fields, uint32_t numXffFields);

    const char* get_user_agent()
    { return useragent.empty() ? nullptr : useragent.c_str(); }

    const char* get_host()
    { return host.empty() ? nullptr : host.c_str(); }

    const char* get_url()
    { return url.empty() ? nullptr : url.c_str(); }

    void set_url(const char* url = nullptr);

    const char* get_uri()
    { return uri.empty() ? nullptr : uri.c_str(); }

    const char* get_via()
    { return via.empty() ? nullptr : via.c_str(); }

    const char* get_referer()
    { return referer.empty() ? nullptr : referer.c_str(); }

    void set_referer(char* referer = nullptr);

    const char* get_cookie()
    { return cookie.empty() ? nullptr : cookie.c_str(); }

    const char* get_response_code()
    { return response_code.empty() ? nullptr : response_code.c_str(); }

    const char* get_content_type()
    { return content_type.empty() ? nullptr : content_type.c_str(); }

    const char* get_location()
    { return location.empty() ? nullptr : location.c_str(); }

    const char* get_req_body()
    { return req_body.empty() ? nullptr : req_body.c_str(); }

    const char* get_server()
    { return server.empty() ? nullptr : server.c_str(); }

    const char* get_body()
    { return body.empty() ? nullptr : body.c_str(); }

    const char* get_x_working_with()
    { return x_working_with.empty() ? nullptr : x_working_with.c_str(); }

    const char* get_new_url();
    const char* get_new_cookie();
    const char* get_new_field(HttpFieldIds fieldId);
    uint16_t get_field_offset(HttpFieldIds fid);
    void set_field_offset(HttpFieldIds fid, uint16_t value);
    uint16_t get_field_end_offset(HttpFieldIds fid);
    void set_field_end_offset(HttpFieldIds fid, uint16_t value);
    uint16_t get_uri_offset();
    uint16_t get_uri_end_offset();
    uint16_t get_cookie_offset();
    uint16_t get_cookie_end_offset();

    snort::SfIp* get_xff_addr()
    { return xff_addr; }

    void update_host(const uint8_t* new_host, int32_t len);
    void update_uri(const uint8_t* new_uri, int32_t len);
    void update_url();
    void update_useragent(const uint8_t* new_ua, int32_t len);
    void update_cookie(const uint8_t* new_cookie, int32_t len);
    void update_referer(const uint8_t* new_referer, int32_t len);
    void update_x_working_with(const uint8_t* new_xww, int32_t len);
    void update_content_type(const uint8_t* new_content_type, int32_t len);
    void update_location(const uint8_t* new_location, int32_t len);
    void update_server(const uint8_t* new_server, int32_t len);
    void update_via(const uint8_t* new_via, int32_t len);
    void update_body(const uint8_t* new_body, int32_t len);
    void update_req_body(const uint8_t* new_req_body, int32_t len);
    void update_response_code(const char* new_rc);
    void set_is_webdav(bool webdav)
    { is_webdav = webdav; }

    bool is_rebuilt_offsets() const
    { return rebuilt_offsets; }

    void set_rebuilt_offsets(bool use_rebuilt_offsets = false)
    { rebuilt_offsets = use_rebuilt_offsets; }

    AppId get_chp_candidate() const
    { return chp_candidate; }

    bool is_chp_finished() const
    { return chp_finished; }

    bool is_chp_hold_flow() const
    { return chp_hold_flow; }

    void set_chp_hold_flow(bool chpHoldFlow = false)
    { chp_hold_flow = chpHoldFlow; }

    AppId get_chp_alt_candidate() const
    { return chp_alt_candidate; }

    void set_chp_alt_candidate(AppId chpAltCandidate = APP_ID_NONE)
    { chp_alt_candidate = chpAltCandidate; }

    bool is_skip_simple_detect() const
    { return skip_simple_detect; }

    void set_skip_simple_detect(bool skipSimpleDetect = false)
    { skip_simple_detect = skipSimpleDetect; }

    void set_chp_finished(bool chpFinished = false)
    { chp_finished = chpFinished; }

    void reset_ptype_scan_counts();

    int get_ptype_scan_count(enum HttpFieldIds type)
    { return ptype_scan_counts[type]; }

    virtual void custom_init() { }

protected:
    void init_chp_match_descriptor(ChpMatchDescriptor& cmd);
    int initial_chp_sweep(ChpMatchDescriptor&);
    void process_chp_buffers();
    void free_chp_matches(ChpMatchDescriptor& cmd, unsigned max_matches);

    HttpPatternMatchers* http_matchers = nullptr;

    AppIdSession& asd;
    std::string host;
    std::string url;
    std::string uri;
    std::string referer;
    std::string useragent;
    std::string via;
    std::string cookie;
    std::string body;
    std::string response_code;
    std::string content_type;
    std::string location;
    std::string req_body;
    std::string server;
    std::string x_working_with;
    std::vector<HttpField> http_fields;
    bool is_webdav = false;
    bool chp_finished = false;
    AppId chp_candidate = APP_ID_NONE;
    AppId chp_alt_candidate = APP_ID_NONE;
    bool chp_hold_flow = false;
    int total_found = 0;
    unsigned app_type_flags = 0;
    int num_matches = 0;
    int num_scans = 0;
    bool rebuilt_offsets = false;
    bool skip_simple_detect = false;
    snort::SfIp* xff_addr = nullptr;
    const char** xffPrecedence = nullptr;
    unsigned numXffFields = 0;
    std::vector<int> ptype_req_counts;
    std::vector<int> ptype_scan_counts;
#if RESPONSE_CODE_PACKET_THRESHHOLD
    unsigned response_code_packets = 0;
#endif

};

#endif

