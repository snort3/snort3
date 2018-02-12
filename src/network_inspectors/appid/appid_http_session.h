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

// appid_inspector.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Apr 19, 2017

#ifndef APPID_HTTP_SESSION_H
#define APPID_HTTP_SESSION_H

#include "appid_api.h"
#include "application_ids.h"
#include "detector_plugins/http_url_patterns.h"
#include "flow/flow.h"
#include "sfip/sf_ip.h"

class AppIdSession;

#define RESPONSE_CODE_PACKET_THRESHHOLD 0

// These values are used in Lua code as raw numbers. Do NOT reassign new values.
#define APP_TYPE_SERVICE    0x1
#define APP_TYPE_CLIENT     0x2
#define APP_TYPE_PAYLOAD    0x4

class AppIdHttpSession
{
public:
    AppIdHttpSession(AppIdSession*);
    ~AppIdHttpSession();

    int process_http_packet(int);

    AppIdSession* asd = nullptr;
    char* host = nullptr;
    char* url = nullptr;
    char* uri = nullptr;
    char* via = nullptr;
    char* useragent = nullptr;
    char* response_code = nullptr;
    char* referer = nullptr;
    char* cookie = nullptr;
    char* content_type = nullptr;
    char* location = nullptr;
    char* body = nullptr;
    char* req_body = nullptr;
    char* server = nullptr;
    char* x_working_with = nullptr;
    SfIp* xffAddr = nullptr;
    const char** xffPrecedence = nullptr;
    char* new_field[HTTP_FIELD_MAX + 1] = { nullptr };
    AppId chp_candidate = APP_ID_NONE;
    AppId chp_alt_candidate = APP_ID_NONE;
    int chp_hold_flow = 0;
    int total_found = 0;
    unsigned app_type_flags = 0;
    int num_matches = 0;
    int num_scans = 0;
    int get_offsets_from_rebuilt = 0;
    unsigned numXffFields = 0;
    int ptype_req_counts[NUMBER_OF_PTYPES] = { 0 };
    int ptype_scan_counts[NUMBER_OF_PTYPES] = { 0 };
    uint16_t host_buflen = 0;
    uint16_t uri_buflen = 0;
    uint16_t useragent_buflen = 0;
    uint16_t response_code_buflen = 0;
    uint16_t referer_buflen = 0;
    uint16_t cookie_buflen = 0;
    uint16_t content_type_buflen = 0;
    uint16_t location_buflen = 0;
    uint16_t body_buflen = 0;
    uint16_t req_body_buflen = 0;
    uint16_t new_field_len[HTTP_FIELD_MAX + 1] = { 0 };
    uint16_t fieldOffset[HTTP_FIELD_MAX + 1] = { 0 };
    uint16_t fieldEndOffset[HTTP_FIELD_MAX + 1] = { 0 };
    bool new_field_contents = false;
    bool is_webdav = false;
    bool chp_finished = false;
    bool skip_simple_detect = false;

#if RESPONSE_CODE_PACKET_THRESHHOLD
    unsigned response_code_packets = 0;
#endif

private:
    void init_chp_match_descriptor(ChpMatchDescriptor& cmd);
    int initial_chp_sweep(ChpMatchDescriptor&);
    void process_chp_buffers();
    void free_chp_matches(ChpMatchDescriptor& cmd, unsigned max_matches);

    HttpPatternMatchers* http_matchers = nullptr;
};

#endif

