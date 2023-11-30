//--------------------------------------------------------------------------
// Copyright (C) 2017-2023 Cisco and/or its affiliates. All rights reserved.
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
#include <utility>

#include "flow/flow.h"
#include "pub_sub/appid_events.h"
#include "sfip/sf_ip.h"

#include "appid_app_descriptor.h"
#include "appid_types.h"
#include "application_ids.h"

class AppIdSession;
class ChpMatchDescriptor;
class HttpPatternMatchers;

#define RESPONSE_CODE_PACKET_THRESHHOLD 0

// These values are used in Lua code as raw numbers. Do NOT reassign new values.
#define APP_TYPE_SERVICE    0x1
#define APP_TYPE_CLIENT     0x2
#define APP_TYPE_PAYLOAD    0x4

struct TunnelDest
{
    snort::SfIp ip;
    uint16_t port = 0;
    TunnelDest(const char* string_srcip, uint16_t tun_port)
    {
        ip.clear();
        if ( ip.set(string_srcip) == SFIP_SUCCESS )
            port = tun_port;
    }
};

class AppIdHttpSession
{
public:
    typedef std::pair<uint16_t,uint16_t> pair_t;

    AppIdHttpSession(AppIdSession&, int64_t);
    virtual ~AppIdHttpSession();
    ClientAppDescriptor client;
    PayloadAppDescriptor payload;
    AppId referred_payload_app_id = APP_ID_NONE;
    AppId misc_app_id = APP_ID_NONE;

    int process_http_packet(AppidSessionDirection direction, AppidChangeBits& change_bits,
        HttpPatternMatchers& http_matchers);

    void update_url(AppidChangeBits& change_bits);
    void set_field(HttpFieldIds id, const std::string* str, AppidChangeBits& change_bits);
    void set_field(HttpFieldIds id, const uint8_t* str, int32_t len, AppidChangeBits& change_bits);
    void set_req_body_field(HttpFieldIds id, const uint8_t* str, int32_t len,
        AppidChangeBits& change_bits);

    const std::string* get_field(HttpFieldIds id) const
    { return meta_data[id]; }

    const char* get_cfield(HttpFieldIds id) const
    { return meta_data[id] != nullptr ? meta_data[id]->c_str() : nullptr; }

    void set_is_webdav(bool webdav)
    { is_webdav = webdav; }

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

    void set_tun_dest();

    const TunnelDest* get_tun_dest() const
    { return tun_dest; }

    void free_tun_dest()
    {
        delete tun_dest;
        tun_dest = nullptr;
    }

    void reset_ptype_scan_counts();

    int get_ptype_scan_count(enum HttpFieldIds type) const
    { return ptype_scan_counts[type]; }

    void clear_all_fields();
    void set_client(AppId, AppidChangeBits&, const char*, const char* version = nullptr);
    void set_payload(AppId, AppidChangeBits&, const char* type = nullptr,
        const char* version = nullptr);
    void set_referred_payload(AppId, AppidChangeBits&);

    int64_t get_httpx_stream_id() const
    {
        return httpx_stream_id;
    }
    void set_rcvd_full_req_body(bool req_full_body)
    {
        rcvd_full_req_body = req_full_body;
    }
    bool get_rcvd_full_req_body()
    {
        return rcvd_full_req_body;
    }

    void set_tunnel(bool tunnel)
    {
        is_tunnel = tunnel;
    }

    bool get_tunnel()
    {
        return is_tunnel;
    }
protected:

    void init_chp_match_descriptor(ChpMatchDescriptor& cmd);
    bool initial_chp_sweep(ChpMatchDescriptor&, HttpPatternMatchers&);
    void process_chp_buffers(AppidChangeBits&, HttpPatternMatchers&);
    void free_chp_matches(ChpMatchDescriptor& cmd, unsigned max_matches);
    void set_http_change_bits(AppidChangeBits& change_bits, HttpFieldIds id);
    void set_scan_flags(HttpFieldIds id);
    void print_field(HttpFieldIds id, const std::string* str);

    AppIdSession& asd;

    // FIXIT-M the meta data buffers in this array are only set from
    // third party (tp_appid_utils.cc) and from http inspect
    // (appid_http_event_handler.cc). The set_field functions should
    // only be accessible to those functions/classes, but the process
    // functions in tp_appid_utils.cc are static. Thus the public
    // set_field() functions in AppIdHttpSession. We do need set functions
    // for this array, as old pointers need to be deleted upon set().
    const std::string* meta_data[NUM_METADATA_FIELDS] = { };

    bool is_webdav = false;
    bool chp_finished = false;
    AppId chp_candidate = APP_ID_NONE;
    AppId chp_alt_candidate = APP_ID_NONE;
    bool chp_hold_flow = false;
    int total_found = 0;
    unsigned app_type_flags = 0;
    int num_matches = 0;
    int num_scans = 0;
    bool skip_simple_detect = false;
    int ptype_req_counts[NUM_HTTP_FIELDS] = { };
    int ptype_scan_counts[NUM_HTTP_FIELDS] = { };
    const TunnelDest* tun_dest = nullptr;
#if RESPONSE_CODE_PACKET_THRESHHOLD
    unsigned response_code_packets = 0;
#endif
    int64_t httpx_stream_id = -1;
    bool is_payload_processed = false;
    bool rcvd_full_req_body = false;
    bool is_tunnel = false;
};

#endif
