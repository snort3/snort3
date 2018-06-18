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
#include <utility>

#include "flow/flow.h"
#include "sfip/sf_ip.h"

#include "appid_types.h"
#include "application_ids.h"
#include "http_xff_fields.h"

class AppIdSession;
class ChpMatchDescriptor;
class HttpPatternMatchers;

// These values are used in Lua code as raw numbers. Do NOT reassign new values.
// 0 - 8 (inclusive)       : used heavily in CHP code. DO NOT CHANGE.
// 9 - NUM_METADATA_FIELDS : extra metadata buffers, beyond CHP.
// NUM_METADATA_FIELDS     : must always follow the last metadata FID.
// NUM_HTTP_FIELDS       : number of CHP filds, so always RSP_BODY_FID + 1
enum HttpFieldIds : uint8_t
{
    // 0-8: CHP fields. DO NOT CHANGE

    // Request-side headers
    REQ_AGENT_FID,          // 0
    REQ_HOST_FID,           // 1
    REQ_REFERER_FID,        // 2
    REQ_URI_FID,            // 3
    REQ_COOKIE_FID,         // 4
    REQ_BODY_FID,           // 5
    // Response-side headers
    RSP_CONTENT_TYPE_FID,   // 6
    RSP_LOCATION_FID,       // 7
    RSP_BODY_FID,           // 8

    // extra (non-CHP) metadata fields.
    MISC_VIA_FID,           // 9
    MISC_RESP_CODE_FID,     // 10
    MISC_SERVER_FID,        // 11
    MISC_XWW_FID,           // 12
    MISC_URL_FID,           // 13

    // Total number of metadata fields, always first after actual FIDs.
    NUM_METADATA_FIELDS,    // 14

    // Number of CHP fields, always 1 past RSP_BODY_FIELD
    NUM_HTTP_FIELDS = MISC_VIA_FID,
    MAX_KEY_PATTERN = REQ_URI_FID,     // DO NOT CHANGE, used in CHP
};

#define RESPONSE_CODE_PACKET_THRESHHOLD 0

// These values are used in Lua code as raw numbers. Do NOT reassign new values.
#define APP_TYPE_SERVICE    0x1
#define APP_TYPE_CLIENT     0x2
#define APP_TYPE_PAYLOAD    0x4

class AppIdHttpSession
{
public:
    typedef std::pair<uint16_t,uint16_t> pair_t;

    AppIdHttpSession(AppIdSession&);
    virtual ~AppIdHttpSession();

    int process_http_packet(AppidSessionDirection direction);
    void update_http_xff_address(struct XffFieldValue* xff_fields, uint32_t numXffFields);

    void update_url();

    snort::SfIp* get_xff_addr()
    { return xff_addr; }

    const std::string* get_field(HttpFieldIds id)
    { return meta_data[id]; }

    const char* get_cfield(HttpFieldIds id)
    { return meta_data[id] != nullptr ? meta_data[id]->c_str() : nullptr; }

    void set_field(HttpFieldIds id, const std::string* str)
    {
        delete meta_data[id];
        meta_data[id] = str;
    }

    void set_field(HttpFieldIds id, const uint8_t* str, int32_t len)
    {
        delete meta_data[id];
        meta_data[id] = str and len ? new std::string((const char*)str, len) : nullptr;
    }

    bool get_offset(int id, uint16_t& start, uint16_t& end)
    {
        if ( REQ_AGENT_FID <= id and id < NUM_HTTP_FIELDS )
        {
            start = meta_offset[id].first;
            end = meta_offset[id].second;
            return true;
        }
        return false;
    }

    bool set_offset(int id, uint16_t start, uint16_t end)
    {
        if ( REQ_AGENT_FID <= id and id < NUM_HTTP_FIELDS )
        {
            meta_offset[id].first = start;
            meta_offset[id].second = end;
            return true;
        }
        return false;
    }

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

    void clear_all_fields();

protected:

    void init_chp_match_descriptor(ChpMatchDescriptor& cmd);
    int initial_chp_sweep(ChpMatchDescriptor&);
    void process_chp_buffers();
    void free_chp_matches(ChpMatchDescriptor& cmd, unsigned max_matches);

    HttpPatternMatchers* http_matchers = nullptr;

    AppIdSession& asd;

    // FIXIT-M the meta data buffers in this array are only set from
    // third party (tp_appid_utils.cc) and from http inspect
    // (appid_http_event_handler.cc). The set_field functions should
    // only be accessible to those functions/classes, but the process
    // functions in tp_appid_utils.cc are static. Thus the public
    // set_field() functions in AppIdHttpSession. We do need set functions
    // for this array, as old pointers need to be deleted upon set().
    const std::string* meta_data[NUM_METADATA_FIELDS] = { 0 };
    pair_t meta_offset[NUM_HTTP_FIELDS];

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
    int ptype_req_counts[NUM_HTTP_FIELDS] = { 0 };
    int ptype_scan_counts[NUM_HTTP_FIELDS] = { 0 };
#if RESPONSE_CODE_PACKET_THRESHHOLD
    unsigned response_code_packets = 0;
#endif
};

#endif

