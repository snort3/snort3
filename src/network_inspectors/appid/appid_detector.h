//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// appid_detector.h author Sourcefire Inc.

#ifndef APPID_DETECTOR_H
#define APPID_DETECTOR_H

#include <vector>

#include "flow/flow.h"

#include "appid_discovery.h"
#include "appid_session.h"
#include "application_ids.h"
#include "service_state.h"

class AppIdContext;
class AppIdInspector;
class LuaStateDescriptor;

namespace snort
{
struct Packet;
}

#define STATE_ID_MAX_VALID_COUNT 5

enum DetectorType
{
    DETECTOR_TYPE_DECODER =  0,
    DETECTOR_TYPE_NETFLOW,
    DETECTOR_TYPE_PORT,
    DETECTOR_TYPE_DERIVED,
    DETECTOR_TYPE_CONFLICT,
    DETECTOR_TYPE_PATTERN,
    DETECTOR_TYPE_NOT_SET
};

typedef std::vector<AppRegistryEntry> FlowApplicationInfo;

struct AppIdFlowContentPattern
{
    const uint8_t* pattern;
    unsigned length;
    int index;
    int nocase;
    unsigned appId;
};
typedef std::vector<AppIdFlowContentPattern> AppIdFlowContentPatterns;

struct ServiceDetectorPort
{
    uint16_t port;
    IpProtocol proto;
    bool reversed_validation;
};
typedef std::vector<ServiceDetectorPort> ServiceDetectorPorts;

class AppIdDiscoveryArgs
{
public:
    AppIdDiscoveryArgs(const uint8_t* data, uint16_t size, AppidSessionDirection dir,
        AppIdSession& asd, snort::Packet* p, AppidChangeBits& cb) : data(data),
        size(size), dir(dir), asd(asd), pkt(p), change_bits(cb)
    {}

    const uint8_t* data;
    uint16_t size;
    AppidSessionDirection dir;
    AppIdSession& asd;
    snort::Packet* pkt;
    AppidChangeBits& change_bits;
};

// These numbers are what Lua (VDB/ODP) gives us. If these numbers are ever changed,
// we need to change get_code_string() code to avoid misinterpretations.
enum APPID_STATUS_CODE
{
    APPID_SUCCESS = 0,
    APPID_INPROCESS = 10,
    APPID_NEED_REASSEMBLY = 11,
    APPID_NOT_COMPATIBLE = 12,
    APPID_INVALID_CLIENT = 13,
    APPID_REVERSED = 14,
    APPID_NOMATCH = 100,
    APPID_ENULL = -10,
    APPID_EINVALID = -11,
    APPID_ENOMEM = -12
};

class AppIdDetector
{
public:
    AppIdDetector() = default;
    virtual ~AppIdDetector() = default;

    virtual int initialize(AppIdInspector&);
    virtual void reload();
    virtual void do_custom_init() { }
    virtual void do_custom_reload() { }
    virtual int validate(AppIdDiscoveryArgs&) = 0;
    virtual void register_appid(AppId, unsigned extractsInfo, OdpContext& odp_ctxt) = 0;

    virtual void* data_get(AppIdSession&);
    virtual int data_add(AppIdSession&, void*, AppIdFreeFCN);
    virtual void add_user(AppIdSession&, const char*, AppId, bool, AppidChangeBits&);
    virtual void add_payload(AppIdSession&, AppId);
    virtual void add_app(AppIdSession& asd, AppId service_id, AppId client_id, const char* version, AppidChangeBits& change_bits)
    {
        if ( version )
            asd.set_client_version(version, change_bits);

        asd.set_client_detected();
        asd.client_inferred_service_id = service_id;
        asd.set_client_id(client_id);
    }
    virtual void add_app(const snort::Packet&, AppIdSession&, AppidSessionDirection, AppId, AppId, const char*, AppidChangeBits&);
    const char* get_code_string(APPID_STATUS_CODE) const;

    const std::string& get_name() const
    { return name; }

    const std::string& get_log_name() const
    { return log_name.empty()? name : log_name; }

    unsigned get_minimum_matches() const
    { return minimum_matches; }

    unsigned int get_precedence() const
    { return precedence; }

    unsigned get_flow_data_index() const
    { return flow_data_index; }

    bool is_custom_detector() const
    { return custom_detector; }

    AppIdDiscovery& get_handler() const
    { return *handler; }

    bool is_client() const
    { return client; }

    virtual LuaStateDescriptor* validate_lua_state(bool /*packet_context*/)
    { return nullptr; }

protected:
    AppIdDiscovery* handler = nullptr;
    std::string name;     // unique name to map detector; can be UUID file name for lua-detector
    std::string log_name; // name from detector package info; can be same as 'name' for c-detector
    bool client = false;
    bool enabled = true;
    bool custom_detector = false;
    IpProtocol proto = IpProtocol::PROTO_NOT_SET;
    unsigned minimum_matches = 0;
    unsigned int precedence = 0;
    bool provides_user = false;
    unsigned flow_data_index = 0;
    unsigned detectorType = DETECTOR_TYPE_NOT_SET;

    AppIdFlowContentPatterns tcp_patterns;
    AppIdFlowContentPatterns udp_patterns;
    FlowApplicationInfo appid_registry;
    ServiceDetectorPorts service_ports;
};

#endif

