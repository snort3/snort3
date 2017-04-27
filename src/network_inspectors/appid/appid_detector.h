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

// client_detector.h author Sourcefire Inc.

#ifndef APPID_DETECTOR_H
#define APPID_DETECTOR_H

#include <vector>
#include "appid_discovery.h"
#include "application_ids.h"
#include "appid_session.h"
#include "service_state.h"
#include "flow/flow.h"

class AppIdConfig;
class LuaDetector;
struct Packet;

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
    AppIdDiscoveryArgs(const uint8_t* data, uint16_t size, int dir, AppIdSession* asd, Packet* p)
        : data(data), size(size), dir(dir), asd(asd), pkt(p)
    {
        config = asd->config;
        session_logging_enabled = asd->session_logging_enabled;
        session_logging_id = asd->session_logging_id;
    }

    const uint8_t* data;
    uint16_t size;
    int dir;
    AppIdSession* asd;
    Packet* pkt;
    const AppIdConfig* config = nullptr;
    bool session_logging_enabled = false;
    char* session_logging_id = nullptr;
};

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
    AppIdDetector();
    virtual ~AppIdDetector();

    virtual int initialize();
    virtual void do_custom_init() = 0;
    virtual int validate(AppIdDiscoveryArgs&) = 0;
    virtual void register_appid(AppId, unsigned extractsInfo) = 0;

    virtual void* data_get(AppIdSession*);
    virtual int data_add(AppIdSession*, void*, AppIdFreeFCN);
    virtual void add_info(AppIdSession*, const char*);
    virtual void add_user(AppIdSession*, const char*, AppId, bool);
    virtual void add_payload(AppIdSession*, AppId);
    virtual void add_app(AppIdSession*, AppId, AppId, const char*);

    const std::string& get_name() const
    {
        return name;
    }

    unsigned get_minimum_matches() const
    {
        return minimum_matches;
    }

    void set_minimum_matches(unsigned minimumMatches = 0)
    {
        minimum_matches = minimumMatches;
    }

    unsigned int get_precedence() const
    {
        return precedence;
    }

    unsigned get_flow_data_index() const
    {
        return flow_data_index;
    }

    bool is_custom_detector() const
    {
        return custom_detector;
    }

    void set_custom_detector(bool isCustom = false)
    {
        this->custom_detector = isCustom;
    }

    AppIdDiscovery& get_handler() const
    {
        return *handler;
    }

protected:
    AppIdDiscovery* handler = nullptr;
    std::string name;
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

#if defined(WORDS_BIGENDIAN)
#define LETOHS(p)   BYTE_SWAP_16(*((uint16_t*)(p)))
#define LETOHL(p)   BYTE_SWAP_32(*((uint32_t*)(p)))
#else
#define LETOHS(p)   (*((uint16_t*)(p)))
#define LETOHL(p)   (*((uint32_t*)(p)))
#endif

#endif

