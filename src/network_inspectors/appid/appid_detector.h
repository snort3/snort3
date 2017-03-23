//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
    { }

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
    virtual void activate();
    virtual int validate(AppIdDiscoveryArgs&);
    virtual void clean();
    virtual void register_appid(AppId, unsigned extractsInfo);

    virtual void* data_get(AppIdSession*);
    virtual int data_add(AppIdSession*, void*, AppIdFreeFCN);
    virtual void add_info(AppIdSession*, const char*);
    virtual void add_user(AppIdSession*, const char*, AppId, int);
    virtual void add_payload(AppIdSession*, AppId);
    virtual void add_app(AppIdSession*, AppId, AppId, const char*);

public:  // FIXIT-M - make this protected:
    AppIdDiscovery* handler = nullptr;
    std::string name;
    bool enabled = true;
    IpProtocol proto = IpProtocol::PROTO_NOT_SET;
    unsigned minimum_matches = 0;
    unsigned int precedence = 0;
    bool provides_user = false;
    unsigned flow_data_index = 0;
    unsigned detectorType = DETECTOR_TYPE_NOT_SET;
    unsigned ref_count = 1;
    unsigned current_ref_count = 0;
    bool isCustom = false;

    AppIdFlowContentPatterns tcp_patterns;
    AppIdFlowContentPatterns udp_patterns;
    FlowApplicationInfo appid_registry;
    ServiceDetectorPorts service_ports;
};

inline uint32_t get_service_detect_level(AppIdSession* asd)
{
    if (asd->get_session_flags(APPID_SESSION_DECRYPTED))
        return 1;
    return 0;
}

#if defined(WORDS_BIGENDIAN)
#define LETOHS(p)   BYTE_SWAP_16(*((uint16_t*)(p)))
#define LETOHL(p)   BYTE_SWAP_32(*((uint32_t*)(p)))
#else
#define LETOHS(p)   (*((uint16_t*)(p)))
#define LETOHL(p)   (*((uint32_t*)(p)))
#endif

#endif

