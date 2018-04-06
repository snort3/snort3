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

// lua_detector_api.h author Sourcefire Inc.

#ifndef LUA_DETECTOR_API_H
#define LUA_DETECTOR_API_H

// This module supports basic API towards Lua detectors.

#include <cstdint>
#include <string>

#include "client_plugins/client_detector.h"
#include "service_plugins/service_detector.h"

#include "main/snort_debug.h"
extern Trace TRACE_NAME(appid_module);

namespace snort
{
struct Packet;
}
struct lua_State;
class AppIdSession;

#define DETECTOR "Detector"
#define DETECTORFLOW "DetectorFlow"

struct DetectorPackageInfo
{
    std::string initFunctionName;
    std::string cleanFunctionName;
    std::string validateFunctionName;
    int minimum_matches = 0;
    std::string name = "NoName";
    IpProtocol proto;
};

struct LuaDetectorParameters
{
    void init(AppIdDiscoveryArgs& args)
    {
        data = args.data;
        size = args.size;
        dir = args.dir;
        asd = &args.asd;
        pkt = args.pkt;
    }

    const uint8_t* data = nullptr;
    uint16_t size = 0;
    int dir = 0;
    AppIdSession* asd;
    snort::Packet* pkt = nullptr;
    uint8_t macAddress[6] = { 0 };
};

class LuaStateDescriptor
{
public:
	LuaStateDescriptor() = default;
    virtual ~LuaStateDescriptor();

    LuaDetectorParameters ldp;
    lua_State* my_lua_state= nullptr;
    int detector_user_data_ref = 0;    // key into LUA_REGISTRYINDEX
    DetectorPackageInfo package_info;
    unsigned int service_id = APP_ID_UNKNOWN;

    int lua_validate(AppIdDiscoveryArgs&);
};

class LuaServiceDetector : public ServiceDetector
{
public:
    LuaServiceDetector(AppIdDiscovery* sdm, const std::string& detector_name, IpProtocol protocol,
            lua_State* L);
    int validate(AppIdDiscoveryArgs&) override;
    LuaStateDescriptor* validate_lua_state(bool packet_context) override;

    LuaStateDescriptor lsd;
};

class LuaClientDetector : public ClientDetector
{
public:
    LuaClientDetector(AppIdDiscovery* cdm, const std::string& detector_name, IpProtocol protocol,
        lua_State* L);
    int validate(AppIdDiscoveryArgs&) override;
    LuaStateDescriptor* validate_lua_state(bool packet_context) override;

    LuaStateDescriptor lsd;
};

int register_detector(lua_State*);
int init_chp_glossary();
void free_chp_glossary();

#endif

