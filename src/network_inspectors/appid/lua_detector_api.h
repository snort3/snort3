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
    AppidSessionDirection dir = APP_ID_FROM_INITIATOR;
    AppIdSession* asd;
    snort::Packet* pkt = nullptr;
    uint8_t macAddress[6] = { 0 };
};

class LuaStateDescriptor
{
public:
    LuaDetectorParameters ldp;
    // FIXIT-M: RELOAD - When reload is supported, update this whenever lua-state is changed
    // move it to the detector classes
    //int detector_user_data_ref = 0;    // key into LUA_REGISTRYINDEX
    DetectorPackageInfo package_info;
    AppId service_id = APP_ID_UNKNOWN;
    int lua_validate(AppIdDiscoveryArgs&);
};

class LuaServiceDetector : public ServiceDetector
{
public:
    LuaServiceDetector(AppIdDiscovery* sdm, const std::string& detector_name,
        const std::string& log_name, bool is_custom, unsigned min_match, IpProtocol protocol);
    int validate(AppIdDiscoveryArgs&) override;
};

class LuaClientDetector : public ClientDetector
{
public:
    LuaClientDetector(AppIdDiscovery* cdm, const std::string& detector_name,
        const std::string& log_name, bool is_custom, unsigned min_match, IpProtocol protocol);
    int validate(AppIdDiscoveryArgs&) override;
};


//FIXIT-M: RELOAD - Don't use this class, 
//required now to store LSD objects
class LuaObject {
   
public:
    LuaObject() = default;
    virtual ~LuaObject() = default;
    LuaObject(const LuaObject&) = delete;
    LuaObject& operator=(const LuaObject&) = delete;

    LuaStateDescriptor lsd;
    virtual AppIdDetector* get_detector() = 0;
    LuaStateDescriptor* validate_lua_state(bool packet_context);
};

class LuaServiceObject: public LuaObject
{ 
public:
    ServiceDetector* sd;
    LuaServiceObject(AppIdDiscovery* sdm, const std::string& detector_name,
        const std::string& log_name, bool is_custom, IpProtocol protocol, lua_State* L);
    ServiceDetector* get_detector()
    { return sd; }
};

class LuaClientObject : public LuaObject
{ 
public:
    ClientDetector* cd;
    LuaClientObject(AppIdDiscovery* cdm, const std::string& detector_name,
        const std::string& log_name, bool is_custom, IpProtocol protocol, lua_State* L);
    ClientDetector* get_detector()
    { return cd; }
};

int register_detector(lua_State*);
void init_chp_glossary();
int init(lua_State*, int result=0);
void free_chp_glossary();

#endif

