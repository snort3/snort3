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

// lua_detector_api.h author Sourcefire Inc.

#ifndef LUA_DETECTOR_API_H
#define LUA_DETECTOR_API_H

// This module supports basic API towards Lua detectors.

#include <cstdint>
#include <string>

#include "appid_types.h"
#include "client_plugins/client_detector.h"
#include "service_plugins/service_detector.h"

namespace snort
{
struct Packet;
}
struct lua_State;
class AppIdSession;
class AppInfoTableEntry;

#define DETECTOR "Detector"
#define DETECTORFLOW "DetectorFlow"

#define LUA_STATE_GLOBAL_SC_ID  "snort_config"

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
        change_bits = &args.change_bits;
        pkt = args.pkt;
    }

    const uint8_t* data = nullptr;
    uint16_t size = 0;
    AppidSessionDirection dir = APP_ID_FROM_INITIATOR;
    AppIdSession* asd;
    AppidChangeBits* change_bits = nullptr;
    const snort::Packet* pkt = nullptr;
};

class LuaStateDescriptor
{
public:
    LuaDetectorParameters ldp;
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


class LuaObject {

public:
    LuaObject(OdpContext& odp_ctxt) : odp_ctxt(odp_ctxt) { }
    virtual ~LuaObject() = default;
    LuaObject(const LuaObject&) = delete;
    LuaObject& operator=(const LuaObject&) = delete;

    LuaStateDescriptor lsd;
    virtual AppIdDetector* get_detector() = 0;
    LuaStateDescriptor* validate_lua_state(bool packet_context);

    const std::string& get_cb_fn_name()
    { return cb_fn_name; }

    void set_cb_fn_name(const char* name)
    { cb_fn_name = name; }

    bool is_running()
    { return running; }

    void set_running(bool is_running)
    { running = is_running; }

    OdpContext& get_odp_ctxt() const
    { return odp_ctxt; }

private:
    std::string cb_fn_name;
    bool running = false;
    OdpContext& odp_ctxt;
};

class LuaServiceObject: public LuaObject
{
public:
    ServiceDetector* sd;
    LuaServiceObject(AppIdDiscovery* sdm, const std::string& detector_name,
        const std::string& log_name, bool is_custom, IpProtocol protocol, lua_State* L,
        OdpContext& odp_ctxt);
    ServiceDetector* get_detector() override
    { return sd; }
};

class LuaClientObject : public LuaObject
{
public:
    ClientDetector* cd;
    LuaClientObject(const std::string& detector_name,
        const std::string& log_name, bool is_custom, IpProtocol protocol, lua_State* L,
        OdpContext& odp_ctxt, bool& has_validate);
    ClientDetector* get_detector() override
    { return cd; }
};

int register_detector(lua_State*);
void init_chp_glossary();
int init(lua_State*, int result=0);
void free_chp_glossary();

void check_detector_callback(const snort::Packet& p, AppIdSession& asd, AppidSessionDirection dir,
    AppId app_id, AppidChangeBits& change_bits, AppInfoTableEntry* entry = nullptr);

#endif
