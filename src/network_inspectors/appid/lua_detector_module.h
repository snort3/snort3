//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// lua_detector_module.h author Sourcefire Inc.

#ifndef LUA_DETECTOR_MODULE_H
#define LUA_DETECTOR_MODULE_H

#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <lua.hpp>
#include <lua/lua.h>

#include "main/thread_config.h"
#include "protocols/protocol_ids.h"

#include "application_ids.h"

namespace snort
{
    struct SnortConfig;
}

class AppIdContext;
class AppIdDetector;
struct DetectorFlow;
class LuaObject;

bool get_lua_field(lua_State* L, int table, const char* field, std::string& out);
bool get_lua_field(lua_State* L, int table, const char* field, int& out);
bool get_lua_field(lua_State* L, int table, const char* field, IpProtocol& out);

class LuaDetectorManager
{
public:
    LuaDetectorManager(AppIdContext&, bool is_control);
    virtual ~LuaDetectorManager();
    virtual void initialize(const snort::SnortConfig*);

    bool load_detector(char* detector_name, bool is_custom, std::string& buf);
    void set_num_odp_detectors()
    { num_odp_detectors = allocated_objects.size(); }
    bool insert_cb_detector(AppId app_id, LuaObject* ud);
    LuaObject* get_cb_detector(AppId app_id);

    lua_State* L;

protected:
    void activate_lua_detectors(const snort::SnortConfig*);
    LuaObject* create_lua_detector(const char* detector_name, bool is_custom,
        const char* detector_filename, bool& has_validate);
    virtual void list_lua_detectors() = 0;

    AppIdContext& ctxt;
    std::list<LuaObject*> allocated_objects;
    size_t num_odp_detectors = 0;
    std::map<AppId, LuaObject*> cb_detectors;
};

class PacketLuaDetectorManager : public LuaDetectorManager
{
public:
    explicit PacketLuaDetectorManager(AppIdContext& appid_ctxt) : LuaDetectorManager(appid_ctxt, false)
    { }
    ~PacketLuaDetectorManager() override
    { free_detector_flow(); }

    void set_detector_flow(DetectorFlow* df)
    { detector_flow = df; }

    DetectorFlow* get_detector_flow() const
    { return detector_flow; }

    void free_detector_flow();

private:
    void list_lua_detectors() override;

    DetectorFlow* detector_flow = nullptr;
};

class ControlLuaDetectorManager : public LuaDetectorManager
{
public:
    explicit ControlLuaDetectorManager(AppIdContext&);
    ~ControlLuaDetectorManager() override;
    void initialize(const snort::SnortConfig*) override;

    static std::shared_ptr<LuaDetectorManager> get_packet_lua_detector_manager();
    static void clear_lua_detector_mgrs();
    static void cleanup_after_swap();

    void set_ignore_chp_cleanup()
    {
        ignore_chp_cleanup = true;
    }

private:
    static std::vector<std::shared_ptr<PacketLuaDetectorManager>> lua_detector_mgr_list;

    void initialize_lua_detectors();
    void load_lua_detectors(const char* path, bool is_custom);
    void list_lua_detectors() override;

    bool ignore_chp_cleanup = false;
};

#endif

