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

// lua_detector_module.h author Sourcefire Inc.

#ifndef LUA_DETECTOR_MODULE_H
#define LUA_DETECTOR_MODULE_H

#include <cstdint>
#include <list>
#include <string>

#include <lua.hpp>
#include <lua/lua.h>

#include "main/thread.h"
#include "protocols/protocol_ids.h"

class AppIdConfig;
class AppIdDetector;
struct DetectorFlow;
class LuaObject;

bool get_lua_field(lua_State* L, int table, const char* field, std::string& out);
bool get_lua_field(lua_State* L, int table, const char* field, int& out);
bool get_lua_field(lua_State* L, int table, const char* field, IpProtocol& out);

class LuaDetectorManager
{
public:
    LuaDetectorManager(AppIdConfig&, int);
    ~LuaDetectorManager();
    static void initialize(AppIdConfig&, int is_control=0);
    static void terminate();
    static void add_detector_flow(DetectorFlow*);
    static void free_detector_flows();
    // FIXIT-M: RELOAD - When reload is supported, move this variable to a separate location
    lua_State* L;

private:
    void initialize_lua_detectors();
    void activate_lua_detectors();
    void list_lua_detectors();
    void load_detector(char* detectorName, bool isCustom);
    void load_lua_detectors(const char* path, bool isCustom);

    AppIdConfig& config;
    std::list<LuaObject*> allocated_objects;
    size_t num_odp_detectors = 0;
};

extern THREAD_LOCAL LuaDetectorManager* lua_detector_mgr;

#endif

