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

// lua_detector_module.h author Sourcefire Inc.

#ifndef LUA_DETECTOR_MODULE_H
#define LUA_DETECTOR_MODULE_H

#include <cstdint>
#include <list>

class AppIdConfig;
class LuaDetector;
struct DetectorFlow;

class LuaDetectorManager
{
public:
    LuaDetectorManager(AppIdConfig&);
    ~LuaDetectorManager();
    static void initialize(AppIdConfig&);
    static void terminate();
    static void add_detector_flow(DetectorFlow*);
    static void free_detector_flows();

private:
    void initialize_lua_detectors();
    void activate_lua_detectors();
    void list_lua_detectors();
    void load_detector(char* detectorName, bool isCustom);
    void load_lua_detectors(const char* path, bool isCustom);

    AppIdConfig& config;
    std::list<LuaDetector*> allocated_detectors;

    // FIXIT-L make these perf counters
    uint32_t lua_tracker_size = 0;
    uint32_t num_lua_detectors = 0;
    uint32_t num_active_lua_detectors = 0;
};

#endif

