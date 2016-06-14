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

// lua_detector_module.h author Sourcefire Inc.

#ifndef LUA_DETECTOR_MODULE_H
#define LUA_DETECTOR_MODULE_H

#include <string>

#include "utils/sflsq.h"

class AppIdConfig;

class LuaDetectorModuleManager
{
public:
    // Initializes Lua modules. Open lua and if available LuaJIT libraries, and registers all API modules.
    static void luaModuleInit();
    static void luaModuleFini();

    // Load all Lua modules into a detector list
    //
    // Each RNA detector file in the folder app_id_detector_path is parsed for
    // detector information. If it is a valid detector, a detector data structure
    // is created for it and stored in allocatedDetectorList.
    static void LoadLuaModules(AppIdConfig*);

    // Finalize Lua modules
    // This function should be called after LoadLuaModules(). It sets up proper AppId references
    // and tracker size for all the detectors.
    static void FinalizeLuaModules(AppIdConfig*);

    // Unload Lua modules
    //
    // This function cleans up all the data structures that were created for the Lua detectors
    // in a given AppId context. It should be called after FinalizeLuaModules().
    static void UnloadLuaModules(AppIdConfig*);

    static void add_chunk(const std::string&);
};

void luaModuleInitAllServices();
void luaModuleCleanAllClients();
void luaModuleInitAllClients();
void RNAPndDumpLuaStats();

void luaDetectorsUnload(AppIdConfig*);
void luaDetectorsSetTrackerSize();

extern SF_LIST allocatedFlowList;

#endif

