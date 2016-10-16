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

// lua_detector_module.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lua_detector_module.h"

#include <glob.h>
#include <libgen.h>
#include <lua.hpp>
#include "lua/lua.h"

#include "appid_config.h"
#include "lua_detector_util.h"
#include "lua_detector_api.h"
#include "lua_detector_flow_api.h"
#include "detector_plugins/detector_http.h"
#include "main/snort_debug.h"
#include "utils/util.h"
#include "utils/sflsq.h"
#include "log/messages.h"

#define MAX_LUA_DETECTOR_FILENAME_LEN 1024
#define MAX_DEFAULT_NUM_LUA_TRACKERS  10000
#define AVG_LUA_TRACKER_SIZE_IN_BYTES 740
#define MAX_MEMORY_FOR_LUA_DETECTORS (512 * 1024 * 1024)

static THREAD_LOCAL LuaDetectorManager* lua_detector_mgr;
static THREAD_LOCAL SF_LIST allocated_detector_flow_list;

static inline bool get_lua_field(lua_State* L, int table, const char* field, std::string& out)
{
    lua_getfield(L, table, field);
    bool result = lua_isstring(L, -1);
    if ( result )
        out = lua_tostring(L, -1);

    lua_pop(L, 1);
    return result;
}

static inline bool get_lua_field(lua_State* L, int table, const char* field, int& out)
{
    lua_getfield(L, table, field);
    bool result = lua_isnumber(L, -1);
    if ( result )
        out = lua_tointeger(L, -1);
    else
        out = 0;

    lua_pop(L, 1);
    return result;
}

static inline bool get_lua_field(lua_State* L, int table, const char* field, IpProtocol& out)
{
    lua_getfield(L, table, field);
    bool result = lua_isnumber(L, -1);
    if ( result )
        out = (IpProtocol)lua_tointeger(L, -1);
    else
        out = IpProtocol::PROTO_NOT_SET;

    lua_pop(L, 1);
    return result;
}

static lua_State* create_lua_state(AppIdModuleConfig* mod_config)
{
    auto L = luaL_newstate();
    luaL_openlibs(L);

    register_detector(L);
    lua_pop(L, 1);          // After registration the methods are still on the stack, remove them

    register_detector_flow_api(L);
    lua_pop(L, 1);

    /*The garbage-collector pause controls how long the collector waits before
      starting a new cycle. Larger values make the collector less aggressive.
      Values smaller than 100 mean the collector will not wait to start a new
      cycle. A value of 200 means that the collector waits for the total memory
      in use to double before starting a new cycle. */
    lua_gc(L, LUA_GCSETPAUSE, 100);

    /*The step multiplier controls the relative speed of the collector relative
      to memory allocation. Larger values make the collector more aggressive
      but also increase the size of each incremental step. Values smaller than
      100 make the collector too slow and can result in the collector never
      finishing a cycle. The default, 200, means that the collector runs at
      "twice" the speed of memory allocation. */
    lua_gc(L, LUA_GCSETSTEPMUL, 200);

    char new_lua_path[PATH_MAX];
    lua_getglobal(L, "package");
    lua_getfield(L, -1, "path");
    const char* cur_lua_path = lua_tostring(L, -1);
    if (cur_lua_path && (strlen(cur_lua_path)))
    {
        snprintf(new_lua_path, sizeof(new_lua_path) - 1,
            "%s;%s/odp/libs/?.lua;%s/custom/libs/?.lua",
            cur_lua_path, mod_config->app_detector_dir, mod_config->app_detector_dir);
    }
    else
    {
        snprintf(new_lua_path, sizeof(new_lua_path) - 1, "%s/odp/libs/?.lua;%s/custom/libs/?.lua",
            mod_config->app_detector_dir, mod_config->app_detector_dir);
    }

    lua_pop(L, 1);
    lua_pushstring(L, new_lua_path);
    lua_setfield(L, -2, "path");
    lua_pop(L, 1);

    return L;
}

LuaDetectorManager::LuaDetectorManager(AppIdConfig& config) :
    config(config)
{
    init_chp_glossary();
    sflist_init(&allocated_detector_flow_list);
    allocated_detectors.clear();
}

LuaDetectorManager::~LuaDetectorManager()
{
    for ( auto& detector : allocated_detectors )
    {
        auto L = detector->my_lua_state;

        lua_getglobal(L, detector->package_info.cleanFunctionName.c_str());
        if ( lua_isfunction(L, -1) )
        {
            /*first parameter is DetectorUserData */
            lua_rawgeti(L, LUA_REGISTRYINDEX, detector->detector_user_data_ref);
            if ( lua_pcall(L, 1, 1, 0) )
            {
                ErrorMessage("Could not cleanup the %s client app element: %s\n",
                    detector->package_info.name.c_str(), lua_tostring(L, -1));
            }
        }
    }

    sflist_static_free_all(&allocated_detector_flow_list, free_detector_flow);
    allocated_detectors.clear();
    free_chp_glossary();
}

void LuaDetectorManager::initialize(AppIdConfig& config)
{
    static bool lua_detectors_listed = false;

    lua_detector_mgr = new LuaDetectorManager(config);
    lua_detector_mgr->initialize_lua_detectors();
    lua_detector_mgr->activate_lua_detectors();
    if (config.mod_config->debug && !lua_detectors_listed)
    {
        lua_detector_mgr->list_lua_detectors();
        lua_detectors_listed = false;
    }
}

void LuaDetectorManager::terminate()
{
    delete lua_detector_mgr;
}

void LuaDetectorManager::add_detector_flow(DetectorFlow* df)
{
    sflist_add_tail(&allocated_detector_flow_list, df);
}

void LuaDetectorManager::free_detector_flows()
{
    sflist_static_free_all(&allocated_detector_flow_list, free_detector_flow);
}

/**calculates Number of flow and host tracker entries for Lua detectors, given amount
 * of memory allocated to RNA (fraction of total system memory) and number of detectors
 * loaded in database. Calculations are based on CAICCI detector and observing memory
 * consumption per tracker.
 * @param rnaMemory - total memory RNA is allowed to use. This is calculated as a fraction of
 * total system memory.
 * @param numDetectors - number of lua detectors present in database.
 */
static inline void set_lua_tracker_size(lua_State* L, uint32_t numTrackers)
{
    /*change flow tracker size according to available memory calculation */
    lua_getglobal(L, "hostServiceTrackerModule");
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, "setHostServiceTrackerSize");
        if (lua_isfunction(L, -1))
        {
            lua_pushinteger (L, numTrackers);
            if (lua_pcall(L, 1, 0, 0) != 0)
                ErrorMessage("Error activating lua detector. Setting tracker size to %u failed.\n",
                    numTrackers);
        }
    }
    else
    {
        DebugMessage(DEBUG_LOG, "hostServiceTrackerModule.setHostServiceTrackerSize not found");
    }

    lua_pop(L, 1);

    // change flow tracker size according to available memory calculation
    lua_getglobal(L, "flowTrackerModule");
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, "setFlowTrackerSize");
        if (lua_isfunction(L, -1))
        {
            lua_pushinteger (L, numTrackers);
            if (lua_pcall(L, 1, 0, 0) != 0)
                ErrorMessage("error setting tracker size");
        }
    }
    else
    {
        DebugMessage(DEBUG_LOG, "flowTrackerModule.setFlowTrackerSize not found");
    }

    lua_pop(L, 1);
}

static inline uint32_t compute_lua_tracker_size(uint64_t rnaMemory, uint32_t numDetectors)
{
    uint64_t detectorMemory = (rnaMemory / 8);
    unsigned numTrackers;

    if (!numDetectors)
        numDetectors = 1;
    numTrackers = (detectorMemory / AVG_LUA_TRACKER_SIZE_IN_BYTES) / numDetectors;
    return (numTrackers > MAX_DEFAULT_NUM_LUA_TRACKERS) ? MAX_DEFAULT_NUM_LUA_TRACKERS :
           numTrackers;
}

// FIXIT-M lifetime of detector is easy to misuse with this idiom
// Leaves 1 value (the Detector userdata) at the top of the stack
static LuaDetector* create_lua_detector(lua_State* L, const char* detectorName, bool is_custom)
{
    LuaDetector* detector = nullptr;
    std::string detector_name;
    IpProtocol proto = IpProtocol::PROTO_NOT_SET;

    Lua::ManageStack mgr(L);
    lua_getglobal(L, "DetectorPackageInfo");
    get_lua_field(L, -1, "name", detector_name);
    if ( !get_lua_field(L, -1, "proto", proto) )
    {
        ErrorMessage("DetectorPackageInfo field 'proto' is not a number\n");
        return nullptr;
    }

    if ( lua_isnil(L, -1) )
        return nullptr;

    lua_getfield(L, -1, "client");
    if ( lua_istable(L, -1) )
    {
        LuaClientDetector* cd = new LuaClientDetector(&ClientDiscovery::get_instance(),
            detectorName, proto);
        cd->is_client = true;
        cd->set_custom_detector(is_custom);
        cd->set_minimum_matches(cd->package_info.minimum_matches);
        cd->package_info.client_detector = true;
        get_lua_field(L, -1, "init", cd->package_info.initFunctionName);
        get_lua_field(L, -1, "clean", cd->package_info.cleanFunctionName);
        get_lua_field(L, -1, "validate", cd->package_info.validateFunctionName);
        get_lua_field(L, -1, "minimum_matches", cd->package_info.minimum_matches);
        cd->package_info.name = detector_name;
        detector = cd;
        lua_pop(L, 1);      // pop client table
    }
    else
    {
        lua_pop(L, 1);      // pop client table

        lua_getfield(L, -1, "server");
        if ( lua_istable(L, -1) )
        {
            LuaServiceDetector* sd = new LuaServiceDetector(&ServiceDiscovery::get_instance(),
                detectorName, proto);
            sd->is_client = false;
            sd->set_custom_detector(is_custom);
            sd->service_id = APP_ID_UNKNOWN;
            sd->package_info.client_detector = false;
            get_lua_field(L, -1, "init", sd->package_info.initFunctionName);
            get_lua_field(L, -1, "clean", sd->package_info.cleanFunctionName);
            get_lua_field(L, -1, "validate", sd->package_info.validateFunctionName);
            get_lua_field(L, -1, "minimum_matches", sd->package_info.minimum_matches);
            sd->package_info.name = detector_name;
            detector = sd;
        }

        lua_pop(L, 1);        // pop server table
    }

    lua_pop(L, 1);  // pop DetectorPackageInfo table

    if ( detector )
    {
        detector->my_lua_state = L;
        UserData<LuaDetector>::push(L, DETECTOR, detector);

        // add a lua reference so the detector doesn't get garbage-collected
        lua_pushvalue(L, -1);
        detector->detector_user_data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }

    return detector;
}

void LuaDetectorManager::load_detector(char* detector_filename, bool isCustom)
{
    char detectorName[MAX_LUA_DETECTOR_FILENAME_LEN];

    lua_State* L = create_lua_state(config.mod_config);
    if ( !L )
    {
        ErrorMessage("can not create new luaState");
        return;
    }

    if ( luaL_loadfile(L, detector_filename) || lua_pcall(L, 0, 0, 0) )
    {
        ErrorMessage("Error loading Lua detector: %s : %s\n", detector_filename, lua_tostring(L,
            -1));
        lua_close(L);
        return;
    }

    snprintf(detectorName, MAX_LUA_DETECTOR_FILENAME_LEN, "%s_%s",
        (isCustom ? "custom" : "cisco"), basename(detector_filename));
    LuaDetector* detector = create_lua_detector(L, detectorName, isCustom);
    allocated_detectors.push_front(detector);
    num_lua_detectors++;

    DebugFormat(DEBUG_LOG,"Loaded detector %s\n", detectorName);
}

void LuaDetectorManager::load_lua_detectors(const char* path, bool isCustom)
{
    char pattern[PATH_MAX];
    snprintf(pattern, sizeof(pattern), "%s/*", path);
    glob_t globs;

    memset(&globs, 0, sizeof(globs));
    int rval = glob(pattern, 0, nullptr, &globs);
    if (rval == 0 )
    {
        for (unsigned n = 0; n < globs.gl_pathc; n++)
            load_detector(globs.gl_pathv[n], isCustom);

        globfree(&globs);
    }
    else if (rval == GLOB_NOMATCH)
        ParseWarning(WARN_CONF, "No lua detectors found in directory '%s'\n", pattern);
    else
        ParseWarning(WARN_CONF, "Error reading lua detectors directory '%s'. Error Code: %d\n",
            pattern, rval);
}

void LuaDetectorManager::initialize_lua_detectors()
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/odp/lua", config.mod_config->app_detector_dir);
    load_lua_detectors(path, false);
    snprintf(path, sizeof(path), "%s/custom/lua", config.mod_config->app_detector_dir);
    load_lua_detectors(path, true);
}

void LuaDetectorManager::activate_lua_detectors()
{
    for ( auto ld : allocated_detectors )
    {
        auto detector = static_cast<LuaClientDetector*>(ld);
        auto L = detector->my_lua_state;

        lua_getglobal(L, detector->package_info.initFunctionName.c_str());
        if (!lua_isfunction(L, -1))
        {
            ErrorMessage("Detector %s: does not contain DetectorInit() function\n",
                detector->get_name().c_str());
            return;
        }

        /*first parameter is DetectorUserData */
        lua_rawgeti(L, LUA_REGISTRYINDEX, detector->detector_user_data_ref);

        /*second parameter is a table containing configuration stuff. */
        // ... which is empty.???
        lua_newtable(L);
        if ( lua_pcall(L, 2, 1, 0) )
            ErrorMessage("Could not initialize the %s client app element: %s\n",
                detector->get_name().c_str(), lua_tostring(L, -1));

        ++num_active_lua_detectors;
    }

    lua_tracker_size = compute_lua_tracker_size(MAX_MEMORY_FOR_LUA_DETECTORS,
        num_active_lua_detectors);
    for ( auto& detector : allocated_detectors )
        set_lua_tracker_size(detector->my_lua_state, lua_tracker_size);
}

void LuaDetectorManager::list_lua_detectors()
{
    // FIXIT-L make these perf counters
    size_t totalMem = 0;
    size_t mem;

    if ( allocated_detectors.empty() )
        return;

    LogMessage("Lua Detector Stats:\n");

    for ( auto& ld : allocated_detectors )
    {
        const char* name;
        mem = lua_gc(ld->my_lua_state, LUA_GCCOUNT, 0);
        totalMem += mem;
        if ( ld->is_client )
            name = static_cast<LuaClientDetector*>(ld)->get_name().c_str();
        else
            name = static_cast<LuaServiceDetector*>(ld)->get_name().c_str();

        LogMessage("\tDetector %s: Lua Memory usage %zu kb\n", name, mem);
    }

    LogMessage("Lua Stats total detectors: %zu\n", allocated_detectors.size());
    LogMessage("Lua Stats total memory usage %zu kb\n", totalMem);
}

