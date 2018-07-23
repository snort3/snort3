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

// lua_detector_module.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lua_detector_module.h"

#include <glob.h>
#include <libgen.h>

#include <cassert>

#include "appid_config.h"
#include "lua_detector_util.h"
#include "lua_detector_api.h"
#include "lua_detector_flow_api.h"
#include "detector_plugins/detector_http.h"
#include "utils/util.h"
#include "utils/sflsq.h"
#include "log/messages.h"

using namespace snort;

#define MAX_LUA_DETECTOR_FILENAME_LEN 1024
#define MAX_DEFAULT_NUM_LUA_TRACKERS  10000
#define AVG_LUA_TRACKER_SIZE_IN_BYTES 740
#define MAX_MEMORY_FOR_LUA_DETECTORS (512 * 1024 * 1024)

THREAD_LOCAL LuaDetectorManager* lua_detector_mgr = nullptr;
static THREAD_LOCAL SF_LIST allocated_detector_flow_list;

bool get_lua_field(lua_State* L, int table, const char* field, std::string& out)
{
    lua_getfield(L, table, field);
    bool result = lua_isstring(L, -1);
    if ( result )
        out = lua_tostring(L, -1);

    lua_pop(L, 1);
    return result;
}

bool get_lua_field(lua_State* L, int table, const char* field, int& out)
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

bool get_lua_field(lua_State* L, int table, const char* field, IpProtocol& out)
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

inline void set_control(lua_State* L, int is_control)
{
    lua_pushboolean (L, is_control); // push flag to stack 
    lua_setglobal(L, "is_control"); // create global key to store value
    lua_pop(L, 1);
}

static lua_State* create_lua_state(const AppIdModuleConfig* mod_config, int is_control)
{
    auto L = luaL_newstate();

    if ( !L )
        return L;

    luaL_openlibs(L);

    set_control(L, is_control);
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

LuaDetectorManager::LuaDetectorManager(AppIdConfig& config, int is_control) :
    config(config)
{
    sflist_init(&allocated_detector_flow_list);
    allocated_objects.clear();
    L = create_lua_state(config.mod_config, is_control);
    if (is_control == 1)
        init_chp_glossary();
}

LuaDetectorManager::~LuaDetectorManager()
{
    auto L = lua_detector_mgr? lua_detector_mgr->L : nullptr;
    if (L)
    {
        if (init(L))
            free_chp_glossary();

        for ( auto& lua_object : allocated_objects )
        {
            LuaStateDescriptor* lsd = lua_object->validate_lua_state(false);

            lua_getfield(L, LUA_REGISTRYINDEX, lsd->package_info.name.c_str());
            lua_getfield(L, -1, lsd->package_info.cleanFunctionName.c_str());
            if ( lua_isfunction(L, -1) )
            {
                //FIXIT-M: RELOAD - use lua references to get user data object from stack
                //first parameter is DetectorUserData
                std::string name = lsd->package_info.name + "_";
                lua_getglobal(L, name.c_str());

                if ( lua_pcall(L, 1, 1, 0) )
                {
                    ErrorMessage("Could not cleanup the %s client app element: %s\n",
                        lsd->package_info.name.c_str(), lua_tostring(L, -1));
                }
            }
	    delete lua_object;
        }
        lua_close(L);
    }

    sflist_static_free_all(&allocated_detector_flow_list, free_detector_flow);
    allocated_objects.clear();
}

void LuaDetectorManager::initialize(AppIdConfig& config, int is_control)
{
    // FIXIT-M: RELOAD - When reload is supported, remove this line which prevents re-initialize
    if (lua_detector_mgr)
        return;

    lua_detector_mgr = new LuaDetectorManager(config, is_control);
    if (!lua_detector_mgr->L)
        FatalError("Error - appid: can not create new luaState, instance=%u\n", get_instance_id());

    lua_detector_mgr->initialize_lua_detectors();
    lua_detector_mgr->activate_lua_detectors();

    if (config.mod_config->debug)
        lua_detector_mgr->list_lua_detectors();
}

void LuaDetectorManager::terminate()
{
    if (!lua_detector_mgr)
        return;

    delete lua_detector_mgr;
    lua_detector_mgr = nullptr;
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
    lua_getfield(L, -1, "hostServiceTrackerModule");
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, "setHostServiceTrackerSize");
        if (lua_isfunction(L, -1))
        {
            lua_pushinteger (L, numTrackers);
            if (lua_pcall(L, 1, 0, 0) != 0 and init(L))
                ErrorMessage("Error - appid: activating lua detector. "
                    "Setting tracker size to %u failed.\n", numTrackers);
        }
    }

    lua_pop(L, 1);

    // change flow tracker size according to available memory calculation
    lua_getfield(L, -1, "flowTrackerModule");
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, "setFlowTrackerSize");
        if (lua_isfunction(L, -1))
        {
            lua_pushinteger (L, numTrackers);
            if (lua_pcall(L, 1, 0, 0) != 0 and init(L))
                ErrorMessage("Error - appid: setting tracker size\n");
        }
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

// Leaves 1 value (the Detector userdata) at the top of the stack when succeeds
static LuaObject* create_lua_detector(lua_State* L, const char* detector_name, bool is_custom)
{
    std::string log_name;
    IpProtocol proto = IpProtocol::PROTO_NOT_SET;

    Lua::ManageStack mgr(L);
    lua_getfield(L, LUA_REGISTRYINDEX, detector_name);

    lua_getfield(L, -1, "DetectorPackageInfo");
    if (!lua_istable(L, -1))
    {
        if (init(L)) // for control thread only
            ErrorMessage("Error - appid: can not read DetectorPackageInfo table from %s\n",
                detector_name);
        if (!lua_isnil(L, -1)) // pop DetectorPackageInfo index if it was pushed
            lua_pop(L, 1);
        return nullptr;
    }

    if (!get_lua_field(L, -1, "name", log_name))
    {
        if (init(L))
            ErrorMessage("Error - appid: can not read DetectorPackageInfo field 'name' from %s\n",
                detector_name);
        lua_pop(L, 1);
        return nullptr;
    }

    if (!get_lua_field(L, -1, "proto", proto))
    {
        if (init(L))
            ErrorMessage("Error - appid: can not read DetectorPackageInfo field 'proto' from %s\n",
                detector_name);
        lua_pop(L, 1);
        return nullptr;
    }

    lua_getfield(L, -1, "client");
    if ( lua_istable(L, -1) )
    {
        return new LuaClientObject(&ClientDiscovery::get_instance(),
            detector_name, log_name, is_custom, proto, L);
    }
    else
    {
        lua_pop(L, 1);      // pop client table

        lua_getfield(L, -1, "server");
        if ( lua_istable(L, -1) )
        {
            return new LuaServiceObject(&ServiceDiscovery::get_instance(),
                detector_name, log_name, is_custom, proto, L);
        }
        else if (init(L))
            ErrorMessage("Error - appid: can not read DetectorPackageInfo field"
                " 'client' or 'server' from %s\n", detector_name);

        lua_pop(L, 1);        // pop server table
    }

    lua_pop(L, 1);  // pop DetectorPackageInfo table

    return nullptr;
}

void LuaDetectorManager::load_detector(char* detector_filename, bool isCustom)
{
    if (luaL_loadfile(L, detector_filename))
    {
        if (init(L))
            ErrorMessage("Error - appid: can not load Lua detector, %s\n", lua_tostring(L, -1));
        return;
    }

    // FIXIT-M: RELOAD - When reload is supported, we might need to make these unique
    // from one reload to the next reload, e.g., "odp_FOO_1", "odp_FOO_2", etc.
    // Alternatively, conflicts between reload may be avoided if a new lua state is
    // created separately, then swapped and free old state.
    char detectorName[MAX_LUA_DETECTOR_FILENAME_LEN];
    snprintf(detectorName, MAX_LUA_DETECTOR_FILENAME_LEN, "%s_%s",
        (isCustom ? "custom" : "odp"), basename(detector_filename));

    // create a new function environment and store it in the registry
    lua_newtable(L); // create _ENV tables
    lua_newtable(L); // create metatable
    lua_getglobal(L, "_G"); // push the value of the global name
    lua_setfield(L, -2, "__index"); // pop and get the global table
    lua_setmetatable(L, -2); // pop and set global as the metatable
    lua_pushvalue(L, -1); // push a copy of the element on the top
    lua_setfield(L, LUA_REGISTRYINDEX, detectorName); // push to registry with unique name

    // set the environment for the loaded script and execute it
    lua_setfenv(L, -2);
    if (lua_pcall(L, 0, 0, 0))
    {
        ErrorMessage("Error - appid: can not set env of Lua detector %s : %s\n",
            detector_filename, lua_tostring(L, -1));
        return;
    }

    LuaObject* lua_object = create_lua_detector(L, detectorName, isCustom);
    if (lua_object)
        allocated_objects.push_front(lua_object);
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
        ParseWarning(WARN_CONF, "appid: no lua detectors found in directory '%s'", pattern);
    else
        ParseWarning(WARN_CONF,
            "appid: error reading lua detectors directory '%s'. Error Code: %d",
            pattern, rval);
}

void LuaDetectorManager::initialize_lua_detectors()
{
    char path[PATH_MAX];
    const char* dir = config.mod_config->app_detector_dir;

    if ( !dir )
        return;

    snprintf(path, sizeof(path), "%s/odp/lua", dir);
    load_lua_detectors(path, false);
    num_odp_detectors = allocated_objects.size();

    snprintf(path, sizeof(path), "%s/custom/lua", dir);
    load_lua_detectors(path, true);
}

void LuaDetectorManager::activate_lua_detectors()
{
    uint32_t lua_tracker_size = compute_lua_tracker_size(MAX_MEMORY_FOR_LUA_DETECTORS,
        allocated_objects.size());
    std::list<LuaObject*>::iterator lo = allocated_objects.begin();

    while (lo != allocated_objects.end())
    {
        LuaStateDescriptor* lsd = (*lo)->validate_lua_state(false);
        lua_getfield(L, LUA_REGISTRYINDEX, lsd->package_info.name.c_str());
        lua_getfield(L, -1, lsd->package_info.initFunctionName.c_str());
        if (!lua_isfunction(L, -1))
        {
            if (init(L))
                ErrorMessage("Error - appid: can not load DetectorInit function from %s\n",
                    (*lo)->get_detector()->get_name().c_str());
            if (!(*lo)->get_detector()->is_custom_detector())
                num_odp_detectors--;
            delete *lo;
            lo = allocated_objects.erase(lo);
            continue;
        }

        //FIXIT-M: RELOAD - use lua references to get user data object from stack
        /*first parameter is DetectorUserData */
        std::string name = lsd->package_info.name + "_";
	    lua_getglobal(L, name.c_str());

        /*second parameter is a table containing configuration stuff. */
        lua_newtable(L);
        if (lua_pcall(L, 2, 1, 0))
        {
            if (init(L))
                ErrorMessage("Error - appid: can not run DetectorInit, %s\n", lua_tostring(L, -1));
            if (!(*lo)->get_detector()->is_custom_detector())
                num_odp_detectors--;
            delete *lo;
            lo = allocated_objects.erase(lo);
            continue;
        }

        lua_getfield(L, LUA_REGISTRYINDEX, lsd->package_info.name.c_str());
        set_lua_tracker_size(L, lua_tracker_size);
        ++lo;
    }
}

void LuaDetectorManager::list_lua_detectors()
{
    LogMessage("AppId Lua-Detector Stats: instance %u, odp detectors %zu, custom detectors %zu,"
        " total memory %d kb\n", get_instance_id(), num_odp_detectors,
        (allocated_objects.size() - num_odp_detectors), lua_gc(L, LUA_GCCOUNT, 0));
}

