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

// lua_detector_module.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lua_detector_module.h"

#include <glob.h>
#include <libgen.h>

#include <cassert>
#include <cstring>
#include <fstream>

#include "log/messages.h"
#include "main/snort_config.h"

#include "appid_config.h"
#include "appid_debug.h"
#include "appid_inspector.h"
#include "lua_detector_util.h"
#include "lua_detector_api.h"
#include "lua_detector_flow_api.h"

using namespace snort;
using namespace std;

#define MIN_LUA_DETECTOR_FILE_SIZE 50
#define MAX_LUA_DETECTOR_FILE_SIZE 256000
#define MAX_LUA_DETECTOR_FILENAME_LEN 1024
#define MAX_DEFAULT_NUM_LUA_TRACKERS  10000
#define AVG_LUA_TRACKER_SIZE_IN_BYTES 740
#define MAX_MEMORY_FOR_LUA_DETECTORS (512 * 1024 * 1024)
#define OPEN_DETECTOR_PACKAGE_VERSION_FILE "version.conf"
#define OPEN_DETECTOR_PACKAGE_VERSION "VERSION="

static vector<LuaDetectorManager*> lua_detector_mgr_list;
static unordered_set<string> lua_detectors_w_validate;

bool get_lua_field(lua_State* L, int table, const char* field, string& out)
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

inline void set_control(lua_State* L, bool is_control)
{
    lua_pushboolean (L, is_control ? 1 : 0); // push flag to stack
    lua_setglobal(L, "is_control"); // create global key to store value
}

static lua_State* create_lua_state(const AppIdConfig& config, bool is_control)
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
            cur_lua_path, config.app_detector_dir, config.app_detector_dir);
    }
    else
    {
        snprintf(new_lua_path, sizeof(new_lua_path) - 1, "%s/odp/libs/?.lua;%s/custom/libs/?.lua",
            config.app_detector_dir, config.app_detector_dir);
    }

    lua_pop(L, 1);
    lua_pushstring(L, new_lua_path);
    lua_setfield(L, -2, "path");
    lua_pop(L, 1);

    return L;
}

static void scan_and_print_odp_version(const char* app_detector_dir)
{
    char odp_version_path[PATH_MAX];
    snprintf(odp_version_path, sizeof(odp_version_path) - 1, "%s/odp/%s",
            app_detector_dir, OPEN_DETECTOR_PACKAGE_VERSION_FILE);

    std::ifstream version_file(odp_version_path);
    if (!version_file.is_open())
        return;
    std::string line;
    while (std::getline(version_file, line))
    {
        if (line.size() <= strlen(OPEN_DETECTOR_PACKAGE_VERSION))
            continue;
        if (line.find(OPEN_DETECTOR_PACKAGE_VERSION) == 0)
        {
            line = line.substr(strlen(OPEN_DETECTOR_PACKAGE_VERSION));
            appid_log(nullptr, TRACE_INFO_LEVEL, "AppId Open Detector Package(ODP) Version: %s\n", line.c_str());
            break;
        }
    }
    version_file.close();
}

LuaDetectorManager::LuaDetectorManager(AppIdContext& ctxt, bool is_control) :
    ctxt(ctxt)
{
    allocated_objects.clear();
    cb_detectors.clear();
    L = create_lua_state(ctxt.config, is_control);
    if (is_control)
        init_chp_glossary();
}

LuaDetectorManager::~LuaDetectorManager()
{
    if (lua_gettop(L))
        appid_log(nullptr, TRACE_WARNING_LEVEL, "appid: leak of %d lua stack elements before detector unload\n",
            lua_gettop(L));

    if (L)
    {
        if (init(L) and !ignore_chp_cleanup)
            free_current_chp_glossary();

        for ( auto& lua_object : allocated_objects )
        {
            LuaStateDescriptor* lsd = lua_object->validate_lua_state(false);

            lua_getfield(L, LUA_REGISTRYINDEX, lsd->package_info.name.c_str());
            lua_getfield(L, -1, lsd->package_info.cleanFunctionName.c_str());
            if ( lua_isfunction(L, -1) )
            {
                string name = lsd->package_info.name + "_";
                lua_getglobal(L, name.c_str());

                if ( lua_pcall(L, 1, 1, 0) )
                {
                    appid_log(nullptr, TRACE_ERROR_LEVEL, "Could not cleanup the %s client app element: %s\n",
                        lsd->package_info.name.c_str(), lua_tostring(L, -1));
                }
            }
            lua_settop(L, 0);
            delete lua_object;
        }
        lua_close(L);
    }

    if (detector_flow)
        free_detector_flow();
    allocated_objects.clear();
    cb_detectors.clear(); // do not free Lua objects in cb_detectors
}

void LuaDetectorManager::initialize(const SnortConfig* sc, AppIdContext& ctxt, bool is_control,
    bool reload)
{
    LuaDetectorManager* lua_detector_mgr = new LuaDetectorManager(ctxt, is_control);
    odp_thread_local_ctxt->set_lua_detector_mgr(*lua_detector_mgr);

    if (!lua_detector_mgr->L)
        appid_log(nullptr, is_control? TRACE_CRITICAL_LEVEL : TRACE_ERROR_LEVEL,
            "Error - appid: can not create new luaState, instance=%u\n", get_instance_id());

    if (reload)
    {
        appid_log(nullptr, TRACE_INFO_LEVEL, "AppId Lua-Detectors : loading lua detectors in control thread\n");
        unsigned max_threads = ThreadConfig::get_instance_max();
        for (unsigned i = 0 ; i < max_threads; i++)
        {
            lua_detector_mgr_list.emplace_back(new LuaDetectorManager(ctxt, 0));

            if (!lua_detector_mgr_list[i]->L)
                appid_log(nullptr, TRACE_CRITICAL_LEVEL, "Error - appid: can not create new luaState, instance=%u\n", i);

        }
    }

    lua_detector_mgr->initialize_lua_detectors(is_control, reload);
    lua_detector_mgr->activate_lua_detectors(sc);

    if (SnortConfig::log_verbose())
        scan_and_print_odp_version(ctxt.config.app_detector_dir);


    if (ctxt.config.list_odp_detectors or SnortConfig::log_verbose())
        lua_detector_mgr->list_lua_detectors();
}

void LuaDetectorManager::init_thread_manager(const SnortConfig* sc, const AppIdContext& ctxt)
{
    LuaDetectorManager* lua_detector_mgr = lua_detector_mgr_list[get_instance_id()];
    odp_thread_local_ctxt->set_lua_detector_mgr(*lua_detector_mgr);
    lua_detector_mgr->activate_lua_detectors(sc);
    if (ctxt.config.list_odp_detectors)
        lua_detector_mgr->list_lua_detectors();
}

void LuaDetectorManager::cleanup_after_swap()
{
    free_old_chp_glossary();
}

void LuaDetectorManager::clear_lua_detector_mgrs()
{
    lua_detector_mgr_list.clear();
}

void LuaDetectorManager::free_detector_flow()
{
    delete detector_flow;
    detector_flow = nullptr;
}

bool LuaDetectorManager::insert_cb_detector(AppId app_id, LuaObject* cb_detector)
{
    if (cb_detectors.find(app_id) != cb_detectors.end())
        return false;
    else
        cb_detectors[app_id] = cb_detector;

    return true;
}

LuaObject* LuaDetectorManager::get_cb_detector(AppId app_id)
{
    auto it = cb_detectors.find(app_id);

    if (it != cb_detectors.end())
        return it->second;

    return nullptr;
}

/**calculates Number of flow and host tracker entries for Lua detectors, given amount
 * of memory allocated to RNA (fraction of total system memory) and number of detectors
 * loaded in database. Calculations are based on CAICCI detector and observing memory
 * consumption per tracker.
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
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: activating lua detector. "
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
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: setting tracker size\n");
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
LuaObject* LuaDetectorManager::create_lua_detector(const char* detector_name,
    bool is_custom, const char* detector_filename, bool& has_validate)
{
    string log_name;
    IpProtocol proto = IpProtocol::PROTO_NOT_SET;

    has_validate = false;

    Lua::ManageStack mgr(L);
    lua_getfield(L, LUA_REGISTRYINDEX, detector_name);

    lua_getfield(L, -1, "DetectorPackageInfo");
    if (!lua_istable(L, -1))
    {
        if (init(L)) // for control thread only
        {
            ifstream detector_file;

            // Skip file if empty
            detector_file.open(detector_filename);
            detector_file >> ws;
            int c = detector_file.peek();
            detector_file.close();
            if (c != EOF)
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: can not read DetectorPackageInfo table from %s\n",
                    detector_name);
        }
        if (!lua_isnil(L, -1)) // pop DetectorPackageInfo index if it was pushed
            lua_pop(L, 1);
        return nullptr;
    }

    if (!get_lua_field(L, -1, "name", log_name))
    {
        if (init(L))
            appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: can not read DetectorPackageInfo field 'name' from %s\n",
                detector_name);
        lua_pop(L, 1);
        return nullptr;
    }

    if (!get_lua_field(L, -1, "proto", proto))
    {
        if (init(L))
            appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: can not read DetectorPackageInfo field 'proto' from %s\n",
                detector_name);
        lua_pop(L, 1);
        return nullptr;
    }

    lua_getfield(L, -1, "client");
    if ( lua_istable(L, -1) )
    {
        return new LuaClientObject(detector_name, log_name, is_custom, proto, L, ctxt.get_odp_ctxt(), has_validate);
    }
    else
    {
        lua_pop(L, 1);      // pop client table

        lua_getfield(L, -1, "server");
        if ( lua_istable(L, -1) )
        {
            has_validate = true;
            return new LuaServiceObject(&ctxt.get_odp_ctxt().get_service_disco_mgr(),
                detector_name, log_name, is_custom, proto, L, ctxt.get_odp_ctxt());
        }
        else if (init(L))
            appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: can not read DetectorPackageInfo field"
                " 'client' or 'server' from %s\n", detector_name);

        lua_pop(L, 1);        // pop server table
    }

    lua_pop(L, 1);  // pop DetectorPackageInfo table

    return nullptr;
}

static int dump(lua_State*, const void* buf,size_t size, void* data)
{
    string* s = static_cast<string*>(data);
    s->append(static_cast<const char*>(buf), size);
    return 0;
}

bool LuaDetectorManager::load_detector(char* detector_filename, bool is_custom, bool is_control, bool reload, string& buf)
{
    if (reload and !buf.empty())
    {
        if (luaL_loadbuffer(L, buf.c_str(), buf.length(), detector_filename))
        {
            if (init(L))
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: can not load Lua detector, %s\n", lua_tostring(L, -1));
            lua_pop(L, 1);
            return false;
        }
    }
    else
    {
        if (!is_control)
        {
            auto iter = lua_detectors_w_validate.find(detector_filename);
            if (iter == lua_detectors_w_validate.end())
                return false;
        }

        if (luaL_loadfile(L, detector_filename))
        {
            if (init(L))
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: can not load Lua detector, %s\n", lua_tostring(L, -1));
            lua_pop(L, 1);
            return false;
        }
        if (reload and lua_dump(L, dump, &buf))
        {
            if (init(L))
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: can not compile Lua detector, %s\n", lua_tostring(L, -1));
            lua_pop(L, 1);
            return false;
        }
    }

    char detectorName[MAX_LUA_DETECTOR_FILENAME_LEN];
#ifdef HAVE_BASENAME_R
    char detector_res[MAX_LUA_DETECTOR_FILENAME_LEN];
    snprintf(detectorName, MAX_LUA_DETECTOR_FILENAME_LEN, "%s_%s",
        (is_custom ? "custom" : "odp"), basename_r(detector_filename, detector_res));
#else
    snprintf(detectorName, MAX_LUA_DETECTOR_FILENAME_LEN, "%s_%s",
        (is_custom ? "custom" : "odp"), basename(detector_filename));
#endif

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
        appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: can not set env of Lua detector %s : %s\n",
            detector_filename, lua_tostring(L, -1));
        lua_pop(L, 1);
        return false;
    }

    bool has_validate;
    LuaObject* lua_object = create_lua_detector(detectorName, is_custom, detector_filename, has_validate);
    if (lua_object)
        allocated_objects.push_front(lua_object);

    return has_validate;
}

void LuaDetectorManager::load_lua_detectors(const char* path, bool is_custom, bool is_control, bool reload)
{
    char pattern[PATH_MAX];
    snprintf(pattern, sizeof(pattern), "%s/*", path);
    glob_t globs;

    memset(&globs, 0, sizeof(globs));
    int rval = glob(pattern, 0, nullptr, &globs);
    if (rval == 0 )
    {
        if (lua_gettop(L))
            appid_log(nullptr, TRACE_WARNING_LEVEL, "appid: leak of %d lua stack elements before detector load\n",
                lua_gettop(L));

        string buf;
        for (unsigned n = 0; n < globs.gl_pathc; n++)
        {
            ifstream file(globs.gl_pathv[n], ios::ate);
            int size = file.tellg();
            //do not load empty lua files
            if (size < MIN_LUA_DETECTOR_FILE_SIZE)
            {
                file.close();
                continue;
            }
            if (size > MAX_LUA_DETECTOR_FILE_SIZE)
            {
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: can not load Lua detector %s : \
                    size exceeded maximum limit\n", globs.gl_pathv[n]);
                file.close();
                continue;
            }
            file.close();

            // In the packet threads, we do not need to load Lua detectors that don't have validate
            // function such as payload_group_*, ssl_group_*, etc. That's because the patterns they
            // register are stored in global tables only in control thread. In packet threads, they
            // do nothing. Skipping loading of these detectors in packet threads saves on the memory
            // used by LuaJIT.

            // Because the code flow for loading Lua detectors is different for initialization vs
            // reload, the LuaJIT memory saving is achieved differently in these two cases.

            // During initialization, load_lua_detectors() gets called for all the threads - first
            // for the control thread and then for the packet threads. Control thread stores the
            // detectors that have validate in lua_detectors_w_validate. Packet thread loads a
            // detector in load_detector() only if it finds the detector in lua_detectors_w_validate.

            // During reload, load_lua_detectors() gets called only for control thread. This
            // function loads detectors for all the packet threads too during reload. It skips
            // loading detectors that don't have validate for packet threads.
            bool has_validate = load_detector(globs.gl_pathv[n], is_custom, is_control, reload, buf);

            if (reload)
            {
                for (auto& lua_detector_mgr : lua_detector_mgr_list)
                {
                    if (has_validate)
                        lua_detector_mgr->load_detector(globs.gl_pathv[n], is_custom, is_control, reload, buf);
                }
                buf.clear();
            }
            else if (is_control and has_validate)
                lua_detectors_w_validate.insert(globs.gl_pathv[n]);
            lua_settop(L, 0);
        }

        globfree(&globs);
    }
    else if (rval == GLOB_NOMATCH)
        ParseWarning(WARN_CONF, "appid: no lua detectors found in directory '%s'", pattern);
    else
        ParseWarning(WARN_CONF,
            "appid: error reading lua detectors directory '%s'. Error Code: %d",
            pattern, rval);
}

void LuaDetectorManager::initialize_lua_detectors(bool is_control, bool reload)
{
    char path[PATH_MAX];
    const char* dir = ctxt.config.app_detector_dir;

    if ( !dir )
        return;

    snprintf(path, sizeof(path), "%s/odp/lua", dir);
    load_lua_detectors(path, false, is_control, reload);
    num_odp_detectors = allocated_objects.size();

    if (reload)
    {
        for (auto& lua_detector_mgr : lua_detector_mgr_list)
            lua_detector_mgr->num_odp_detectors = lua_detector_mgr->allocated_objects.size();
    }
    snprintf(path, sizeof(path), "%s/custom/lua", dir);
    load_lua_detectors(path, true, is_control, reload);
}

void LuaDetectorManager::activate_lua_detectors(const SnortConfig* sc)
{
    uint32_t lua_tracker_size = compute_lua_tracker_size(MAX_MEMORY_FOR_LUA_DETECTORS,
        allocated_objects.size());
    list<LuaObject*>::iterator lo = allocated_objects.begin();

    if (lua_gettop(L))
        appid_log(nullptr, TRACE_WARNING_LEVEL, "appid: leak of %d lua stack elements before detector activate\n",
            lua_gettop(L));

    while (lo != allocated_objects.end())
    {
        LuaStateDescriptor* lsd = (*lo)->validate_lua_state(false);
        lua_getfield(L, LUA_REGISTRYINDEX, lsd->package_info.name.c_str());
        lua_getfield(L, -1, lsd->package_info.initFunctionName.c_str());
        if (!lua_isfunction(L, -1))
        {
            if (init(L))
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: can not load DetectorInit function from %s\n",
                    (*lo)->get_detector()->get_name().c_str());
            if (!(*lo)->get_detector()->is_custom_detector())
                num_odp_detectors--;
            lua_settop(L, 0);
            delete *lo;
            lo = allocated_objects.erase(lo);
            continue;
        }

        /*first parameter is DetectorUserData */
        string name = lsd->package_info.name + "_";
        lua_getglobal(L, name.c_str());

        /*second parameter is a table containing configuration stuff. */
        lua_newtable(L);
        const SnortConfig** sc_ud = static_cast<const SnortConfig**>(lua_newuserdata(L, sizeof(const SnortConfig*)));
        *(sc_ud) = sc;
        lua_setglobal(L, LUA_STATE_GLOBAL_SC_ID);
        if (lua_pcall(L, 2, 1, 0))
        {
            if (init(L))
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Error - appid: can not run DetectorInit, %s\n", lua_tostring(L, -1));
            if (!(*lo)->get_detector()->is_custom_detector())
                num_odp_detectors--;
            lua_settop(L, 0);
            delete *lo;
            lo = allocated_objects.erase(lo);
            continue;
        }
        *(sc_ud) = nullptr;

        lua_getfield(L, LUA_REGISTRYINDEX, lsd->package_info.name.c_str());
        set_lua_tracker_size(L, lua_tracker_size);
        lua_settop(L, 0);
        ++lo;
    }
}

void LuaDetectorManager::list_lua_detectors()
{

    #ifdef REG_TEST
    // Lua memory usage is inconsistent, for ease of testing lets print 0 instead.
    int memory_used_by_lua = 0;
    #else
    int memory_used_by_lua = lua_gc(L, LUA_GCCOUNT, 0);
    #endif

    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId Lua-Detector Stats: instance %u, odp detectors %zu, custom detectors %zu,"
        " total memory %d kb\n", get_instance_id(), num_odp_detectors,
        (allocated_objects.size() - num_odp_detectors), memory_used_by_lua);
}

