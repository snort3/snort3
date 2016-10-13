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

// lua_detector_module.cc author Sourcefire Inc.

// supporting Lua detectors in core engine.

#include "lua_detector_module.h"

#include <algorithm>
#include <glob.h>
#include <lua.hpp>
#include <openssl/md5.h>

#include "appid_config.h"
#include "client_plugins/client_app_base.h"
#include "service_plugins/service_base.h"
#include "fw_appid.h" // for lua*PerfStats
#include "hash/sfghash.h"
#include "log/messages.h"
#include "lua/lua.h"
#include "lua_detector_api.h"
#include "lua_detector_flow_api.h"
#include "main/snort_debug.h"
#include "utils/util.h"

#define MD5CONTEXT MD5_CTX

#define MD5INIT    MD5_Init
#define MD5UPDATE  MD5_Update
#define MD5FINAL   MD5_Final
#define MD5DIGEST  MD5

#define MAXPD 1024
#define LUA_DETECTOR_FILENAME_MAX 1024

THREAD_LOCAL SF_LIST allocatedFlowList;  /*list of flows allocated. */

static inline bool match_char_set(char c, const char* set)
{
    while ( *set && *set != c )
        ++set;

    return *set != '\0';
}

static inline const char* find_first_not_of(const char* s, const char* const set)
{
    while ( *s && match_char_set(*s, set) )
        ++s;

    return s;
}

static inline const char* find_first_of(const char* s, const char* const set)
{
    while ( *s && !match_char_set(*s, set) )
        ++s;

    return s;
}

static const char* tokenize(const char* const delim, const char*& save, size_t& len)
{
    if ( !save || !*save )
        return nullptr;

    save = find_first_not_of(save, delim);

    if ( !*save )
        return nullptr;

    const char* end = find_first_of(save, delim);

    const char* tmp = save;

    len = end - save;
    save = end;

    return tmp;
}

static inline bool get_lua_ns(lua_State* L, const char* const ns)
{
    const char* save = ns;
    size_t len = 0;

    lua_pushvalue(L, LUA_GLOBALSINDEX);

    while ( const char* s = tokenize(". ", save, len) )
    {
        if ( !lua_istable(L, -1) )
            return false;

        lua_pushlstring(L, s, len);
        lua_gettable(L, -2);
    }

    return true;
}

static inline bool get_lua_field(
    lua_State* L, int table, const char* field, std::string& out)
{
    lua_getfield(L, table, field);
    bool result = lua_isstring(L, -1);
    if ( result )
        out = lua_tostring(L, -1);

    lua_pop(L, 1);
    return result;
}

static inline bool get_lua_field(
    lua_State* L, int table, const char* field, int& out)
{
    lua_getfield(L, table, field);
    bool result = lua_isnumber(L, -1);
    if ( result )
        out = lua_tointeger(L, -1);

    lua_pop(L, 1);
    return result;
}

static inline bool get_lua_field(
    lua_State* L, int table, const char* field, IpProtocol& out)
{
    lua_getfield(L, table, field);
    bool result = lua_isnumber(L, -1);
    if ( result )
        out = (IpProtocol)lua_tointeger(L, -1);

    lua_pop(L, 1);
    return result;
}

static lua_State* create_lua_state()
{
    auto L = luaL_newstate();
    luaL_openlibs(L);

    Detector_register(L);
    // After detector register the methods are still on the stack, remove them
    lua_pop(L, 1);

    DetectorFlow_register(L);
    lua_pop(L, 1);

#ifdef REMOVED_WHILE_NOT_IN_USE
    /*The garbage-collector pause controls how long the collector waits before
      starting a new cycle. Larger values make the collector less aggressive.
      Values smaller than 100 mean the collector will not wait to start a new
      cycle. A value of 200 means that the collector waits for the total memory
      in use to double before starting a new cycle. */

    lua_gc(myLuaState, LUA_GCSETPAUSE, 100);

    /*The step multiplier controls the relative speed of the collector relative
      to memory allocation. Larger values make the collector more aggressive
      but also increase the size of each incremental step. Values smaller than
      100 make the collector too slow and can result in the collector never
      finishing a cycle. The default, 200, means that the collector runs at
      "twice" the speed of memory allocation. */

    lua_gc(myLuaState, LUA_GCSETSTEPMUL, 200);
#endif

    // set lua library paths
    char extra_path_buffer[PATH_MAX];

    // FIXIT-L compute this path in the appid config module and return it ready to use
    snprintf(
        extra_path_buffer, PATH_MAX-1, "%s/odp/libs/?.lua;%s/custom/libs/?.lua",
        AppIdConfig::get_appid_config()->mod_config->app_detector_dir,
        AppIdConfig::get_appid_config()->mod_config->app_detector_dir);

    const int save_top = lua_gettop(L);
    if ( get_lua_ns(L, "package.path") )
    {
        lua_pushstring(L, extra_path_buffer);
        lua_concat(L, 2);
        lua_setfield(L, -2, "path");
    }
    else
        ErrorMessage("Could not set lua package.path\n");

    lua_settop(L, save_top);

    return L;
}

static void get_detector_package_info(Detector* detector)
{
    auto L = detector->myLuaState;
    Lua::ManageStack mgr(L);

    auto& pkg = detector->packageInfo;
    lua_getglobal(L, "DetectorPackageInfo");

    // use defaults
    if ( lua_isnil(L, -1) )
        return;

    // get name
    get_lua_field(L, -1, "name", pkg.name);

    // get proto
    if ( !get_lua_field(L, -1, "proto", pkg.proto) )
    {
        ErrorMessage("DetectorPackageInfo field 'proto' is not a number\n");
    }

    // get client
    lua_getfield(L, -1, "client");
    if ( lua_istable(L, -1) )
    {
        get_lua_field(L, -1, "init", pkg.client.initFunctionName);
        get_lua_field(L, -1, "clean", pkg.client.cleanFunctionName);
        get_lua_field(L, -1, "validate", pkg.client.validateFunctionName);
        get_lua_field(L, -1, "minimum_matches", pkg.client.minimum_matches);
    }

    // pop client table
    lua_pop(L, 1);

    // get server
    lua_getfield(L, -1, "server");
    if ( lua_istable(L, -1) )
    {
        get_lua_field(L, -1, "init", pkg.server.initFunctionName);
        get_lua_field(L, -1, "clean", pkg.server.cleanFunctionName);
        get_lua_field(L, -1, "validate", pkg.server.validateFunctionName);
        get_lua_field(L, -1, "minimum_matches", pkg.server.minimum_matches);
    }

    lua_pop(L, 1);  /*pop server table */
    lua_pop(L, 1);  /*pop DetectorPackageInfo table */
}

static void clean_client_detector(Detector* detector)
{
    auto L = detector->myLuaState;
    const auto& client = detector->packageInfo.client;

    assert(!client.cleanFunctionName.empty() );

    lua_getglobal(L, client.cleanFunctionName.c_str());
    if (!lua_isfunction(L, -1))
    {
        ErrorMessage("Detector %s: does not contain DetectorFini() function\n",
            detector->name.c_str());
        return;
    }

    /*first parameter is DetectorUserData */
    lua_rawgeti(L, LUA_REGISTRYINDEX, detector->detectorUserDataRef);

    if ( lua_pcall(L, 1, 1, 0) )
    {
        ErrorMessage("Could not cleanup the %s client app element: %s\n",
            detector->name.c_str(), lua_tostring(L, -1));
    }
}

LuaDetectorManager::LuaDetectorManager()
{
    sflist_init(&allocatedFlowList);
    allocated_detectors.clear();
}

LuaDetectorManager::~LuaDetectorManager()
{
    for ( auto& detector : allocated_detectors )
    {
        if ( detector->isActive && !detector->packageInfo.client.initFunctionName.empty() )
            clean_client_detector(detector);

        delete detector;
    }

    sflist_static_free_all(&allocatedFlowList, freeDetectorFlow);
    allocated_detectors.clear();
}

/**calculates Number of flow and host tracker entries for Lua detectors, given amount
 * of memory allocated to RNA (fraction of total system memory) and number of detectors
 * loaded in database. Calculations are based on CAICCI detector and observing memory
 * consumption per tracker.
 * @param rnaMemory - total memory RNA is allowed to use. This is calculated as a fraction of
 * total system memory.
 * @param numDetectors - number of lua detectors present in database.
 */
#define LUA_TRACKERS_MAX  10000
#define LUA_TRACKER_AVG_MEM_BYTES  740

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
                ErrorMessage("error setting tracker size");
        }
    }
    else
    {
        DebugMessage(DEBUG_LOG, "hostServiceTrackerModule.setHosServiceTrackerSize not found");
    }
    lua_pop(L, 1);

    /*change flow tracker size according to available memory calculation */
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
    numTrackers = (detectorMemory / LUA_TRACKER_AVG_MEM_BYTES) / numDetectors;
    return (numTrackers > LUA_TRACKERS_MAX) ? LUA_TRACKERS_MAX : numTrackers;
}

void LuaDetectorManager::initialize_lua_detector( const char* detectorName, char* validator,
        unsigned int validatorLen, unsigned char* const digest, AppIdConfig* pConfig,
        bool isCustom)
{
    Detector* detector;

    lua_State* L = create_lua_state();
    if ( !L )
    {
        ErrorMessage("can not create new luaState");
        delete[] validator;
        return;
    }

    if ( luaL_loadbuffer(L, validator, validatorLen, "<buffer>") || lua_pcall(L, 0, 0, 0) )
    {
        ErrorMessage("cannot run validator %s, error: %s\n", detectorName, lua_tostring(L, -1));
        lua_close(L);
        delete[] validator;
        return;
    }

    detector = createDetector(L, detectorName);
    if ( !detector )
    {
        ErrorMessage("cannot allocate detector %s\n", detectorName);
        lua_close(L);
        delete[] validator;
        return;
    }

    get_detector_package_info(detector);
    detector->validatorBuffer = validator;
    detector->isActive = true;
    detector->appid_config =  pConfig;
    detector->isCustom = isCustom;

    if ( detector->packageInfo.server.initFunctionName.empty() )
    {
        RNAClientAppModule* cam = nullptr;
        detector->client.appFpId = APP_ID_UNKNOWN;
        cam = &detector->client.appModule;
        cam->name = detector->packageInfo.name.c_str();
        cam->proto = detector->packageInfo.proto;
        cam->validate = validateAnyClientApp;
        cam->minimum_matches = detector->packageInfo.client.minimum_matches;
        cam->userData = detector;
        cam->api = getClientApi();
    }
    else
    {
        add_service_to_active_list(&detector->server.serviceModule);
        detector->server.serviceId = APP_ID_UNKNOWN;

        /*create a ServiceElement */
        if (checkServiceElement(detector))
        {
            detector->server.pServiceElement->validate = validateAnyService;
            detector->server.pServiceElement->userdata = detector;
            detector->server.pServiceElement->detectorType = DETECTOR_TYPE_DECODER;
        }
    }

    memcpy(detector->digest, digest, sizeof(detector->digest));
    allocated_detectors.push_front(detector);
    num_lua_detectors++;

    DebugFormat(DEBUG_LOG,"Loaded detector %s\n", detectorName);
}

void LuaDetectorManager::validate_lua_detector(const char* path, AppIdConfig* pConfig, bool isCustom)
{
    unsigned n;
    FILE* file;
    char pattern[PATH_MAX];
    snprintf(pattern, sizeof(pattern), "%s/*", path);

    glob_t globs;
    memset(&globs, 0, sizeof(globs));
    int rval = glob(pattern, 0, nullptr, &globs);
    if (rval != 0 && rval != GLOB_NOMATCH)
    {
        ErrorMessage("Unable to read directory '%s'\n",pattern);
        return;
    }

    // Open each RNA detector file and gather detector information from it
    for (n = 0; n < globs.gl_pathc; n++)
    {
        unsigned char digest[16];
        MD5CONTEXT context;
        char detectorName[LUA_DETECTOR_FILENAME_MAX];
        char* basename;

        basename = strrchr(globs.gl_pathv[n], '/');
        if (!basename)
            basename = globs.gl_pathv[n];
        basename++;

        snprintf(detectorName, LUA_DETECTOR_FILENAME_MAX, "%s_%s", (isCustom ? "custom" : "cisco"),
            basename);

        if ((file = fopen(globs.gl_pathv[n], "r")) == nullptr)
        {
            ErrorMessage("Unable to read lua detector '%s'\n",globs.gl_pathv[n]);
            continue;
        }

        /*Load lua file as a detector. */
        if (fseek(file, 0, SEEK_END))
        {
            ErrorMessage("Unable to seek lua detector '%s'\n",globs.gl_pathv[n]);
            continue;
        }

        auto validatorBufferLen = ftell(file);
        if (validatorBufferLen == -1)
        {
            ErrorMessage("Unable to return offset on lua detector '%s'\n",globs.gl_pathv[n]);
            continue;
        }
        if (fseek(file, 0, SEEK_SET))
        {
            ErrorMessage("Unable to seek lua detector '%s'\n",globs.gl_pathv[n]);
            continue;
        }

        auto validatorBuffer = new uint8_t[validatorBufferLen + 1]();
        if (fread(validatorBuffer, validatorBufferLen, 1, file) == 0)
        {
            ErrorMessage("Failed to read lua detector %s\n",globs.gl_pathv[n]);
            delete[] validatorBuffer;
            continue;
        }

        validatorBuffer[validatorBufferLen] = '\0';
        MD5INIT(&context);
        MD5UPDATE(&context, validatorBuffer, validatorBufferLen);
        MD5FINAL(digest, &context);

        // FIXIT-M this finds the wrong detector -- it should be find_last_of
        auto it = std::find_if(
            allocated_detectors.begin(),
            allocated_detectors.end(),
            [&detectorName](const Detector* d) {
            return d->name == detectorName;
        });

        if ( it != allocated_detectors.end() )
        {
            Detector* detector = *it;
            if ( !memcmp(digest, detector->digest, sizeof(digest)) )
            {
                detector->isActive = true;
                detector->appid_config = pConfig;
                delete[] validatorBuffer;
            }
        }

        initialize_lua_detector(detectorName, (char*)validatorBuffer, validatorBufferLen, digest, pConfig,
            isCustom);
    }

    globfree(&globs);
}

// These functions call the 'DetectorInit' function of the lua detector.
// Calls initialization function as defined in packageInfo, which reads either user defined name
// or DetectorInit symbol. Pushes detectorUserData on stack as input parameter and the calls the
// function. Notice * that on error, lua_state is not closed. This keeps faulty detectors around
// without using it, but it keeps wrapping functions simpler.
static void init_service_detector(Detector* detector)
{
    const auto& name = detector->name;
    auto L = detector->myLuaState;
    const auto& server = detector->packageInfo.server;

    lua_getglobal(L, server.initFunctionName.c_str());
    if (!lua_isfunction(L, -1))
        return;

    /*first parameter is DetectorUserData */
    lua_rawgeti(L, LUA_REGISTRYINDEX, detector->detectorUserDataRef);
    if ( lua_pcall(L, 1, 1, 0) )
    {
        ErrorMessage("error loading lua Detector %s, error %s\n",
            name.c_str(), lua_tostring(L, -1));
        return;
    }
    else
    {
        if ( detector->server.pServiceElement )
            detector->server.pServiceElement->ref_count = 1;

        DebugFormat(DEBUG_APPID, "Initialized %s\n", name.c_str());
    }
}

static void init_client_detector(Detector* detector)
{
    auto L = detector->myLuaState;
    const auto& client = detector->packageInfo.client;

    assert(!client.initFunctionName.empty());

    lua_getglobal(L, client.initFunctionName.c_str());
    if (!lua_isfunction(L, -1))
    {
        ErrorMessage("Detector %s: does not contain DetectorInit() function\n",
            detector->name.c_str());
        return;
    }

    /*first parameter is DetectorUserData */
    lua_rawgeti(L, LUA_REGISTRYINDEX, detector->detectorUserDataRef);

    /*second parameter is a table containing configuration stuff. */
    // ... which is empty.???
    lua_newtable(L);

    if ( lua_pcall(L, 2, 1, 0) )
    {
        ErrorMessage("Could not initialize the %s client app element: %s\n",
            detector->name.c_str(), lua_tostring(L, -1));
        return;
    }
}

void LuaDetectorManager::init_lua_service_detectors()
{
    for ( auto& detector : allocated_detectors )
        init_service_detector(detector);
}

void LuaDetectorManager::init_lua_client_detectors()
{
    for ( auto& detector : allocated_detectors )
        if ( detector->isActive && !detector->packageInfo.client.initFunctionName.empty() )
            init_client_detector(detector);
}

void LuaDetectorManager::activate_lua_detectors()
{
    init_lua_client_detectors();
    init_lua_service_detectors();

    for ( auto& detector : allocated_detectors )
        if ( detector->isActive )
        {
            ++num_active_lua_detectors;

            if ( detector->server.pServiceElement )
                detector->server.pServiceElement->current_ref_count =
                    detector->server.pServiceElement->ref_count;
        }

    lua_tracker_size = compute_lua_tracker_size(512*1024*1024, num_active_lua_detectors);
    for ( auto& detector : allocated_detectors )
    {
        if ( detector->isActive )
            set_lua_tracker_size(detector->myLuaState, lua_tracker_size);
    }
}

void LuaDetectorManager::load_lua_detectors(AppIdConfig* pConfig)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/odp/lua",
            AppIdConfig::get_appid_config()->mod_config->app_detector_dir);
    validate_lua_detector(path, pConfig, 0);
    snprintf(path, sizeof(path), "%s/custom/lua",
            AppIdConfig::get_appid_config()->mod_config->app_detector_dir);
    validate_lua_detector(path, pConfig, 1);
}

void LuaDetectorManager::list_lua_detectors()
{
    // FIXIT-L make these perf counters
    size_t totalMem = 0;
    size_t mem;

    if ( allocated_detectors.empty() )
        return;

    LogMessage("Lua Detector Stats:\n");

    for ( auto& detector : allocated_detectors )
    {
        mem = lua_gc(detector->myLuaState, LUA_GCCOUNT, 0);
        totalMem += mem;
        LogMessage("\tDetector %s: Lua Memory usage %zu kb\n", detector->name.c_str(), mem);
    }

    LogMessage("Lua Stats total detectors: %lu\n", allocated_detectors.size());
    LogMessage("Lua Stats total memory usage %zu kb\n", totalMem);
}

