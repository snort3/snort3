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

#include <list>
#include <algorithm>
#include <glob.h>
#include <lua.hpp>
#include <openssl/md5.h>

#include "appid_config.h"
#include "client_plugins/client_app_base.h"
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

// This data structure is shared in the main and the reload threads. However, the detectors
// in this list could be using different AppID contexts (pAppidOldConfig, pAppidActiveConfig
// and pAppidActiveConfig) based on which context the detector is being used. For example,
// a detector could simultaneously be loaded in the reload thread while the same detector
// could be used in the packet processing thread. Since allocatedDetectorList is used only
// during loading, we don't need to use synchronization measures to access it.
static std::list<Detector*> allocatedDetectorList;

SF_LIST allocatedFlowList;  /*list of flows allocated. */
static uint32_t gLuaTrackerSize = 0;
static unsigned gNumDetectors = 0;
static unsigned gNumActiveDetectors;

inline bool match_char_set(char c, const char* set)
{
    while ( *set && *set != c )
        ++set;

    return *set != '\0';
}

inline const char* find_first_not_of(const char* s, const char* const set)
{
    while ( *s && match_char_set(*s, set) )
        ++s;

    return s;
}

inline const char* find_first_of(const char* s, const char* const set)
{
    while ( *s && !match_char_set(*s, set) )
        ++s;

    return s;
}

const char* tokenize(const char* const delim, const char*& save, size_t& len)
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

static lua_State* createLuaState()
{
    // FIXIT-H J should obtain lua states from lua state factory
    auto L = luaL_newstate();
    luaL_openlibs(L);

// FIXIT-M J this is stupid, remove it
#ifdef HAVE_LIBLUAJIT
    /*linked in during compilation */
    luaopen_jit(myLuaState);

    {
        static unsigned once = 0;
        if (!once)
        {
            lua_getfield(myLuaState, LUA_REGISTRYINDEX, "_LOADED");
            lua_getfield(myLuaState, -1, "jit");  /* Get jit.* module table. */
            lua_getfield (myLuaState, -1, "version");
            if (lua_isstring(myLuaState, -1))
                DEBUG_WRAP(DebugMessage(DEBUG_APPID, "LuaJIT: Version %s\n", lua_tostring(
                    myLuaState, -1)); );
            lua_pop(myLuaState, 1);
            once = 1;
        }
    }

#endif  /*HAVE_LIBLUAJIT */

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

    snprintf(
        extra_path_buffer, PATH_MAX-1, "%s/odp/libs/?.lua;%s/custom/libs/?.lua",
        pAppidActiveConfig->mod_config->app_detector_dir,
        pAppidActiveConfig->mod_config->app_detector_dir);

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

#ifdef REMOVED_WHILE_NOT_IN_USE
static void getDetectorPackageInfo(lua_State* L, Detector* detector, int fillDefaults)
{
    tDetectorPackageInfo* pkg = &detector->packageInfo;
    lua_getglobal (L, "DetectorPackageInfo");
    if (!lua_istable(L, -1))
    {
        lua_pop(L, 1);

        if (fillDefaults)
        {
            /*set default values first */
            pkg->name = snort_strdup("NoName");
            pkg->server.initFunctionName = snort_strdup("DetectorInit");
            pkg->server.cleanFunctionName = snort_strdup("DetectorClean");
            pkg->server.validateFunctionName = snort_strdup("DetectorValidate");
            if (!pkg->name || !pkg->server.initFunctionName || !pkg->server.cleanFunctionName ||
                !pkg->server.validateFunctionName)
                _dpd.errMsg("failed to allocate package");
        }
        return;
    }

    /* Get all the variables */
    lua_getfield(L, -1, "name"); /* string */
    if (lua_isstring(L, -1))
    {
        pkg->name = snort_strdup(lua_tostring(L, -1));
        if (!pkg->name)
            _dpd.errMsg("failed to allocate package name");
    }
    else if (fillDefaults)
    {
        pkg->name = snort_strdup("NoName");
        if (!pkg->name)
            _dpd.errMsg("failed to allocate package name");
    }
    lua_pop(L, 1);

    lua_getfield(L, -1, "proto"); /* integer? */
    if (lua_isnumber(L, -1))
    {
        pkg->proto = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, -1, "client");
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, "init"); /* string*/
        if (lua_isstring(L, -1))
        {
            pkg->client.initFunctionName = snort_strdup(lua_tostring(L, -1));
            if (!pkg->client.initFunctionName)
                _dpd.errMsg("failed to allocate client init function name");
        }
        lua_pop(L, 1);

        lua_getfield(L, -1, "clean"); /* string*/
        if (lua_isstring(L, -1))
        {
            pkg->client.cleanFunctionName = snort_strdup(lua_tostring(L, -1));
            if (!pkg->client.cleanFunctionName)
                lua_getfield(L, -1, "validate"); /* string*/
            if (lua_isstring(L, -1))
            {
                pkg->client.validateFunctionName = snort_strdup(lua_tostring(L, -1));
                if (!pkg->client.validateFunctionName)
                    _dpd.errMsg("failed to allocate client validate function name");
            }
            lua_pop(L, 1);

            lua_getfield(L, -1, "minimum_matches");     /* integer*/
            if (lua_isnumber(L, -1))
            {
                pkg->client.minMatches = lua_tointeger(L, -1);
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);      /*pop client table */

        lua_getfield(L, -1, "server");
        if (lua_istable(L, -1))
        {
            lua_getfield(L, -1, "init");     /* string*/
            if (lua_isstring(L, -1))
            {
                pkg->server.initFunctionName = snort_strdup(lua_tostring(L, -1));
                if (!pkg->server.initFunctionName)
                    _dpd.errMsg("failed to allocate server init function name");
            }
            else if (fillDefaults)
            {
                pkg->server.initFunctionName = snort_strdup("DetectorInit");
                if (!pkg->server.initFunctionName)
                    _dpd.errMsg("failed to allocate server init function name");
            }
            lua_pop(L, 1);

            lua_getfield(L, -1, "clean");     /* string*/
            if (lua_isstring(L, -1))
            {
                pkg->server.cleanFunctionName = snort_strdup(lua_tostring(L, -1));
                if (!pkg->server.cleanFunctionName)
                    _dpd.errMsg("failed to allocate server clean function name");
            }
            else if (fillDefaults)
            {
                pkg->server.cleanFunctionName = snort_strdup("DetectorClean");
                if (!pkg->server.cleanFunctionName)
                    _dpd.errMsg("failed to allocate server clean function name");
            }
            lua_pop(L, 1);

            lua_getfield(L, -1, "validate");     /* string*/
            if (lua_isstring(L, -1))
            {
                pkg->server.validateFunctionName = snort_strdup(lua_tostring(L, -1));
                if (!pkg->server.validateFunctionName)
                    _dpd.errMsg("failed to allocate server validate function name");
            }
            else if (fillDefaults)
            {
                pkg->server.validateFunctionName = snort_strdup("DetectorValidate");
                if (!pkg->server.validateFunctionName)
                    _dpd.errMsg("failed to allocate server validate function name");
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);      /*pop server table */

        lua_pop(L, 1);      /*pop DetectorPackageInfo table */
    }
}

#endif

// fetch or create packageInfo defined inside lua detector
static void getDetectorPackageInfo(Detector* detector)
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
        // FIXIT-M J error messages should use source info
        ErrorMessage("DetectorPackageInfo field 'proto' is not a number\n");
    }

    // get client
    lua_getfield(L, -1, "client");
    if ( !lua_istable(L, -1) )
    {
        // FIXIT-M J error messages should use source info
        ErrorMessage("DetectorPackageInfo field 'client' is not a table\n");
    }
    else
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
    if ( !lua_istable(L, -1) )
    {
        // FIXIT-M J error messages should use source info
        ErrorMessage("DetectorPackageInfo field 'server' is not a table\n");
    }
    else
    {
        get_lua_field(L, -1, "init", pkg.server.initFunctionName);
        get_lua_field(L, -1, "clean", pkg.server.cleanFunctionName);
        get_lua_field(L, -1, "validate", pkg.server.validateFunctionName);
        get_lua_field(L, -1, "minimum_matches", pkg.server.minimum_matches);
    }
}

/**Calls DetectorInit function inside lua detector.
 * Calls initialization function as defined in packageInfo, which reads either user defined name
 * or DetectorInit symbol. Pushes detectorUserData on stack as input parameter and the calls the
 * function. Notice * that on error, lua_state is not closed. This keeps faulty detectors around
 * without using it, but it keeps wrapping functions simpler.
 */
static void luaServerInit(Detector* detector)
{
    const auto& name = detector->name;
    auto L = detector->myLuaState;
    const auto& server = detector->packageInfo.server;

    if ( server.initFunctionName.empty() )
    {
        ErrorMessage("Detector %s: DetectorInit() is not provided for server\n", name.c_str());
        return;
    }

    lua_getglobal(L, server.initFunctionName.c_str());

    if (!lua_isfunction(L, -1))
    {
        ErrorMessage("Detector %s: does not contain DetectorInit() function\n", name.c_str());
        return;
    }

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

/**Calls init function inside lua detector.
 * Calls initialization function as defined in packageInfo. Pushes detectorUserData on stack
 * as input parameter and the calls the function. Notice * that on error, lua_state is not
 * closed. This keeps faulty detectors around without using it, but it keeps wrapping functions
 * simpler.
 */
static void luaClientInit(Detector* detector)
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
        // FIXIT shouldn't this be using detector->name?
        ErrorMessage("Could not initialize the %s client app element: %s\n",
            detector->name.c_str(), lua_tostring(L, -1));
        return;
    }
    else
    {
        DebugFormat(DEBUG_APPID, "Initialized %s\n", detector->name.c_str());
    }
}

static void luaClientFini(Detector* detector)
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

/**set tracker sizes on Lua detector sizes. Uses global module names to access functions.
 */
static inline void setLuaTrackerSize(lua_State* L, uint32_t numTrackers)
{
    /*change flow tracker size according to available memory calculation */
    lua_getglobal(L, "hosServiceTrackerModule");
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, "setHosServiceTrackerSize");
        if (lua_isfunction(L, -1))
        {
            lua_pushinteger (L, numTrackers);
            if (lua_pcall(L, 1, 0, 0) != 0)
            {
                ErrorMessage("error setting tracker size");
            }
        }
    }
    else
    {
#ifdef LUA_DETECTOR_DEBUG
        DebugFormat(DEBUG_LOG, "hosServiceTrackerModule.setHosServiceTrackerSize not found");
#endif
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
            {
                ErrorMessage("error setting tracker size");
            }
        }
    }
    else
    {
#ifdef LUA_DETECTOR_DEBUG
        DebugFormat(DEBUG_LOG, "flowTrackerModule.setFlowTrackerSize not found");
#endif
    }
    lua_pop(L, 1);
}

static void luaCustomLoad( char* detectorName, char* validator, unsigned int validatorLen,
        unsigned char* const digest, AppIdConfig* pConfig, bool isCustom)
{
    Detector* detector;
    RNAClientAppModule* cam = nullptr;

    lua_State* L = createLuaState();
    if ( !L )
    {
        ErrorMessage("can not create new luaState");
        snort_free(validator);
        return;
    }

    if ( luaL_loadbuffer(L, validator, validatorLen, "<buffer>") ||
        lua_pcall(L, 0, 0, 0) )
    {
        ErrorMessage("cannot run validator %s, error: %s\n",
            detectorName, lua_tostring(L, -1));

        lua_close(L);
        snort_free(validator);

        return;
    }

    detector = createDetector(L, detectorName);
    if ( !detector )
    {
        ErrorMessage("cannot allocate detector %s\n", detectorName);
        lua_close(L);
        snort_free(validator);

        return;
    }

    getDetectorPackageInfo(detector);
    detector->validatorBuffer = validator;
    detector->isActive = true;
    detector->pAppidNewConfig = detector->pAppidActiveConfig = detector->pAppidOldConfig = pConfig;
    detector->isCustom = isCustom;

    if ( detector->packageInfo.server.initFunctionName.empty() )
    {
        assert(false); // FIXIT-H J cam is null at this point so... WOMP
        detector->client.appFpId = APP_ID_UNKNOWN;
        cam = &detector->client.appModule;
        // cam->name = detector->packageInfo.name;
        cam->proto = detector->packageInfo.proto;
        cam->validate = validateAnyClientApp;
        cam->minimum_matches = detector->packageInfo.client.minimum_matches;
        cam->userData = detector;
        cam->api = getClientApi();
    }
    else
    {
        /*add to active service list */
        detector->server.serviceModule.next = pConfig->serviceConfig.active_service_list;
        pConfig->serviceConfig.active_service_list = &detector->server.serviceModule;

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
    allocatedDetectorList.push_front(detector);
    gNumDetectors++;

    DebugFormat(DEBUG_LOG,"Loaded detector %s\n", detectorName);
}

void LuaDetectorModuleManager::luaModuleInit()
{
    sflist_init(&allocatedFlowList);
    allocatedDetectorList.clear();
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

static inline uint32_t calculateLuaTrackerSize(u_int64_t rnaMemory, uint32_t numDetectors)
{
    u_int64_t detectorMemory = (rnaMemory/8);
    unsigned numTrackers;
    if (!numDetectors)
        numDetectors = 1;
    numTrackers = (detectorMemory/LUA_TRACKER_AVG_MEM_BYTES)/numDetectors;
    return (numTrackers > LUA_TRACKERS_MAX) ? LUA_TRACKERS_MAX : numTrackers;
}

static void loadCustomLuaModules(char* path, AppIdConfig* pConfig, bool isCustom)
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
        {
            basename = globs.gl_pathv[n];
        }
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

        // FIXIT-H J this finds the wrong detector -- it should be find_last_of
        auto it = std::find_if(
            allocatedDetectorList.begin(),
            allocatedDetectorList.end(),
            [&detectorName](const Detector* d) {
            return d->name == detectorName;
        });

        if ( it != allocatedDetectorList.end() )
        {
            Detector* detector = *it;
            if ( !memcmp(digest, detector->digest, sizeof(digest)) )
            {
                detector->isActive = true;
                detector->pAppidNewConfig = pConfig;
                delete[] validatorBuffer;
            }
        }

        luaCustomLoad(detectorName, (char*)validatorBuffer, validatorBufferLen, digest, pConfig,
            isCustom);
    }

    globfree(&globs);
}

void LuaDetectorModuleManager::FinalizeLuaModules(AppIdConfig* pConfig)
{
    gNumActiveDetectors = 0;

    for ( auto& detector : allocatedDetectorList )
    {
        detector->pAppidOldConfig = detector->pAppidActiveConfig;
        detector->pAppidActiveConfig = pConfig;
        if ( detector->isActive )
        {
            ++gNumActiveDetectors;

            if ( detector->server.pServiceElement )
                detector->server.pServiceElement->current_ref_count =
                    detector->server.pServiceElement->ref_count;
        }
    }

    luaDetectorsSetTrackerSize();
}

void LuaDetectorModuleManager::LoadLuaModules(AppIdConfig* pConfig)
{
    for ( auto& detector : allocatedDetectorList )
    {
        detector->wasActive = detector->isActive;
        detector->isActive = 0;

        if ( detector->server.pServiceElement )
            detector->server.pServiceElement->ref_count = 0;
    }

    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/odp/lua", pAppidActiveConfig->mod_config->app_detector_dir);
    loadCustomLuaModules(path, pConfig, 0);
    snprintf(path, sizeof(path), "%s/custom/lua",
        pAppidActiveConfig->mod_config->app_detector_dir);
    loadCustomLuaModules(path, pConfig, 1);
    // luaDetectorsCleanInactive();
}

void luaDetectorsUnload(AppIdConfig* pConfig)
{
    for ( auto& detector : allocatedDetectorList )
    {
        if ( detector->isActive && !detector->packageInfo.server.initFunctionName.empty())
            detectorRemoveAllPorts(detector, pConfig);

        if ( detector->isActive && !detector->packageInfo.client.initFunctionName.empty() )
            luaClientFini(detector);

        detector->isActive = false;

        if (detector->server.pServiceElement)
            detector->server.pServiceElement->ref_count = 0;
    }

    gNumActiveDetectors = 0;
}

void luaDetectorsSetTrackerSize()
{
    gLuaTrackerSize = calculateLuaTrackerSize(512*1024*1024, gNumActiveDetectors);

    DebugFormat(DEBUG_APPID, "    Setting tracker size to %u\n", gLuaTrackerSize);

    for ( auto& detector : allocatedDetectorList )
    {
        if ( detector->isActive )
            setLuaTrackerSize(detector->myLuaState, gLuaTrackerSize);
    }
}

void LuaDetectorModuleManager::UnloadLuaModules(AppIdConfig*)
{
    for ( auto& detector : allocatedDetectorList )
    {
        if ( detector->wasActive )
        {
            if ( detector->client.appFpId )
                luaClientFini(detector);

            detector->wasActive = false;
        }

        // Detector cleanup is done. Move pAppidOldConfig to the current
        // AppID context.
        detector->pAppidOldConfig = detector->pAppidActiveConfig;
    }
}

/**Reconfigure all Lua modules.
 * Iterates over all Lua detectors in system and reconfigures them. This
 * will however not read rna_csd_validator_map table again to check for
 * newly activated or deactivate detectors. Current design calls for restarting
 * RNA whenever detectors are activated/deactivated.
 */
void luaModuleInitAllServices()
{
    for ( auto& detector : allocatedDetectorList )
        luaServerInit(detector);
}

/**Reconfigure all Lua modules.
 * Iterates over all Lua detectors in system and reconfigures them. This
 * will however not read rna_csd_validator_map table again to check for
 * newly activated or deactivate detectors. Current design calls for restarting
 * RNA whenever detectors are activated/deactivated.
 */
void luaModuleInitAllClients()
{
    for ( auto& detector : allocatedDetectorList )
        if ( detector->isActive && !detector->packageInfo.client.initFunctionName.empty() )
            luaClientInit(detector);
}

void luaModuleCleanAllClients()
{
    for ( auto& detector : allocatedDetectorList )
        if ( !detector->packageInfo.client.initFunctionName.empty() )
            luaClientFini(detector);

    /*dont free detector. Lua side reclaims the memory. */
}

/**Finish routine for DetectorCore module. It release all Lua sessions and frees any memory.
 * @warn This function should be called once and that too when RNA is performing clean exit.
 * @return void.
  */
void LuaDetectorModuleManager::luaModuleFini()
{
    DebugMessage(DEBUG_APPID, "luaModuleFini(): entered");

    /*flow can be freed during garbage collection */

    sflist_static_free_all(&allocatedFlowList, freeDetectorFlow);
    allocatedDetectorList.clear();
}

void RNAPndDumpLuaStats()
{
    size_t totalMem = 0;
    size_t mem;

    if ( allocatedDetectorList.empty() )
        return;

    LogMessage("Lua detector Stats");

    for ( auto& detector : allocatedDetectorList )
    {
        mem = lua_gc(detector->myLuaState, LUA_GCCOUNT, 0);
        totalMem += mem;
        LogMessage("    Detector %s: Lua Memory usage %zu kb", detector->name.c_str(), mem);
    }

    LogMessage("Lua Stats total memory usage %zu kb", totalMem);
}

