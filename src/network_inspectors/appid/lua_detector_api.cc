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

// lua_detector_api.cc author Sourcefire Inc.

#include "lua_detector_api.h"

#include <cstring>

#include <pcre.h>
#include <lua.hpp>

#include "hash/sfxhash.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "profiler/profiler.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"

#include "app_forecast.h"
#include "app_info_table.h"
#include "fw_appid.h"
#include "host_port_app_cache.h"
#include "http_common.h"
#include "lua_detector_flow_api.h"
#include "lua_detector_module.h"
#include "lua_detector_util.h"
#include "service_plugins/service_base.h"
#include "service_plugins/service_ssl.h"
#include "client_plugins/client_app_base.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/detector_pattern.h"

#define DETECTOR "Detector"
#define OVECCOUNT 30    /* should be a multiple of 3 */
#define URL_LIST_STEP_SIZE  5000

#define CHECK_INPUTS() \
    if ( !checkServiceElement(ud) || !ud->validateParams.pkt ) \
    { \
        lua_pushnumber(L, SERVICE_ENULL); \
        return 1; \
    }

enum
{
    LUA_LOG_CRITICAL = 0,
    LUA_LOG_ERR = 1,
    LUA_LOG_WARN = 2,
    LUA_LOG_NOTICE = 3,
    LUA_LOG_INFO = 4,
    LUA_LOG_DEBUG = 5,
};

/*static const char * LuaLogLabel = "luaDetectorApi"; */

ProfileStats luaDetectorsPerfStats;
ProfileStats luaCiscoPerfStats;
ProfileStats luaCustomPerfStats;

static void FreeDetectorAppUrlPattern(DetectorAppUrlPattern* pattern);

// FIXIT-H J lifetime of detector is easy to misuse with this idiom
// Leaves 1 value (the Detector userdata) at the top of the stack
Detector* createDetector(lua_State* L, const char* detectorName)
{
    auto detector = new Detector();
    detector->myLuaState = L;
    detector->name = detectorName;

    UserData<Detector>::push(L, DETECTOR, detector);

    // add a lua reference so the detector doesn't get garbage-collected
    // FIXIT-M J should go in a different table maybe?
    lua_pushvalue(L, -1);
    detector->detectorUserDataRef = luaL_ref(L, LUA_REGISTRYINDEX);

    return detector;
}

// must be called only when RNA is exitting.
static void freeDetector(Detector* detector)
{ delete detector; }

// check service element, Allocate if necessary
int checkServiceElement(Detector* detector)
{
    if ( !detector->server.pServiceElement )
    {
        detector->server.pServiceElement = new RNAServiceElement;
        assert(detector->server.pServiceElement);
        detector->server.pServiceElement->name = detector->server.serviceModule.name;
    }

    return 1;
}

// Creates a new detector instance. Creates a new detector instance and leaves the instance
// on stack. This is the first call by a lua detector to create and instance. Later calls
// provide the detector instance.
//
// lua params:
//  #1 - serviceName/stack - name of service
//  #2 - pValidator/stack - service validator function name
//  #3 - pFini/stack - service clean exit function name
//  return - a detector instance or none
static int service_init(lua_State* L)
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    // auto pServiceName = luaL_checkstring(L, 2);
    auto pValidator = luaL_checkstring(L, 3);
    auto pFini = luaL_checkstring(L, 4);

    lua_getglobal(L, pValidator);
    lua_getglobal(L, pFini);

    if ( lua_isfunction(L, -1) && lua_isfunction(L, -2) )
    {
        if ( checkServiceElement(ud) )
        {
            ud->server.pServiceElement->validate = validateAnyService;
            ud->server.pServiceElement->userdata = ud.ptr;
            ud->server.pServiceElement->detectorType = DETECTOR_TYPE_DECODER;
        }

        lua_pop(L, 2);
        return 1;
    }
    else
    {
        ErrorMessage("%s: attempted setting validator/fini to non-function\n",
            ud->server.serviceModule.name);

        lua_pop(L, 2);
        return 0;
    }
}

// Register a pattern for fast pattern matching. Lua detector calls this function to register a
// pattern
// for fast pattern matching. This is similar to registerPattern in traditional C detector.
//
// lua params:
//  #1 - detector/stack - detector object
//  #2 - protocol/stack - protocol type. Values can be {tcp=6, udp=17 }
//  #3 - pattern/stack - pattern string.
//  #4 - size/stack - number of bytes in pattern
//  #5 - position/stack -  position offset where to start matching pattern.
//  return - status/stack - 0 if successful, -1 otherwise.
static int service_registerPattern(lua_State* L)
{
    int index = 1;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);

    // FIXIT-H J none of these params check for signedness casting issues
    // FIXIT-M: May want to create a lua_toipprotocol() so we can handle
    //          error checking in that function.
    int protocol = lua_tonumber(L, index++);
    if (protocol > UINT8_MAX)
    {
        ErrorMessage("Invalid protocol value %d\n", protocol);
        return -1;
    }

    const char* pattern = lua_tostring(L, index++);
    size_t size = lua_tonumber(L, index++);
    unsigned int position = lua_tonumber(L, index++);

    /*Note: we can not give callback into lua directly so we have to
      give a local callback function, which will do demuxing and
      then call lua callback function. */

    /*mpse library does not hold reference to pattern therefore we dont need to allocate it. */

    ServiceRegisterPatternDetector(validateAnyService, (IpProtocol)protocol, (uint8_t*)pattern,
        size, position, ud, ud->server.serviceModule.name);

    lua_pushnumber(L, 0);
    return 1;
}

static int common_registerAppId(lua_State* L)
{
    unsigned int appId;
    int index = 1;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    appId = lua_tonumber(L, index++);

    if ( !ud->packageInfo.server.initFunctionName.empty() )
        appSetLuaServiceValidator(
            validateAnyService, appId, APPINFO_FLAG_SERVICE_ADDITIONAL, ud.ptr);

    if ( !ud->packageInfo.client.initFunctionName.empty() )
        appSetLuaClientValidator(
            validateAnyClientApp, appId, APPINFO_FLAG_CLIENT_ADDITIONAL, ud.ptr);

    appInfoSetActive(appId, true);

    lua_pushnumber(L, 0);
    return 1;
}

static int Detector_htons(lua_State* L)
{
    // FIXIT-L J ignoring arg #1, as it is unused
    // auto* ud = UserData<Detector>::check(L, DETECTOR, 1);

    unsigned short aShort = lua_tonumber(L, 2);

    lua_pushnumber(L, htons(aShort));
    return 1;
}

static int Detector_htonl(lua_State* L)
{
    // FIXIT-L J ignoring arg #1, as it is unused
    // auto* ud = UserData<Detector>::check(L, DETECTOR, 1);

    unsigned int anInt = lua_tonumber(L, 2);

    lua_pushnumber(L, htonl(anInt));
    return 1;
}

// Logs messages from detectors into wherever /etc/syslog.conf directs them.
// examples are:
//      detector:log(DC.logLevel.warning, 'a warning')
// lua params:
//  #1 - level - level of message. See DetectorCommon for enumeration.
//  #2 - message - message to be logged.
static int Detector_logMessage(lua_State* L)
{
    const auto& name = (*UserData<Detector>::check(L, DETECTOR, 1))->server.serviceModule.name;

    unsigned int level = lua_tonumber(L, 2);
    const char* message = lua_tostring(L, 3);

    switch ( level )
    {
    case LUA_LOG_CRITICAL:
        FatalError("%s:%s\n", name, message);
        break;

    case LUA_LOG_ERR:
    case LUA_LOG_WARN:
        // FIXIT-L J should WARN do a WarningMessage instead?
        ErrorMessage("%s:%s\n", name, message);
        break;

    case LUA_LOG_NOTICE:
    case LUA_LOG_INFO:
        LogMessage("%s:%s\n", name, message);
        break;

    case LUA_LOG_DEBUG:
        DebugFormat(DEBUG_APPID, "%s:%s\n", name, message);
        break;

    default:
        break;
    }

    return 0;
}

// Analyze application payload
// lua params:
//  1 - detector/stack - detector object
//  2 - major/stack - major number of application
//  3 - minor/stack - minor number of application
//  4 - flags/stack - any flags
static int service_analyzePayload(lua_State* L)
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);
    unsigned int payloadId = lua_tonumber(L, 2);

    assert(ud->validateParams.pkt);

    ud->validateParams.flowp->payloadAppId = payloadId;

    return 0;
}

// Design notes: Due to following two design limitations:
//  a. lua validate functions, known only at runtime, can not be wrapped inside unique
//     C functions at runtime and
//  b. core engine can not call lua functions directly.
//
// There must be a common validate function in C that in turn calls relevent Lua functions.
// Right now there is only one detector so there is a one-to-one mapping, but the framework
// will have to support multiple detectors in production environment. Core engine API will be
// changed to take an additional void* that will be used to call only a unique detector.
int validateAnyService(ServiceValidationArgs* args)
{
    Profile lua_detector_context(luaCustomPerfStats);

    int retValue;
    auto detector = args->userdata;

    if ( !detector )
    {
        // FIXIT-M J unhelpful error message
        ErrorMessage("invalid LUA parameters");
        return SERVICE_ENULL;
    }

    auto L = detector->myLuaState;

    detector->validateParams.data = args->data;
    detector->validateParams.size = args->size;
    detector->validateParams.dir = args->dir;
    detector->validateParams.flowp = args->flowp;
    detector->validateParams.pkt = args->pkt;

    const auto& serverName = detector->name;

    /*Note: Some frequently used header fields may be extracted and stored in detector for
      better performance. */

    if ( detector->packageInfo.server.validateFunctionName.empty() || !lua_checkstack(L, 1) )
    {
        ErrorMessage("server %s: invalid LUA %s\n", serverName.c_str(), lua_tostring(L, -1));
        detector->validateParams.pkt = nullptr;
        return SERVICE_ENULL;
    }

    lua_getglobal(L, detector->packageInfo.server.validateFunctionName.c_str());

    DebugFormat(DEBUG_APPID, "server %s: Lua Memory usage %d\n",serverName.c_str(), lua_gc(L,
        LUA_GCCOUNT, 0));
    DebugFormat(DEBUG_APPID,"server %s: validating\n", serverName.c_str());

    if ( lua_pcall(L, 0, 1, 0) )
    {
        /*Runtime Lua errors are suppressed in production code since detectors are written for
          efficiency
          and with defensive minimum checks. Errors are dealt as exceptions that dont impact
          processing
          by other detectors or future packets by the same detector. */
        ErrorMessage("server %s: error validating %s\n", serverName.c_str(), lua_tostring(L, -1));
        detector->validateParams.pkt = nullptr;
        return SERVICE_ENULL;
    }

    /**detectorFlows must be destroyed after each packet is processed.*/
    sflist_static_free_all(&allocatedFlowList, freeDetectorFlow);

    /* retrieve result */
    if ( !lua_isnumber(L, -1) )
    {
        ErrorMessage("server %s:  validator returned non-numeric value\n", serverName.c_str());
        detector->validateParams.pkt = nullptr;
        return SERVICE_ENULL;
    }

    retValue = lua_tonumber(L, -1);
    lua_pop(L, 1);  /* pop returned value */

    DebugFormat(DEBUG_APPID, "server %s: Validator returned %d\n", serverName.c_str(), retValue);

    detector->validateParams.pkt = nullptr;

    return retValue;
}

/**design: dont store serviceId in detector structure since a single detector
 * can get serviceId for multiple protocols. For example SIP which gets Id for RTP and
 * SIP services.
 */

// Get service id from database, given service name. Lua detectors call this function at init time
// get get a service Id (an integer) from database.
// @param serviceName/stack - Name of service
// @return serviceId/stack - serviceId if successful, -1 otherwise.
static int service_getServiceId(lua_State* L)
{
    auto ud = *UserData<Detector>::check(L, DETECTOR, 1);

    lua_pushnumber(L, ud->server.serviceId);
    return 1;
}

/**
 * Design Notes: In these APIs, three different AppID contexts - pAppidNewConfig, pAppidOldConfig
 * and pAppidActiveConfig are used. pAppidNewConfig is used in APIs related to the loading of the
 * detector such as service_addPorts(), client_registerPattern(), etc. A detector is loaded either
 * during reload or at initialization. Use of pAppidNewConfig will cause the data structures related
 * to the detector such as service ports, patterns, etc to be saved in the new AppID context.
 *
 * The new AppID context becomes active at the end of initialization or at reload swap.
 * FinalizeLuaModules() is called at this time, which changes all the detectors' pAppidActiveConfig
 * references to the new context. Also, pAppidOldConfig will be changed to point to the previous
 * AppID context. In the packet processing APIs such as service_addService(), client_addUser(), etc.
 * pAppidActiveConfig is used.
 *
 * In the cleanup APIs such as service_removePorts(), Detector_fini(), etc., data structures in the
 * old AppID conext need to be freed. Therefore, pAppidOldConfig is used in these APIs.
 */

// Add port for a given service. Lua detectors call this function to register ports on which a
// given service is expected to run.
// @param protocol/stack - protocol type. Values can be {tcp=6, udp=17 }
// @param port/stack - port number to register.
// @return status/stack - 0 if successful, -1 otherwise.
static int service_addPorts(lua_State* L)
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    RNAServiceValidationPort pp;
    pp.proto = (IpProtocol)lua_tonumber(L, 2);
    pp.port = lua_tonumber(L, 3);
    pp.reversed_validation = lua_tonumber(L, 5);
    pp.validate = &validateAnyService;

    if ( ((pp.proto != IpProtocol::UDP) && (pp.proto != IpProtocol::TCP)) || !pp.port )
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    if ( ServiceAddPort(&pp, &ud->server.serviceModule, ud, ud->pAppidNewConfig) )
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    ++ud->server.pServiceElement->ref_count;

    lua_pushnumber(L, 0);
    return 1;
}

// Remove all ports for a given service. Lua detectors call this function to remove ports for this
// service
// when exiting. This function is not used currently by any detectors.
// @return status/stack - 0 if successful, -1 otherwise.
static int service_removePorts(lua_State* L)
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    detectorRemoveAllPorts(ud, ud->pAppidOldConfig);

    lua_pushnumber(L, 0);
    return 1;
}

// Shared function between Lua API and RNA core.
void detectorRemoveAllPorts(Detector* detector, AppIdConfig* pConfig)
{ ServiceRemovePorts(&validateAnyService, detector, pConfig); }

// Set service name. Lua detectors call this function to set service name. It is preferred to set
// service name
// when a detector is created. Afterwards there is rarely a need to change service name.
// @param serviceName/stack - Name of service
// @return status/stack - 0 if successful, -1 otherwise.
static int service_setServiceName(lua_State* L)
{
    lua_pushnumber(L, 0);
    return 1;
}

/**Get service name. Lua detectors call this function to get service name. There is
 * rarely a need to change service name.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1.
 * @return serviceName/stack - service name if successful, nil otherwise.
 */
static int service_getServiceName(
    lua_State* L
    )
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    lua_pushstring(L, ud->server.serviceModule.name);
    return 1;
}

/**Is this a customer defined detector. Lua detectors can call this function to verify if the detector
 * was created by Sourcefire or not.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1.
 * @return integer/stack - -1 if failed, 0 if sourcefire created, 1 otherwise.
 */
static int service_isCustomDetector(lua_State* L)
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);
    lua_pushnumber(L, ud->isCustom);
    return 1;
}

/**Set service validator Lua function name. Lua detectors use this function to set a lua function name
 * as service validator function. It is preferred to set validatorname when a detector is created.
 * Afterwards there is rarely a need to change service name.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @param validatorName/stack - Name of service validator
 * @return int - Number of elements on stack, which is always 0.
 */
static int service_setValidator(lua_State* L)
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    const char* pValidator = lua_tostring(L, 2);
    lua_getglobal(L, pValidator);

    if (!lua_isfunction(L, -1))
    {
        ErrorMessage("%s: attempted setting validator to non-function\n",
            ud->server.serviceModule.name);

        lua_pop(L, 1);
        lua_pushnumber(L, -1);
        return 1;
    }

    lua_pop(L, 1);

    ud->packageInfo.server.validateFunctionName = pValidator;

    lua_pushnumber(L, 0);
    return 1;
}

/** Add data (validator function name) to a flow. Detector use this function when confirming a flow
 * belongs to this service.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @param sourcePort/stack - Source port number.
 * @return int - Number of elements on stack, which is always 0.
 */
static int service_addDataId(lua_State* L)
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);
    uint16_t sport = lua_tonumber(L, 2);

    /*check inputs and whether this function is called in context of a
      packet */
    if ( !checkServiceElement(ud) || !ud->validateParams.pkt )
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    AppIdFlowdataAddId(ud->validateParams.flowp, sport, ud->server.pServiceElement);

    lua_pushnumber(L, 0);
    return 1;
}

/** Add service id to a flow. Positive identification by a detector.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @param serviceId/stack - id of service postively identified on this flow.
 * @param vendorName/stack - name of vendor of service. This is optional.
 * @param version/stack - version of service. This is optional.
 * @return int - Number of elements on stack, which is always 1.
 * @return int/stack - values from enum SERVICE_RETCODE
 */
static int service_addService(
    lua_State* L
    )
{
    char* vendor, * version;
    unsigned int serviceId, retValue = SERVICE_ENULL;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    serviceId = lua_tonumber(L, 2);
    vendor = (char*)luaL_optstring(L, 3, nullptr);
    version = (char*)luaL_optstring(L, 4, nullptr);

    /*check inputs (vendor and version may be null) and whether this function is
      called in context of a packet */
    if ( !checkServiceElement(ud) || !ud->validateParams.pkt )
    {
        lua_pushnumber(L, SERVICE_ENULL);
        return 1;
    }

    /*Phase2 - discuss RNAServiceSubtype will be maintained on lua side therefore the last
      parameter on the following call is nullptr.
      Subtype is not displayed on DC at present. */
    retValue = AppIdServiceAddService(ud->validateParams.flowp, ud->validateParams.pkt,
        ud->validateParams.dir, ud->server.pServiceElement,
        appGetAppFromServiceId(serviceId, ud->pAppidActiveConfig), vendor, version, nullptr);

    lua_pushnumber(L, retValue);
    return 1;
}

/**Function confirms the flow is not running this service.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1.
 * @return int/stack - values from enum SERVICE_RETCODE
 */
static int service_failService(lua_State* L)
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    CHECK_INPUTS();

    unsigned int retValue = AppIdServiceFailService(ud->validateParams.flowp,
        ud->validateParams.pkt,
        ud->validateParams.dir, ud->server.pServiceElement, APPID_SESSION_DATA_NONE,
        ud->pAppidActiveConfig);

    lua_pushnumber(L, retValue);
    return 1;
}

/**Detector use this function to indicate the flow may belong to this flow.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1.
 * @return int/stack - values from enum SERVICE_RETCODE
 */
static int service_inProcessService(lua_State* L)
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    CHECK_INPUTS();

    unsigned int retValue = AppIdServiceInProcess(ud->validateParams.flowp, ud->validateParams.pkt,
        ud->validateParams.dir, ud->server.pServiceElement);

    lua_pushnumber(L, retValue);
    return 1;
}

/**Detector use this function to indicate error in service identification.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1.
 * @return int/stack - values from enum SERVICE_RETCODE
 */
static int service_inCompatibleData(lua_State* L)
{
    unsigned int retValue = SERVICE_ENULL;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    CHECK_INPUTS();

    retValue = AppIdServiceIncompatibleData(ud->validateParams.flowp,
        ud->validateParams.pkt,
        ud->validateParams.dir, ud->server.pServiceElement,
        APPID_SESSION_DATA_NONE, ud->pAppidActiveConfig);

    lua_pushnumber(L, retValue);
    return 1;
}

/** Get size of current packet. It should be noted that due to restrictions on sharing pointers
 * between C and Lua, packet data is maintained on C side. Lua side can get specific fields, run
 * memcmp and pattern matching on packet data.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1 if successful, 0 otherwise.
 * @return packetSize/stack - size of packet on stack, if successful.
 */
static int Detector_getPacketSize(
    lua_State* L
    )
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    lua_pushnumber(L, ud->validateParams.size);
    return 1;
}

/**Get packet direction. A flow/session maintains initiater and responder sides. A packet direction
 * is determined wrt to the original initiater.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1 if successful, 0 otherwise.
 * @return packetDir/stack - direction of packet on stack, if successful.
 */
static int Detector_getPacketDir(
    lua_State* L
    )
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    lua_pushnumber(L, ud->validateParams.dir);
    return 1;
}

/**Perform a pcre match with grouping. A simple regular expression match with no grouping
 * can also be performed.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of group matches.  May be 0 or more.
 * @return matchedStrings/stack - matched strings are pushed on stack starting with group 0.
 *     There may be 0 or more strings.
 */
static int Detector_getPcreGroups(
    lua_State* L
    )
{
    char* pattern;
    unsigned int offset;
    pcre* re;
    int ovector[OVECCOUNT];
    const char* error;
    int erroffset;
    int rc, i;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    pattern = (char*)lua_tostring(L, 2);
    offset = lua_tonumber(L, 3);     /*offset can be zero, no check necessary. */

    {
        /*compile the regular expression pattern, and handle errors */
        re = pcre_compile(
            pattern,              /*the pattern */
            PCRE_DOTALL,          /*default options - dot matches everything including newline */
            &error,               /*for error message */
            &erroffset,           /*for error offset */
            nullptr);                /*use default character tables */

        if (re == nullptr)
        {
            ErrorMessage("PCRE compilation failed at offset %d: %s\n", erroffset, error);
            return 0;
        }

        /*pattern match against the subject string. */
        rc = pcre_exec(
            re,                                         /*compiled pattern */
            nullptr,                                       /*no extra data */
            (char*)ud->validateParams.data,       /*subject string */
            ud->validateParams.size,              /*length of the subject */
            offset,                                     /*offset 0 */
            0,                                          /*default options */
            ovector,                                    /*output vector for substring information
                                                           */
            OVECCOUNT);                                 /*number of elements in the output vector
                                                           */

        if (rc < 0)
        {
            /*Matching failed: clubbing PCRE_ERROR_NOMATCH with other errors. */
            pcre_free(re);
            return 0;
        }

        /*Match succeded */

        /*printf("\nMatch succeeded at offset %d", ovector[0]); */
        pcre_free(re);

        if (rc == 0)
        {
            /*overflow of matches */
            rc = OVECCOUNT/3;
            /*printf("ovector only has room for %d captured substrings", rc - 1); */
            ErrorMessage("ovector only has room for %d captured substrings\n",rc - 1);
        }
    }

    lua_checkstack (L, rc);
    for (i = 0; i < rc; i++)
    {
        /*printf("%2d: %.*s\n", i, , substring_start); */
        lua_pushlstring(L, (char*)ud->validateParams.data + ovector[2*i], ovector[2*i+1] -
            ovector[2*i]);
    }

    return rc;
}

/**Performs a simple memory comparison.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @param pattern/stack - pattern to be matched.
 * @param patternLenght/stack - length of pattern
 * @param offset/stack - offset into packet payload where matching should start.
 *
 * @return int - Number of group matches.  May be 1 if successful, and 0 if error is encountered.
 * @return memCmpResult/stack - returns -1,0,1 based on memcmp result.
 */
static int Detector_memcmp(
    lua_State* L
    )
{
    char* pattern;
    unsigned int patternLen;
    unsigned int offset;
    int rc;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    pattern = (char*)lua_tostring(L, 2);
    patternLen = lua_tonumber(L, 3);
    offset = lua_tonumber(L, 4);     /*offset can be zero, no check necessary. */

    rc = memcmp((char*)ud->validateParams.data + offset, pattern, patternLen);

    lua_checkstack (L, 1);
    lua_pushnumber(L, rc);
    return 1;
}

/**Get Packet Protocol Type
 *
 * @param Lua_State* - Lua state variable.
 * @return int - Number of elements on stack, which is protocol type if successful, 0 otherwise.
 * @return protocol type TCP or UDP
 */
static int Detector_getProtocolType(lua_State* L)
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    if ( !ud->validateParams.pkt || !ud->validateParams.pkt->has_ip() )
    {
        // FIXIT-H J why the inconsistent use of checkstack?
        lua_checkstack (L, 1);
        lua_pushnumber(L, 0);
        return 1;
    }

    lua_checkstack (L, 1);
    // FIXIT-H: is this conversion to double valid?
    lua_pushnumber(L, (double)ud->validateParams.pkt->get_ip_proto_next() );
    return 1;
}

/**Get source IP address from IP header.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return IPv4/stack - Source IPv4 addresss.
 */
static int Detector_getPktSrcIPAddr(lua_State* L)
{
    const sfip_t* ipAddr;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    ipAddr = ud->validateParams.pkt->ptrs.ip_api.get_src();

    lua_checkstack (L, 1);
    lua_pushnumber(L, ipAddr->ip32[0]);
    return 1;
}

/**Get source port number from IP header.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return portNumber/stack - source port number.
 */
static int Detector_getPktSrcPort(lua_State* L)
{
    unsigned int port;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    port = ud->validateParams.pkt->ptrs.sp;

    lua_checkstack (L, 1);
    lua_pushnumber(L, port);
    return 1;
}

/**Get destination port number from IP header.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return portNumber/stack - destination Port number.
 */
static int Detector_getPktDstPort(lua_State* L)
{
    unsigned int port;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    port = ud->validateParams.pkt->ptrs.dp;

    lua_checkstack (L, 1);
    lua_pushnumber(L, port);
    return 1;
}

/**Get destination IP address from IP header.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return IPv4/stack - destination IPv4 addresss.
 */
static int Detector_getPktDstIPAddr(lua_State* L)
{
    const sfip_t* ipAddr;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    ipAddr = ud->validateParams.pkt->ptrs.ip_api.get_dst();

    lua_checkstack (L, 1);
    lua_pushnumber(L, ipAddr->ip32[0]);
    return 1;
}

/**Get packet count. This is used mostly for printing packet sequence
 * number when RNA is being tested with a pcap file.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return packetCount/stack - Total packet processed by RNA.
 */
static int Detector_getPktCount(lua_State* L)
{
    lua_checkstack (L, 1);
    lua_pushnumber(L, app_id_processed_packet_count);
    return 1;
}

CLIENT_APP_RETCODE validateAnyClientApp(
    const uint8_t* data,
    uint16_t size,
    const int dir,
    AppIdData* flowp,
    Packet* pkt,
    Detector* detector,
    const AppIdConfig*
    )
{
    Profile lua_profile_context(luaCustomPerfStats);

    int retValue;
    lua_State* myLuaState;
    const char* validateFn;
    const char* clientName;

    if (!data || !flowp || !pkt || !detector)
    {
        return CLIENT_APP_ENULL;
    }

    myLuaState = detector->myLuaState;
    detector->validateParams.data = data;
    detector->validateParams.size = size;
    detector->validateParams.dir = dir;
    detector->validateParams.flowp = flowp;
    detector->validateParams.pkt = (Packet*)pkt;
    validateFn = detector->packageInfo.client.validateFunctionName.c_str();
    clientName = detector->name.c_str();

    if ((!validateFn) || !(lua_checkstack(myLuaState, 1)))
    {
        ErrorMessage("client %s: invalid LUA %s\n",clientName, lua_tostring(myLuaState, -1));
        detector->validateParams.pkt = nullptr;
        return CLIENT_APP_ENULL;
    }

    lua_getglobal(myLuaState, validateFn);

    DebugFormat(DEBUG_APPID,"client %s: Lua Memory usage %d\n",clientName, lua_gc(myLuaState,
        LUA_GCCOUNT,0));
    DebugFormat(DEBUG_APPID,"client %s: validating\n",clientName);

    if (lua_pcall(myLuaState, 0, 1, 0))
    {
        ErrorMessage("client %s: error validating %s\n",clientName, lua_tostring(myLuaState, -1));
        detector->validateParams.pkt = nullptr;
        return (CLIENT_APP_RETCODE)SERVICE_ENULL;
    }

    /**detectorFlows must be destroyed after each packet is processed.*/
    sflist_static_free_all(&allocatedFlowList, freeDetectorFlow);

    /* retrieve result */
    if (!lua_isnumber(myLuaState, -1))
    {
        ErrorMessage("client %s:  validator returned non-numeric value\n",clientName);
        detector->validateParams.pkt = nullptr;
    }

    retValue = lua_tonumber(myLuaState, -1);
    lua_pop(myLuaState, 1);  /* pop returned value */
    /*lua_settop(myLuaState, 0); */

    DebugFormat(DEBUG_APPID,"client %s: Validator returned %d\n",clientName, retValue);

    detector->validateParams.pkt = nullptr;

    return (CLIENT_APP_RETCODE)retValue;
}

static int client_registerPattern(lua_State* L)
{
    IpProtocol protocol;
    size_t size;
    const char* pattern;
    unsigned int position;
    int index = 1;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    protocol = (IpProtocol)lua_tonumber(L, index++);
    pattern = lua_tostring(L, index++);
    size = lua_tonumber(L, index++);
    position = lua_tonumber(L, index++);

    /*Note: we can not give callback into lua directly so we have to
      give a local callback function, which will do demuxing and
      then call lua callback function. */

    /*mpse library does not hold reference to pattern therefore we dont need to allocate it. */

    ud->client.appModule.userData = ud.ptr;
    ClientAppLoadForConfigCallback((void*)&(ud->client.appModule),
        &ud->pAppidNewConfig->clientAppConfig);
    ClientAppRegisterPattern(
        validateAnyClientApp, protocol, (const uint8_t*)pattern, size,
        position, 0, ud, &ud->pAppidNewConfig->clientAppConfig);

    lua_pushnumber(L, 0);
    return 1;   /*number of results */
}

/**Creates a new detector instance. Creates a new detector instance and leaves the instance
 * on stack. This is the first call by a lua detector to create and instance. Later calls
 * provide the detector instance.
 *
 * @param Lua_State* - Lua state variable.
 * @param serviceName/stack - name of service
 * @param pValidator/stack - service validator function name
 * @param pFini/stack - service clean exit function name
 * @return int - Number of elements on stack, which should be 1 if success 0 otherwise.
 * @return detector - a detector instance on stack if successful
 */

static int client_init(lua_State*)
{
    /*nothing to do */
    return 0;
}

static int service_addClient(lua_State* L)
{
    AppId clienAppId, serviceId;
    const char* version;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    clienAppId = lua_tonumber(L, 2);
    serviceId = lua_tonumber(L, 3);
    version = lua_tostring(L, 4);

    if ( !ud->validateParams.pkt || !version )
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    AppIdAddClientApp(ud->validateParams.flowp, serviceId, clienAppId, version);

    lua_pushnumber(L, 0);
    return 1;
}

static int client_addApp(lua_State* L)
{
    unsigned int serviceId, productId;
    const char* version;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    serviceId = lua_tonumber(L, 2);
    productId = lua_tonumber(L, 4);
    version = lua_tostring(L, 5);

    CHECK_INPUTS();

    if ( !ud->client.appModule.api )
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    ud->client.appModule.api->add_app(ud->validateParams.flowp,
        appGetAppFromServiceId(serviceId, ud->pAppidActiveConfig), appGetAppFromClientId(
        productId, ud->pAppidActiveConfig), version);

    lua_pushnumber(L, 0);
    return 1;
}

static int client_addInfo(lua_State* L)
{
    const char* info;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    info = lua_tostring(L, 2);

    CHECK_INPUTS();

    if (!ud->client.appModule.api)
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    ud->client.appModule.api->add_info(ud->validateParams.flowp, info);

    lua_pushnumber(L, 0);
    return 1;
}

static int client_addUser(lua_State* L)
{
    unsigned int serviceId;
    const char* userName;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    userName = lua_tostring(L, 2);
    serviceId = lua_tonumber(L, 3);

    CHECK_INPUTS();

    if (!ud->client.appModule.api)
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    ud->client.appModule.api->add_user(ud->validateParams.flowp, userName,
        appGetAppFromServiceId(serviceId, ud->pAppidActiveConfig), 1);

    lua_pushnumber(L, 0);
    return 1;
}

static int client_addPayload(lua_State* L)
{
    unsigned int payloadId;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    payloadId = lua_tonumber(L, 2);

    CHECK_INPUTS();

    if (!ud->client.appModule.api)
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    ud->client.appModule.api->add_payload(ud->validateParams.flowp,
        appGetAppFromPayloadId(payloadId, ud->pAppidActiveConfig));

    lua_pushnumber(L, 0);
    return 1;
}

/**Get flow object from a detector object. The flow object is then used with flowApi.
 * A new copy of flow object is provided with every call. This can be optimized by maintaining
 * a single copy.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return packetCount/stack - Total packet processed by RNA.
 * @todo maintain a single copy and return the same copy with every call to Detector_getFlow().
 */
static int Detector_getFlow(lua_State* L)
{
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    CHECK_INPUTS();

    auto df = new DetectorFlow();
    df->pFlow = ud->validateParams.flowp;

    UserData<DetectorFlow>::push(L, "DetectorFlow", df);

    return 1;
}

int Detector_addHttpPattern(lua_State* L)
{
    int index = 1;

    /* Verify detector user data and that we are not in packet context */
    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);

    /* Verify valid pattern type */
    enum httpPatternType pType = (enum httpPatternType)lua_tointeger(L, index++);
    if (pType < HTTP_PAYLOAD || pType > HTTP_URL)
    {
        ErrorMessage("Invalid HTTP pattern type.");
        return 0;
    }

    /* Verify valid DHSequence */
    DHPSequence seq  = (DHPSequence)lua_tointeger(L, index++);
    if (seq < SINGLE || seq > USER_AGENT_HEADER)
    {
        ErrorMessage("Invalid HTTP DHP Sequence.");
        return 0;
    }

    uint32_t service_id      = lua_tointeger(L, index++);
    uint32_t client_app      = lua_tointeger(L, index++);
    /*uint32_t client_app_type =*/ lua_tointeger(L, index++);
    uint32_t payload         = lua_tointeger(L, index++);
    /*uint32_t payload_type    =*/ lua_tointeger(L, index++);

    // FIXIT-H J should this be inverted?
    if (ud->validateParams.pkt)
    {
        ErrorMessage(
            "Invalid detector context addHttpPattern: service_id %u; client_app %u; payload %u\n",
            service_id, client_app, payload);
        return 0;
    }

    /* Verify that pattern is a valid string */
    size_t pattern_size = 0;
    const char* tmpString = lua_tolstring(L, index++, &pattern_size);
    if ( tmpString == nullptr || pattern_size == 0)
    {
        ErrorMessage("Invalid HTTP pattern string.");
        return 0;
    }

    uint8_t* pattern_str = (uint8_t*)snort_strdup(tmpString);
    uint32_t appId = lua_tointeger(L, index++);

    HTTPListElement* element = (HTTPListElement*)snort_calloc(sizeof(HTTPListElement));
    DetectorHTTPPattern* pattern = &element->detectorHTTPPattern;
    AppIdConfig* pConfig = ud->pAppidNewConfig;

    pattern->seq           = seq;
    pattern->service_id    = appGetAppFromServiceId(service_id, pConfig);
    pattern->client_app    = appGetAppFromClientId(client_app, pConfig);
    pattern->payload       = appGetAppFromPayloadId(payload, pConfig);
    pattern->pattern       = pattern_str;
    pattern->pattern_size  = (int)pattern_size;
    pattern->appId         = appId;

    /* for apps that should not show up in 4.10 and ealier, we cannot include an entry in
       the legacy client app or payload tables. We will use the appId instead. This is only for
       user-agents that ID clients. if you want a user-agent to ID a payload, include it in the
       payload database. If you want a host pattern ID, use the other API.  */

    if (!service_id && !client_app && !payload && pType == 2)
    {
        pattern->client_app = appId;
    }

    switch (pType)
    {
    case HTTP_PAYLOAD:
        element->next = pConfig->httpPatternLists.hostPayloadPatternList;
        pConfig->httpPatternLists.hostPayloadPatternList = element;
        break;

    case HTTP_URL:
        element->next = pConfig->httpPatternLists.urlPatternList;
        pConfig->httpPatternLists.urlPatternList = element;
        break;

    case HTTP_USER_AGENT:
        element->next = pConfig->httpPatternLists.clientAgentPatternList;
        pConfig->httpPatternLists.clientAgentPatternList = element;
        break;
    }

    appInfoSetActive(pattern->service_id, true);
    appInfoSetActive(pattern->client_app, true);
    appInfoSetActive(pattern->payload, true);
    appInfoSetActive(appId, true);

    return 0;
}

/*  On the lua side, this should look something like:
        addSSLCertPattern(<appId>, '<pattern string>' )
*/
int Detector_addSSLCertPattern(lua_State* L)
{
    uint8_t* pattern_str;
    size_t pattern_size;
    int index = 1;
    uint8_t type;
    AppId app_id;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    if ( ud->validateParams.pkt )
    {
        ErrorMessage("Invalid SSL detector user data or context.");
        return 0;
    }

    type = lua_tointeger(L, index++);
    app_id  = (AppId)lua_tointeger(L, index++);

    pattern_size = 0;
    const char* tmpString = lua_tolstring(L, index++, &pattern_size);
    if (!tmpString || !pattern_size)
    {
        ErrorMessage("Invalid SSL Host pattern string");
        return 0;
    }
    pattern_str = (uint8_t*)snort_strdup(tmpString);

#ifdef REMOVED_WHILE_NOT_IN_USE
    if (!ssl_add_cert_pattern(pattern_str, pattern_size, type, app_id,
        &ud->pAppidNewConfig->serviceSslConfig))
    {
        snort_free(pattern_str);
        ErrorMessage("Failed to add an SSL pattern list member");
        return 0;
    }
#else
    UNUSED(pattern_str);
    UNUSED(type);
#endif

    appInfoSetActive(app_id, true);
    return 0;
}

/*  On the lua side, this should look something like:
        addDNSHostPattern(<appId>, '<pattern string>' )
*/
int Detector_addDNSHostPattern(lua_State* L)
{
    uint8_t* pattern_str;
    size_t pattern_size;
    int index = 1;
    uint8_t type;
    AppId app_id;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    if ( ud->validateParams.pkt )
    {
        ErrorMessage("LuaDetectorApi:Invalid DNS detector user data or context.");
        return 0;
    }

    type = lua_tointeger(L, index++);
    app_id  = (AppId)lua_tointeger(L, index++);

    pattern_size = 0;
    const char* tmpString = lua_tolstring(L, index++, &pattern_size);
    if (!tmpString || !pattern_size)
    {
        ErrorMessage("LuaDetectorApi:Invalid DNS Host pattern string");
        return 0;
    }
    pattern_str = (uint8_t*)snort_strdup(tmpString);
    if (!dns_add_host_pattern(pattern_str, pattern_size, type, app_id,
        &ud->pAppidNewConfig->serviceDnsConfig))
    {
        snort_free(pattern_str);
        ErrorMessage("LuaDetectorApi:Failed to add an SSL pattern list member");
    }

    return 0;
}

static int Detector_addSSLCnamePattern(lua_State* L)
{
    uint8_t* pattern_str;
    size_t pattern_size;
    int index = 1;
    uint8_t type;
    AppId app_id;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    if ( ud->validateParams.pkt )
    {
        ErrorMessage("Invalid SSL detector user data or context.");
        return 0;
    }

    type = lua_tointeger(L, index++);
    app_id  = (AppId)lua_tointeger(L, index++);

    pattern_size = 0;
    const char* tmpString = lua_tolstring(L, index++, &pattern_size);
    if (!tmpString || !pattern_size)
    {
        ErrorMessage("Invalid SSL Host pattern string");
        return 0;
    }
    pattern_str = (uint8_t*)snort_strdup(tmpString);

#ifdef REMOVED_WHILE_NOT_IN_USE
    if (!ssl_add_cname_pattern(pattern_str, pattern_size, type, app_id,
        &ud->pAppidNewConfig->serviceSslConfig))
    {
        snort_free(pattern_str);
        ErrorMessage("Failed to add an SSL pattern list member");
        return 0;
    }
#else
    UNUSED(pattern_str);
    UNUSED(type);
#endif

    appInfoSetActive(app_id, true);
    return 0;
}

static int Detector_addHostPortApp(lua_State* L)
{
    /*uint8_t *ipaddr_str; */
    size_t ipaddr_size;
    int index = 1;
    uint8_t type;
    AppId app_id;
    in6_addr ip6Addr;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    if ( ud->validateParams.pkt )
    {
        ErrorMessage("%s: Invalid detector user data or context.\n",__func__);
        return 0;
    }

    type = lua_tointeger(L, index++);
    app_id  = (AppId)lua_tointeger(L, index++);

    ipaddr_size = 0;
    const char* tmpString = lua_tolstring(L, index++, &ipaddr_size);
    if (!tmpString || !ipaddr_size)
    {
        ErrorMessage("%s:Invalid ipaddr string\n",__func__);
        return 0;
    }
    if (!strchr(tmpString, ':'))
    {
        if (inet_pton(AF_INET, tmpString, &ip6Addr) <= 0)
        {
            ErrorMessage("%s: Invalid IP address: %s\n",__func__, tmpString);
            return 0;
        }

        // FIXIT-H J ip6Addr type is struct in6_addr, so...
        // ip6Addr.u6_addr32[0] = ip6Addr.u6_addr32[1] =  0;
        // ip6Addr.u6_addr32[2] = ntohl(0x0000ffff);
    }
    else
    {
        if (inet_pton(AF_INET6, tmpString, &ip6Addr) <= 0)
        {
            ErrorMessage("%s: Invalid IP address: %s\n",__func__, tmpString);
            return 0;
        }
    }
    unsigned port  = lua_tointeger(L, index++);
    unsigned proto  = lua_tointeger(L, index++);

    if (proto > UINT8_MAX)
    {
        ErrorMessage("%s:Invalid protocol value %d\n",__func__, proto);
        return 0;
    }

    if (!hostPortAppCacheAdd(&ip6Addr, (uint16_t)port, (IpProtocol)proto, type, app_id,
        ud->pAppidNewConfig))
    {
        ErrorMessage("%s:Failed to backend call\n",__func__);
    }

    return 0;
}

static int Detector_addContentTypePattern(lua_State* L)
{
    uint8_t* pattern;
    AppId appId;
    int index = 1;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);

    size_t stringSize = 0;
    const char* tmpString = lua_tolstring(L, index++, &stringSize);
    if (!tmpString || !stringSize)
    {
        ErrorMessage("Invalid HTTP Header string");
        return 0;
    }
    pattern = (uint8_t*)snort_strdup(tmpString);
    appId = lua_tointeger(L, index++);

    if (ud->validateParams.pkt)
    {
        ErrorMessage("Invalid detector context addSipUserAgent: appId %d\n",appId);
        snort_free(pattern);
        return 0;
    }

    HTTPListElement* element = (HTTPListElement*)snort_calloc(sizeof(HTTPListElement));
    DetectorHTTPPattern* detector = &element->detectorHTTPPattern;
    AppIdConfig* pConfig  = ud->pAppidNewConfig;

    detector->pattern = pattern;
    detector->pattern_size = strlen((char*)pattern);
    detector->appId = appId;

    element->next = pConfig->httpPatternLists.contentTypePatternList;
    pConfig->httpPatternLists.contentTypePatternList = element;

    appInfoSetActive(appId, true);

    return 0;
}

static inline int GetDetectorUserData(lua_State* L, int index,
    UserData<Detector>** detector_user_data, const char* errorString)
{
    // Verify detector user data and that we are not in packet context
    *detector_user_data = UserData<Detector>::check(L, DETECTOR, index);
    if (!*detector_user_data || (**detector_user_data)->validateParams.pkt)
    {
        ErrorMessage("%s", errorString);
        return -1;
    }

    return 0;
}

static int detector_create_chp_app(UserData<Detector>* ud, AppId appIdInstance,
    unsigned app_type_flags, int num_matches)
{
    CHPApp* new_app = (CHPApp*)snort_calloc(sizeof(CHPApp));
    new_app->appIdInstance = appIdInstance;
    new_app->app_type_flags = app_type_flags;
    new_app->num_matches = num_matches;

    if (sfxhash_add((*ud)->pAppidNewConfig->CHP_glossary,
        &(new_app->appIdInstance), new_app))
    {
        ErrorMessage("LuaDetectorApi:Failed to add CHP for appId %d, instance %d",
            CHP_APPIDINSTANCE_TO_ID(appIdInstance), CHP_APPIDINSTANCE_TO_INSTANCE(appIdInstance));
        snort_free(new_app);
        return -1;
    }
    return 0;
}

static int Detector_CHPCreateApp(lua_State* L)
{
    UserData<Detector>* ud;
    AppId appId;
    unsigned app_type_flags;
    int num_matches;

    AppId appIdInstance;

    int index = 1;

    if (GetDetectorUserData(L, index++, &ud,
        "LuaDetectorApi:Invalid HTTP detector user data in CHPCreateApp."))
        return 0;

    appId = lua_tointeger(L, index++);
    appIdInstance = CHP_APPID_SINGLE_INSTANCE(appId); // Last instance for the old API

    app_type_flags =    lua_tointeger(L, index++);
    num_matches =       lua_tointeger(L, index++);

    // We only want one of these for each appId.
    if (sfxhash_find((*ud)->pAppidNewConfig->CHP_glossary, &appIdInstance))
    {
        ErrorMessage(
            "LuaDetectorApi:Attempt to add more than one CHP for appId %d - use CHPMultiCreateApp",
            appId);
        return 0;
    }

    detector_create_chp_app(ud, appIdInstance, app_type_flags, num_matches);
    return 0;
}

static inline int CHPGetKeyPatternBoolean(lua_State* L, int index)
{
    return (0 != lua_tointeger(L, index));
}

static inline int CHPGetPatternType(lua_State* L, int index, PatternType* pattern_type)
{
    *pattern_type = (PatternType)lua_tointeger(L, index);
    if (*pattern_type < AGENT_PT || *pattern_type > MAX_PATTERN_TYPE)
    {
        ErrorMessage("LuaDetectorApi:Invalid CHP Action pattern type.");
        return -1;
    }
    return 0;
}

static inline int CHPGetPatternDataAndSize(lua_State* L, int index, char** pattern_data,
    size_t* pattern_size)
{
    const char* tmpString = nullptr; // Lua owns this pointer
    *pattern_size = 0;
    *pattern_data = nullptr;
    tmpString = lua_tolstring(L, index, &*pattern_size);
    // FIXIT-M: recode all this to something elegant since snort_strdup can't fail (just like Rudy)
    // non-empty pattern required
    if (!tmpString || !*pattern_size || !(*pattern_data = snort_strdup(tmpString)))
    {
        if (*pattern_size) // implies snort_strdup() failed
            ErrorMessage("LuaDetectorApi:CHP Action PATTERN string mem alloc failed.");
        else
            ErrorMessage("LuaDetectorApi:Invalid CHP Action PATTERN string.");  // empty string in
                                                                                // Lua code - bad
        return -1;
    }
    return 0;
}

static inline int CHPGetActionType(lua_State* L, int index, ActionType* action_type)
{
    *action_type = (ActionType)lua_tointeger(L, index);
    if (*action_type < NO_ACTION || *action_type > MAX_ACTION_TYPE)
    {
        ErrorMessage("LuaDetectorApi:Incompatible CHP Action type, might be for a later version.");
        return -1;
    }
    return 0;
}

static inline int CHPGetActionData(lua_State* L, int index, char** action_data)
{
    // An empty string is translated into a nullptr pointer because the action data is optional
    const char* tmpString = nullptr; // Lua owns this pointer
    size_t action_data_size = 0;
    tmpString = lua_tolstring(L, index, &action_data_size);
    if (action_data_size)
        *action_data = snort_strdup(tmpString);
    else
        *action_data = nullptr;

    return 0;
}

static int detector_add_chp_action(UserData<Detector>* ud,
    AppId appIdInstance, int isKeyPattern, PatternType patternType,
    size_t patternSize, char* patternData, ActionType actionType, char* optionalActionData)
{
    uint precedence;
    CHPListElement* tmp_chpa, * chpa;
    CHPApp* chpapp;

    //find the CHP App for this
    if (!(chpapp = (decltype(chpapp))sfxhash_find((*ud)->pAppidNewConfig->CHP_glossary,
            &appIdInstance)))
    {
        ErrorMessage(
            "LuaDetectorApi:Invalid attempt to add a CHP action for unknown appId %d, instance %d. - pattern:\"%s\" - action \"%s\"",
            CHP_APPIDINSTANCE_TO_ID(appIdInstance), CHP_APPIDINSTANCE_TO_INSTANCE(appIdInstance),
            patternData, optionalActionData ? optionalActionData : "");
        snort_free(patternData);
        if (optionalActionData)
            snort_free(optionalActionData);
        return 0;
    }

    if (isKeyPattern)
    {
        chpapp->key_pattern_count++;
        chpapp->key_pattern_length_sum += patternSize;
    }

    if (chpapp->ptype_scan_counts[patternType] == 0)
        chpapp->num_scans++;
    precedence = chpapp->ptype_scan_counts[patternType]++;
    // at runtime we'll want to know how many of each type of pattern we are looking for.
    if (actionType == REWRITE_FIELD || actionType == INSERT_FIELD)
        chpapp->ptype_rewrite_insert_used[patternType]=1; // true.
    else if (actionType != ALTERNATE_APPID)
        chpapp->ptype_req_counts[patternType]++;

    chpa = (CHPListElement*)snort_calloc(sizeof(CHPListElement));
    chpa->chp_action.appIdInstance = appIdInstance;
    chpa->chp_action.precedence = precedence;
    chpa->chp_action.key_pattern = isKeyPattern;
    chpa->chp_action.ptype = patternType;
    chpa->chp_action.psize = patternSize;
    chpa->chp_action.pattern = patternData;
    chpa->chp_action.action = actionType;
    chpa->chp_action.action_data = optionalActionData;
    chpa->chp_action.chpapp = chpapp; // link this struct to the Glossary entry

    AppIdConfig* pConfig = (*ud)->pAppidNewConfig;

    tmp_chpa = pConfig->httpPatternLists.chpList;
    if (!tmp_chpa)
        pConfig->httpPatternLists.chpList = chpa;
    else
    {
        while (tmp_chpa->next)
            tmp_chpa = tmp_chpa->next;
        tmp_chpa->next = chpa;
    }

    /* Set the safe-search bits in the appId entry */
    if (actionType == GET_OFFSETS_FROM_REBUILT)
    {
        /* This is a search engine and it is SUPPORTED for safe-search packet rewrite */
        appInfoEntryFlagSet(CHP_APPIDINSTANCE_TO_ID(appIdInstance), APPINFO_FLAG_SEARCH_ENGINE |
            APPINFO_FLAG_SUPPORTED_SEARCH, pConfig);
    }
    else if (actionType == SEARCH_UNSUPPORTED)
    {
        /* This is a search engine and it is UNSUPPORTED for safe-search packet rewrite */
        appInfoEntryFlagSet(CHP_APPIDINSTANCE_TO_ID(appIdInstance), APPINFO_FLAG_SEARCH_ENGINE,
            pConfig);
    }
    return 0;
}

static int Detector_CHPAddAction(lua_State* L)
{
    UserData<Detector>* ud;
    int key_pattern;
    PatternType ptype;
    size_t psize;
    char* pattern;
    ActionType action;
    char* action_data;

    AppId appIdInstance;
    AppId appId;

    int index = 1;

    if (GetDetectorUserData(L, index++, &ud,
        "LuaDetectorApi:Invalid HTTP detector user data in CHPAddAction."))
        return 0;

    // Parameter 1
    appId = lua_tointeger(L, index++);
    appIdInstance = CHP_APPID_SINGLE_INSTANCE(appId); // Last instance for the old API

    // Parameter 2
    key_pattern = CHPGetKeyPatternBoolean(L, index++);

    // Parameter 3
    if (CHPGetPatternType(L, index++, &ptype))
        return 0;

    // Parameter 4
    if (CHPGetPatternDataAndSize(L, index++, &pattern, &psize))
        return 0;

    // Parameter 5
    if (CHPGetActionType(L, index++, &action))
    {
        snort_free(pattern);
        return 0;
    }

    // Parameter 6
    if (CHPGetActionData(L, index++, &action_data))
    {
        snort_free(pattern);
        return 0;
    }

    return detector_add_chp_action(ud, appIdInstance, key_pattern, ptype,
        psize, pattern, action, action_data);
}

static int Detector_CHPMultiCreateApp(lua_State* L)
{
    UserData<Detector>* ud;
    AppId appId;
    unsigned app_type_flags;
    int num_matches;

    AppId appIdInstance;
    int instance;

    int index = 1;

    if (GetDetectorUserData(L, index++, &ud,
        "LuaDetectorApi:Invalid HTTP detector user data in CHPMultiCreateApp."))
        return 0;

    appId =             lua_tointeger(L, index++);
    app_type_flags =    lua_tointeger(L, index++);
    num_matches =       lua_tointeger(L, index++);

    for (instance=0; instance < CHP_APPID_INSTANCE_MAX; instance++ )
    {
        appIdInstance = (appId << CHP_APPID_BITS_FOR_INSTANCE) + instance;
        if (sfxhash_find((*ud)->pAppidNewConfig->CHP_glossary,
            &appIdInstance))
            continue;
        break;
    }

    // We only want a maximum of these for each appId.
    if (instance == CHP_APPID_INSTANCE_MAX)
    {
        ErrorMessage("LuaDetectorApi:Attempt to create more than %d CHP for appId %d",
            CHP_APPID_INSTANCE_MAX, appId);
        return 0;
    }

    if (detector_create_chp_app(ud, appIdInstance, app_type_flags, num_matches))
        return 0;

    lua_pushnumber(L, appIdInstance);
    return 1;
}

static int Detector_CHPMultiAddAction(lua_State* L)
{
    UserData<Detector>* ud;
    int key_pattern;
    PatternType ptype;
    size_t psize;
    char* pattern;
    ActionType action;
    char* action_data;

    AppId appIdInstance;

    int index = 1;

    if (GetDetectorUserData(L, index++, &ud,
        "LuaDetectorApi:Invalid HTTP detector user data in CHPMultiAddAction."))
        return 0;

    // Parameter 1
    appIdInstance = lua_tointeger(L, index++);

    // Parameter 2
    key_pattern = CHPGetKeyPatternBoolean(L, index++);

    // Parameter 3
    if (CHPGetPatternType(L, index++, &ptype))
        return 0;

    // Parameter 4
    if (CHPGetPatternDataAndSize(L, index++, &pattern, &psize))
        return 0;

    // Parameter 5
    if (CHPGetActionType(L, index++, &action))
    {
        snort_free(pattern);
        return 0;
    }

    // Parameter 6
    if (CHPGetActionData(L, index++, &action_data))
    {
        snort_free(pattern);
        return 0;
    }

    return detector_add_chp_action(ud, appIdInstance, key_pattern, ptype,
        psize, pattern, action, action_data);
}

static int Detector_portOnlyService(lua_State* L)
{
    int index = 1;

    // Verify detector user data and that we are not in packet context
    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    if ( ud->validateParams.pkt )
    {
        ErrorMessage("LuaDetectorApi:Invalid HTTP detector user data in addPortOnlyService.");
        return 0;
    }

    AppId appId = lua_tointeger(L, index++);
    u_int16_t port = lua_tointeger(L, index++);
    u_int8_t protocol = lua_tointeger(L, index++);

    if (port == 0)
        ud->pAppidNewConfig->ip_protocol[protocol] = appId;
    else if (protocol == 6)
        ud->pAppidNewConfig->tcp_port_only[port] = appId;
    else if (protocol == 17)
        ud->pAppidNewConfig->udp_port_only[port] = appId;

    return 0;
}

/* Add a length-based detector.  This is done by adding a new length sequence
 * to the cache.  Note that this does not require a validate and is only used
 * as a fallback identification.
 *
 * @param lua_State* - Lua state variable.
 * @param appId/stack        - App ID to use for this detector.
 * @param proto/stack        - Protocol (IPPROTO_TCP/DC.ipproto.tcp (6) or
 *                             IPPROTO_UDP/DC.ipproto.udp (17)).
 * @param sequence_cnt/stack - Number of elements in sequence below (max of
 *                             LENGTH_SEQUENCE_CNT_MAX).
 * @param sequence_str/stack - String that defines direction/length sequence.
 *  - Example: "I/8,R/512,I/512,R/1024,I/1024"
 *     - Direction: I(nitiator) or R(esponder).
 *     - Length   : Payload size (bytes) (> 0).
 * @return int - Number of elements on stack, which is always 1.
 * @return status/stack - 0 if successful, -1 otherwise.
 */
static int Detector_lengthAppCacheAdd(lua_State* L)
{
    int i;
    const char* str_ptr;
    uint16_t length;
    LengthKey length_sequence;
    int index = 1;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);

    AppId appId = lua_tonumber(L, index++);
    IpProtocol proto = (IpProtocol)lua_tonumber(L, index++);
    uint8_t sequence_cnt = lua_tonumber(L, index++);
    const char* sequence_str = lua_tostring(L, index++);

    if (((proto != IpProtocol::TCP) && (proto != IpProtocol::UDP))
        || ((sequence_cnt == 0) || (sequence_cnt > LENGTH_SEQUENCE_CNT_MAX))
        || ((sequence_str == nullptr) || (strlen(sequence_str) == 0)))
    {
        ErrorMessage("LuaDetectorApi:Invalid input (%d,%u,%u,\"%s\")!",
            appId, (unsigned)proto, (unsigned)sequence_cnt, sequence_str ? sequence_str : "");
        lua_pushnumber(L, -1);
        return 1;
    }

    memset(&length_sequence, 0, sizeof(length_sequence));

    length_sequence.proto        = proto;
    length_sequence.sequence_cnt = sequence_cnt;

    str_ptr = sequence_str;
    for (i = 0; i < sequence_cnt; i++)
    {
        int last_one;

        switch (*str_ptr)
        {
        case 'I':
            length_sequence.sequence[i].direction = APP_ID_FROM_INITIATOR;
            break;
        case 'R':
            length_sequence.sequence[i].direction = APP_ID_FROM_RESPONDER;
            break;
        default:
            ErrorMessage("LuaDetectorApi:Invalid sequence string (\"%s\")!",
                sequence_str);
            lua_pushnumber(L, -1);
            return 1;
        }
        str_ptr++;

        if (*str_ptr != '/')
        {
            ErrorMessage("LuaDetectorApi:Invalid sequence string (\"%s\")!",
                sequence_str);
            lua_pushnumber(L, -1);
            return 1;
        }
        str_ptr++;

        length = (uint16_t)atoi(str_ptr);
        if (length == 0)
        {
            ErrorMessage("LuaDetectorApi:Invalid sequence string (\"%s\")!",
                sequence_str);
            lua_pushnumber(L, -1);
            return 1;
        }
        length_sequence.sequence[i].length = length;

        while ((*str_ptr != ',') && (*str_ptr != 0))
        {
            str_ptr++;
        }

        last_one = (i == (sequence_cnt - 1));
        if (   (!last_one && (*str_ptr != ','))
            || (last_one && (*str_ptr != 0)))
        {
            ErrorMessage("LuaDetectorApi:Invalid sequence string (\"%s\")!",
                sequence_str);
            lua_pushnumber(L, -1);
            return 1;
        }
        str_ptr++;
    }

    if (!lengthAppCacheAdd(&length_sequence, appId, ud->pAppidNewConfig))
    {
        ErrorMessage("LuaDetectorApi:Could not add entry to cache!");
        lua_pushnumber(L, -1);
        return 1;
    }

    lua_pushnumber(L, 0);
    return 1;
}

static int Detector_AFAddApp(lua_State* L)
{
    int index = 1;
    AFElement val;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    if ( ud->validateParams.pkt )
    {
        ErrorMessage("LuaDetectorApi:Invalid HTTP detector user data in AFAddApp.");
        return 0;
    }

    ApplicationId indicator = (ApplicationId)lua_tointeger(L, index++);
    ApplicationId forecast  = (ApplicationId)lua_tointeger(L, index++);
    ApplicationId target    = (ApplicationId)lua_tointeger(L, index++);

    if (sfxhash_find(ud->pAppidNewConfig->AF_indicators, &indicator))
    {
        ErrorMessage("LuaDetectorApi:Attempt to add more than one AFElement per appId %d",
            indicator);
        return 0;
    }

    val.indicator = indicator;
    val.forecast = forecast;
    val.target = target;

    if (sfxhash_add(ud->pAppidNewConfig->AF_indicators, &indicator, &val))
    {
        ErrorMessage("LuaDetectorApi:Failed to add AFElement for appId %d", indicator);
        return 0;
    }

    return 0;
}

static int Detector_addAppUrl(lua_State* L)
{
    int index = 1;
    DetectorAppUrlPattern** tmp;
    const char* tmpString;

    /* Verify detector user data and that we are not in packet context */
    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    if ( ud->validateParams.pkt )
    {
        ErrorMessage("Invalid HTTP detector user data in addAppUrl.");
        return 0;
    }

    u_int32_t service_id      = lua_tointeger(L, index++);
    u_int32_t client_app      = lua_tointeger(L, index++);
    /*u_int32_t client_app_type =*/ lua_tointeger(L, index++);
    u_int32_t payload         = lua_tointeger(L, index++);
    /*u_int32_t payload_type    =*/ lua_tointeger(L, index++);

    if (ud->validateParams.pkt)
    {
        ErrorMessage(
            "Invalid HTTP detector context addAppUrl: service_id %u; client_app %u; payload %u\n",
            service_id, client_app, payload);
        return 0;
    }

    /* Verify that host pattern is a valid string */
    size_t hostPatternSize = 0;
    u_int8_t* hostPattern = nullptr;
    tmpString = lua_tolstring(L, index++, &hostPatternSize);
    if (!tmpString || !hostPatternSize)
    {
        ErrorMessage("Invalid host pattern string.");
        return 0;
    }
    else
        hostPattern = (u_int8_t*)snort_strdup(tmpString);

    /* Verify that path pattern is a valid string */
    size_t pathPatternSize = 0;
    u_int8_t* pathPattern = nullptr;
    tmpString = lua_tolstring(L, index++, &pathPatternSize);
    if (!tmpString || !pathPatternSize )
    {
        ErrorMessage("Invalid path pattern string.");
        snort_free(hostPattern);
        return 0;
    }
    else
        pathPattern = (u_int8_t*)snort_strdup(tmpString);

    /* Verify that scheme pattern is a valid string */
    size_t schemePatternSize;
    u_int8_t* schemePattern = nullptr;
    tmpString = lua_tolstring(L, index++, &schemePatternSize);
    if (!tmpString || !schemePatternSize )
    {
        ErrorMessage("Invalid scheme pattern string.");
        snort_free(pathPattern);
        snort_free(hostPattern);
        return 0;
    }
    else
        schemePattern = (u_int8_t*)snort_strdup(tmpString);

    /* Verify that query pattern is a valid string */
    size_t queryPatternSize;
    u_int8_t* queryPattern = nullptr;
    tmpString = lua_tolstring(L, index++, &queryPatternSize);
    if (tmpString && queryPatternSize)
        queryPattern = (u_int8_t*)snort_strdup(tmpString);
    else
    {
        ErrorMessage("Invalid query pattern string.");
        snort_free(hostPattern);
        snort_free(pathPattern);
        snort_free(schemePattern);
        return 0;
    }

    u_int32_t appId = lua_tointeger(L, index++);

    /* Allocate memory for data structures */
    DetectorAppUrlPattern* pattern =
            (DetectorAppUrlPattern*)snort_calloc(sizeof(DetectorAppUrlPattern));
    AppIdConfig* pConfig = ud->pAppidNewConfig;

    pattern->userData.service_id        = appGetAppFromServiceId(service_id, pConfig);
    pattern->userData.client_app        = appGetAppFromClientId(client_app, pConfig);
    pattern->userData.payload           = appGetAppFromPayloadId(payload, pConfig);
    pattern->userData.appId             = appId;
    pattern->userData.query.pattern     = queryPattern;
    pattern->userData.query.patternSize = queryPatternSize;
    pattern->patterns.host.pattern      = hostPattern;
    pattern->patterns.host.patternSize  = (int)hostPatternSize;
    pattern->patterns.path.pattern      = pathPattern;
    pattern->patterns.path.patternSize  = (int)pathPatternSize;
    pattern->patterns.scheme.pattern    = schemePattern;
    pattern->patterns.scheme.patternSize = (int)schemePatternSize;

    DetectorAppUrlList* urlList = &pConfig->httpPatternLists.appUrlList;

    /**first time usedCount and allocatedCount are both 0, urlPattern will be nullptr.
     * This case is same as malloc. In case of error, realloc will return nullptr, and
     * original urlPattern buffer is left untouched.
     */
    if (urlList->usedCount == urlList->allocatedCount)
    {
        tmp = (decltype(tmp))realloc(urlList->urlPattern, (urlList->allocatedCount+
            URL_LIST_STEP_SIZE)*
            sizeof(*tmp));
        if (!tmp)
        {
            FreeDetectorAppUrlPattern(pattern);
            return 0;
        }
        urlList->urlPattern = tmp;
        urlList->allocatedCount += URL_LIST_STEP_SIZE;
    }

    urlList->urlPattern[urlList->usedCount++] = pattern;

    appInfoSetActive(pattern->userData.service_id, true);
    appInfoSetActive(pattern->userData.client_app, true);
    appInfoSetActive(pattern->userData.payload, true);
    appInfoSetActive(appId, true);

    return 0;
}

static int Detector_addRTMPUrl(lua_State* L)
{
    int index = 1;
    DetectorAppUrlPattern** tmp;
    const char* tmpString;

    /* Verify detector user data and that we are not in packet context */
    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    if ( ud->validateParams.pkt )
    {
        ErrorMessage("Invalid HTTP detector user data in addRTMPUrl.");
        return 0;
    }

    u_int32_t service_id      = lua_tointeger(L, index++);
    u_int32_t client_app      = lua_tointeger(L, index++);
    /*u_int32_t client_app_type =*/ lua_tointeger(L, index++);
    u_int32_t payload         = lua_tointeger(L, index++);
    /*u_int32_t payload_type    =*/ lua_tointeger(L, index++);

    if (ud->validateParams.pkt)
    {
        ErrorMessage(
            "Invalid HTTP detector context addRTMPUrl: service_id %u; client_app %u; payload %u\n",
            service_id, client_app, payload);
        return 0;
    }

    /* Verify that host pattern is a valid string */
    size_t hostPatternSize = 0;
    u_int8_t* hostPattern = nullptr;
    tmpString = lua_tolstring(L, index++, &hostPatternSize);
    // FIXIT - recode all this to something elegant since snort_strdup can't fail (just like Rudy)
    if (!tmpString || !hostPatternSize || !(hostPattern = (u_int8_t*)snort_strdup(tmpString)))
    {
        ErrorMessage("Invalid host pattern string.");
        return 0;
    }

    /* Verify that path pattern is a valid string */
    size_t pathPatternSize = 0;
    u_int8_t* pathPattern = nullptr;
    tmpString = lua_tolstring(L, index++, &pathPatternSize);
    // FIXIT - recode all this to something elegant since snort_strdup can't fail (just like Rudy)
    if (!tmpString || !pathPatternSize || !(pathPattern = (u_int8_t*)snort_strdup(tmpString)))
    {
        ErrorMessage("Invalid path pattern string.");
        snort_free(hostPattern);
        return 0;
    }

    /* Verify that scheme pattern is a valid string */
    size_t schemePatternSize;
    u_int8_t* schemePattern = nullptr;
    tmpString = lua_tolstring(L, index++, &schemePatternSize);
    // FIXIT - recode all this to something elegant since snort_strdup can't fail (just like Rudy)
    if (!tmpString || !schemePatternSize || !(schemePattern = (u_int8_t*)snort_strdup(tmpString)))
    {
        ErrorMessage("Invalid scheme pattern string.");
        snort_free(pathPattern);
        snort_free(hostPattern);
        return 0;
    }

    /* Verify that query pattern is a valid string */
    size_t queryPatternSize;
    u_int8_t* queryPattern = nullptr;
    tmpString = lua_tolstring(L, index++, &queryPatternSize);
    if (tmpString  && queryPatternSize)
        queryPattern = (u_int8_t*)snort_strdup(tmpString);

    u_int32_t appId           = lua_tointeger(L, index++);

    /* Allocate memory for data structures */
    DetectorAppUrlPattern* pattern = (DetectorAppUrlPattern*)snort_calloc(
        sizeof(DetectorAppUrlPattern));

    /* we want to put these patterns in just like for regular Urls, but we do NOT need legacy IDs for them.
     * so just use the appID for service, client, or payload ID */
    pattern->userData.service_id        = service_id;
    pattern->userData.client_app        = client_app;
    pattern->userData.payload           = payload;
    pattern->userData.appId             = appId;
    pattern->userData.query.pattern     = queryPattern;
    pattern->userData.query.patternSize = queryPatternSize;
    pattern->patterns.host.pattern              = hostPattern;
    pattern->patterns.host.patternSize         = (int)hostPatternSize;
    pattern->patterns.path.pattern              = pathPattern;
    pattern->patterns.path.patternSize         = (int)pathPatternSize;
    pattern->patterns.scheme.pattern              = schemePattern;
    pattern->patterns.scheme.patternSize         = (int)schemePatternSize;

    AppIdConfig* pConfig = ud->pAppidNewConfig;
    DetectorAppUrlList* urlList = &pConfig->httpPatternLists.RTMPUrlList;

    /**first time usedCount and allocatedCount are both 0, urlPattern will be nullptr.
     * This case is same as malloc. In case of error, realloc will return nullptr, and
     * original urlPattern buffer is left untouched.
     */
    if (urlList->usedCount == urlList->allocatedCount)
    {
        tmp = (decltype(tmp))realloc(urlList->urlPattern, (urlList->allocatedCount+
            URL_LIST_STEP_SIZE)*
            sizeof(*tmp));
        if (!tmp)
        {
            FreeDetectorAppUrlPattern(pattern);
            return 0;
        }
        urlList->urlPattern = tmp;
        urlList->allocatedCount += URL_LIST_STEP_SIZE;
    }

    urlList->urlPattern[urlList->usedCount++] = pattern;

    appInfoSetActive(pattern->userData.service_id, true);
    appInfoSetActive(pattern->userData.client_app, true);
    appInfoSetActive(pattern->userData.payload, true);
    appInfoSetActive(appId, true);

    return 0;
}

/*Lua should inject patterns in <clienAppId, clientVersion, multi-Pattern> format. */
static int Detector_addSipUserAgent(lua_State* L)
{
    int index = 1;

    /* Verify detector user data and that we are not in packet context */
    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);

    u_int32_t client_app      = lua_tointeger(L, index++);
    const char* clientVersion       = lua_tostring(L, index++);
    if (!clientVersion )
    {
        ErrorMessage("Invalid sip client version string.");
        return 0;
    }

    if (ud->validateParams.pkt)
    {
        ErrorMessage("Invalid detector context addSipUserAgent: client_app %u\n",client_app);
        return 0;
    }

    /* Verify that ua pattern is a valid string */
    const char* uaPattern = lua_tostring(L, index++);
    if (!uaPattern)
    {
        ErrorMessage("Invalid sip ua pattern string.");
        return 0;
    }

#ifdef REMOVED_WHILE_NOT_IN_USE
    sipUaPatternAdd(client_app, clientVersion, uaPattern,
            &ud->pAppidNewConfig->detectorSipConfig);
#endif

    appInfoSetActive(client_app, true);

    return 0;
}

static int openCreateApp(lua_State* L)
{
    int index = 1;
    const char* tmpString;

    /* Verify detector user data and that we are not in packet context */
    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    if ( ud->validateParams.pkt )
    {
        ErrorMessage("Invalid HTTP detector user data in addAppUrl.");
        return 0;
    }

    /* Verify that host pattern is a valid string */
    size_t appNameLen = 0;
    tmpString = lua_tolstring(L, index++, &appNameLen);
    if (!tmpString || !appNameLen)
    {
        ErrorMessage("Invalid appName string.");
        lua_pushnumber(L, APP_ID_NONE);
        return 1;   /*number of results */
    }

    AppInfoTableEntry* entry = appInfoEntryCreate(tmpString,
        ud->pAppidNewConfig);

    if (entry)
    {
        lua_pushnumber(L, entry->appId);
        return 1;   /*number of results */
    }

    lua_pushnumber(L, APP_ID_NONE);
    return 1;   /*number of results */
}

static int openAddClientApp(lua_State* L)
{
    unsigned int serviceAppId, clienAppId;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    serviceAppId = lua_tonumber(L, 2);
    clienAppId = lua_tonumber(L, 3);

    /*check inputs and whether this function is called in context of a
      packet */
    if ( !ud->validateParams.pkt )
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    if (!ud->client.appModule.api)
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    ud->client.appModule.api->add_app(ud->validateParams.flowp, serviceAppId,
        clienAppId, "");

    lua_pushnumber(L, 0);
    return 1;
}

/** Add service id to a flow. Positive identification by a detector.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @param serviceId/stack - id of service postively identified on this flow.
 * @param vendorName/stack - name of vendor of service. This is optional.
 * @param version/stack - version of service. This is optional.
 * @return int - Number of elements on stack, which is always 1.
 * @return int/stack - values from enum SERVICE_RETCODE
 */
static int openAddServiceApp(lua_State* L)
{
    unsigned int serviceId, retValue = SERVICE_ENULL;
    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    serviceId = lua_tonumber(L, 2);

    CHECK_INPUTS();

    /*Phase2 - discuss RNAServiceSubtype will be maintained on lua side therefore the last
      parameter on the following call is nullptr.
      Subtype is not displayed on DC at present. */
    retValue = AppIdServiceAddService(ud->validateParams.flowp, ud->validateParams.pkt,
        ud->validateParams.dir, ud->server.pServiceElement,
        serviceId, nullptr, nullptr, nullptr);

    lua_pushnumber(L, retValue);
    return 1;
}

static int openAddPayloadApp(lua_State* L)
{
    unsigned int payloadAppId;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    payloadAppId = lua_tonumber(L, 2);

    /*check inputs and whether this function is called in context of a
      packet */
    if ( !ud->validateParams.pkt )
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    if (!ud->client.appModule.api)
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    ud->client.appModule.api->add_payload(ud->validateParams.flowp, payloadAppId);

    lua_pushnumber(L, 0);
    return 1;
}

int openAddHttpPattern(lua_State* L)
{
    int index = 1;
    AppIdConfig* pConfig;

    /* Verify detector user data and that we are not in packet context */
    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);

    pConfig = ud->pAppidNewConfig;

    /* Verify valid pattern type */
    enum httpPatternType pType = (enum httpPatternType)lua_tointeger(L, index++);
    if (pType < HTTP_PAYLOAD || pType > HTTP_URL)
    {
        ErrorMessage("Invalid HTTP pattern type.");
        return 0;
    }

    /* Verify valid DHSequence */
    DHPSequence seq  = (DHPSequence)lua_tointeger(L, index++);
    if (seq < SINGLE || seq > USER_AGENT_HEADER)
    {
        ErrorMessage("Invalid HTTP DHP Sequence.");
        return 0;
    }

    uint32_t serviceAppId  = lua_tointeger(L, index++);
    uint32_t clienAppId   = lua_tointeger(L, index++);
    uint32_t payloadAppId  = lua_tointeger(L, index++);

    if (ud->validateParams.pkt)
    {
        ErrorMessage(
            "Invalid detector context addHttpPattern: serviceAppId %u; clienAppId %u; payloadAppId %u\n",
            serviceAppId, clienAppId, payloadAppId);
        return 0;
    }

    /* Verify that pattern is a valid string */
    size_t pattern_size = 0;
    uint8_t* pattern_str = (uint8_t*)snort_strdup(lua_tolstring(L, index++, &pattern_size));
    if (pattern_str == nullptr || pattern_size == 0)
    {
        ErrorMessage("Invalid HTTP pattern string.");
        snort_free(pattern_str);
        return 0;
    }

    HTTPListElement* element = (HTTPListElement*)snort_calloc(sizeof(HTTPListElement));
    DetectorHTTPPattern* pattern = &element->detectorHTTPPattern;
    pattern->seq           = seq;
    pattern->service_id    = serviceAppId;
    pattern->client_app    = clienAppId;
    pattern->payload       = payloadAppId;
    pattern->pattern       = pattern_str;
    pattern->pattern_size  = (int)pattern_size;
    pattern->appId         = APP_ID_NONE;

    switch (pType)
    {
    case HTTP_PAYLOAD:
        element->next = pConfig->httpPatternLists.hostPayloadPatternList;
        pConfig->httpPatternLists.hostPayloadPatternList = element;
        break;

    case HTTP_URL:
        element->next = pConfig->httpPatternLists.urlPatternList;
        pConfig->httpPatternLists.urlPatternList = element;
        break;

    case HTTP_USER_AGENT:
        element->next = pConfig->httpPatternLists.clientAgentPatternList;
        pConfig->httpPatternLists.clientAgentPatternList = element;
        break;
    }

    appInfoSetActive(serviceAppId, true);
    appInfoSetActive(clienAppId, true);
    appInfoSetActive(payloadAppId, true);

    return 0;
}

static int openAddUrlPattern(lua_State* L)
{
    int index = 1;
    DetectorAppUrlPattern** tmp;
    const char* tmpString;

    /* Verify detector user data and that we are not in packet context */
    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);
    if ( ud->validateParams.pkt )
    {
        ErrorMessage("Invalid HTTP detector user data in addAppUrl.");
        return 0;
    }

    AppIdConfig* pConfig = ud->pAppidNewConfig;
    u_int32_t serviceAppId      = lua_tointeger(L, index++);
    u_int32_t clienAppId      = lua_tointeger(L, index++);
    u_int32_t payloadAppId         = lua_tointeger(L, index++);

    if (ud->validateParams.pkt)
    {
        ErrorMessage(
            "Invalid HTTP detector context addAppUrl: serviceAppId %u; clienAppId %u; payloadAppId %u\n",
            serviceAppId, clienAppId, payloadAppId);
        return 0;
    }

    /* Verify that host pattern is a valid string */
    size_t hostPatternSize = 0;
    u_int8_t* hostPattern = nullptr;
    tmpString = lua_tolstring(L, index++, &hostPatternSize);
    if (!tmpString || !hostPatternSize || !(hostPattern = (u_int8_t* )snort_strdup(tmpString)))
    {
        ErrorMessage("Invalid host pattern string.");
        return 0;
    }

    /* Verify that path pattern is a valid string */
    size_t pathPatternSize = 0;
    u_int8_t* pathPattern = nullptr;
    tmpString = lua_tolstring(L, index++, &pathPatternSize);
    if (!tmpString || !pathPatternSize || !(pathPattern = (u_int8_t*)snort_strdup(tmpString)))
    {
        ErrorMessage("Invalid path pattern string.");
        snort_free(hostPattern);
        return 0;
    }

    /* Verify that scheme pattern is a valid string */
    size_t schemePatternSize;
    u_int8_t* schemePattern = nullptr;
    tmpString = lua_tolstring(L, index++, &schemePatternSize);
    if (!tmpString || !schemePatternSize || !(schemePattern = (u_int8_t*)snort_strdup(tmpString)))
    {
        ErrorMessage("Invalid scheme pattern string.");
        snort_free(pathPattern);
        snort_free(hostPattern);
        return 0;
    }

    /* Allocate memory for data structures */
    DetectorAppUrlPattern* pattern = (DetectorAppUrlPattern*)snort_calloc(
        sizeof(DetectorAppUrlPattern));
    pattern->userData.service_id        = serviceAppId;
    pattern->userData.client_app        = clienAppId;
    pattern->userData.payload           = payloadAppId;
    pattern->userData.appId             = APP_ID_NONE;
    pattern->userData.query.pattern     = nullptr;
    pattern->userData.query.patternSize = 0;
    pattern->patterns.host.pattern              = hostPattern;
    pattern->patterns.host.patternSize         = (int)hostPatternSize;
    pattern->patterns.path.pattern              = pathPattern;
    pattern->patterns.path.patternSize         = (int)pathPatternSize;
    pattern->patterns.scheme.pattern              = schemePattern;
    pattern->patterns.scheme.patternSize         = (int)schemePatternSize;

    DetectorAppUrlList* urlList = &pConfig->httpPatternLists.appUrlList;

    /**first time usedCount and allocatedCount are both 0, urlPattern will be nullptr.
     * This case is same as malloc. In case of error, realloc will return nullptr, and
     * original urlPattern buffer is left untouched.
     */
    if (urlList->usedCount == urlList->allocatedCount)
    {
        tmp = (decltype(tmp))realloc(urlList->urlPattern,
            (urlList->allocatedCount + URL_LIST_STEP_SIZE) * sizeof(*tmp));
        if (!tmp)
        {
            FreeDetectorAppUrlPattern(pattern);
            return 0;
        }
        urlList->urlPattern = tmp;
        urlList->allocatedCount += URL_LIST_STEP_SIZE;
    }

    urlList->urlPattern[urlList->usedCount++] = pattern;

    appInfoSetActive(serviceAppId, true);
    appInfoSetActive(clienAppId, true);
    appInfoSetActive(payloadAppId, true);

    return 0;
}

void CleanClientPortPatternList(AppIdConfig* pConfig)
{
    PortPatternNode* tmp;

    if ( pConfig->clientPortPattern)
    {
        while ((tmp = pConfig->clientPortPattern->luaInjectedPatterns))
        {
            pConfig->clientPortPattern->luaInjectedPatterns = tmp->next;
            snort_free(tmp->pattern);
            snort_free(tmp->detectorName);
            snort_free(tmp);
        }

        snort_free(pConfig->clientPortPattern);
    }
}

void CleanServicePortPatternList(AppIdConfig* pConfig)
{
    PortPatternNode* tmp;

    if ( pConfig->servicePortPattern)
    {
        while ((tmp = pConfig->servicePortPattern->luaInjectedPatterns))
        {
            pConfig->servicePortPattern->luaInjectedPatterns = tmp->next;
            snort_free(tmp->pattern);
            snort_free(tmp->detectorName);
            snort_free(tmp);
        }

        snort_free(pConfig->servicePortPattern);
    }
}

/* Add a port and pattern based detection for client application. Both port and pattern criteria
 * must be met before client application is deemed detected.
 *
 * @param lua_State* - Lua state variable.
 * @param proto/stack        - Protocol (IPPROTO_TCP/DC.ipproto.tcp (6) or
 *                             IPPROTO_UDP/DC.ipproto.udp (17)).
 * @param port/stack - port number to register.
 * @param pattern/stack - pattern to be matched.
 * @param patternLenght/stack - length of pattern
 * @param offset/stack - offset into packet payload where matching should start.
 * @param appId/stack        - App ID to use for this detector.
 * @return int - Number of elements on stack, which is always 0.
 */
static int addPortPatternClient(lua_State* L)
{
    int index = 1;
    AppIdConfig* pConfig;
    PortPatternNode* pPattern;
    IpProtocol protocol;
    uint16_t port;
    const char* pattern;
    size_t patternSize = 0;
    unsigned position;
    AppId appId;

    /* Verify detector user data and that we are not in packet context */
    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);

    pConfig = ud->pAppidNewConfig;
    protocol = (IpProtocol)lua_tonumber(L, index++);
    //port      = lua_tonumber(L, index++);
    port = 0;
    pattern = lua_tolstring(L, index++, &patternSize);
    position = lua_tonumber(L, index++);
    appId = lua_tointeger(L, index++);

    if (!pConfig->clientPortPattern)
        pConfig->clientPortPattern =
            (decltype(pConfig->clientPortPattern))snort_calloc(sizeof(ClientPortPattern));

    if (appId <= APP_ID_NONE || !pattern || !patternSize || (protocol != IpProtocol::TCP &&
        protocol !=
        IpProtocol::UDP))
    {
        ErrorMessage("addPortPatternClient(): Invalid input in %s\n",
            ud->name.c_str());
        return 0;
    }
    pPattern  = (decltype(pPattern))snort_calloc(sizeof(PortPatternNode));
    pPattern->pattern  = (decltype(pPattern->pattern))snort_calloc(patternSize);
    pPattern->appId = appId;
    pPattern->protocol = protocol;
    pPattern->port = port;
    memcpy(pPattern->pattern, pattern, patternSize);
    pPattern->length = patternSize;
    pPattern->offset = position;
    pPattern->detectorName = snort_strdup(ud->name.c_str());

    //insert ports in order.
    {
        PortPatternNode** prev;
        PortPatternNode** curr;

        prev = nullptr;
        for (curr = &pConfig->clientPortPattern->luaInjectedPatterns;
            *curr;
            prev = curr, curr = &((*curr)->next))
        {
            if (strcmp(pPattern->detectorName, (*curr)->detectorName) || pPattern->protocol <
                (*curr)->protocol
                || pPattern->port < (*curr)->port)
                break;
        }
        if (prev)
        {
            pPattern->next = (*prev)->next;
            (*prev)->next = pPattern;
        }
        else
        {
            pPattern->next = *curr;
            *curr = pPattern;
        }
    }

    appInfoSetActive(appId, true);

    return 0;
}

/* Add a port and pattern based detection for service application. Both port and pattern criteria
 * must be met before service application is deemed detected.
 *
 * @param lua_State* - Lua state variable.
 * @param proto/stack        - Protocol (IPPROTO_TCP/DC.ipproto.tcp (6) or
 *                             IPPROTO_UDP/DC.ipproto.udp (17)).
 * @param port/stack - port number to register.
 * @param pattern/stack - pattern to be matched.
 * @param patternLenght/stack - length of pattern
 * @param offset/stack - offset into packet payload where matching should start.
 * @param appId/stack        - App ID to use for this detector.
 * @return int - Number of elements on stack, which is always 0.
 */
static int addPortPatternService(lua_State* L)
{
    int index = 1;
    size_t patternSize = 0;
    AppIdConfig* pConfig;
    PortPatternNode* pPattern;
    IpProtocol protocol;
    uint16_t port;
    const char* pattern;
    unsigned position;
    AppId appId;

    /* Verify detector user data and that we are not in packet context */
    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);

    pConfig = ud->pAppidNewConfig;
    protocol = (IpProtocol)lua_tonumber(L, index++);
    port      = lua_tonumber(L, index++);
    pattern = lua_tolstring(L, index++, &patternSize);
    position = lua_tonumber(L, index++);
    appId = lua_tointeger(L, index++);

    if (!pConfig->servicePortPattern)
        pConfig->servicePortPattern =
            (decltype(pConfig->servicePortPattern))snort_calloc(sizeof(ServicePortPattern));

    pPattern = (decltype(pPattern))snort_calloc(sizeof(PortPatternNode));
    pPattern->pattern  = (decltype(pPattern->pattern))snort_calloc(patternSize);
    pPattern->appId = appId;
    pPattern->protocol = protocol;
    pPattern->port = port;
    memcpy(pPattern->pattern, pattern, patternSize);
    pPattern->length = patternSize;
    pPattern->offset = position;
    pPattern->detectorName = snort_strdup(ud->name.c_str());

    //insert ports in order.
    {
        PortPatternNode** prev;
        PortPatternNode** curr;

        prev = nullptr;
        for (curr = &pConfig->servicePortPattern->luaInjectedPatterns;
            *curr;
            prev = curr, curr = &((*curr)->next))
        {
            if (strcmp(pPattern->detectorName, (*curr)->detectorName) || pPattern->protocol <
                (*curr)->protocol
                || pPattern->port < (*curr)->port)
                break;
        }
        if (prev)
        {
            pPattern->next = (*prev)->next;
            (*prev)->next = pPattern;
        }
        else
        {
            pPattern->next = *curr;
            *curr = pPattern;
        }
    }

    appInfoSetActive(appId, true);

    return 0;
}

/*Lua should inject patterns in <clienAppId, clientVersion, multi-Pattern> format. */
static int Detector_addSipServer(lua_State* L)
{
    int index = 1;

    /* Verify detector user data and that we are not in packet context */
    auto& ud = *UserData<Detector>::check(L, DETECTOR, index++);

    u_int32_t client_app      = lua_tointeger(L, index++);
    const char* clientVersion       = lua_tostring(L, index++);
    if (!clientVersion )
    {
        ErrorMessage("Invalid sip client version string.");
        return 0;
    }

    if (ud->validateParams.pkt)
    {
        ErrorMessage("Invalid detector context addSipServer: client_app %u\n",client_app);
        return 0;
    }

    /* Verify that ua pattern is a valid string */
    const char* uaPattern = lua_tostring(L, index++);
    if (!uaPattern)
    {
        ErrorMessage("Invalid sip ua pattern string.");
        return 0;
    }

    // FIXIT - uncomment when sip detector is included in the build
#ifdef REMOVED_WHILE_NOT_IN_USE
    sipServerPatternAdd(client_app, clientVersion, uaPattern,
            &ud->pAppidNewConfig->detectorSipConfig);
#endif
    appInfoSetActive(client_app, true);

    return 0;
}

static inline int ConvertStringToAddress(const char* string, sfip_t* address)
{
    int af;
    struct in6_addr buf;

    if (strchr(string, ':'))
        af = AF_INET6;
    else if (strchr(string, '.'))
        af = AF_INET;
    else
        return 0;

    if (inet_pton(af, string, &buf))
    {
        if (sfip_set_raw(address, &buf, af) != SFIP_SUCCESS)
            return 0;
    }
    else
        return 0;

    return 1;    // success
}

/**Creates a future flow based on the current flow.  When the future flow is
 * seen, the app ID will simply be declared with the info given here.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object.
 * @param client_addr/stack - client address of the future flow
 * @param client_port/stack - client port of the the future flow (can use 0 for wildcard here)
 * @param server_addr/stack - server address of the future flow
 * @param server_port/stack - server port of the future flow
 * @param proto/stack - protocol type (see define IPPROTO_xxxx in /usr/include/netinet/in.h)
 * @param service_app_id/stack - service app ID to declare for future flow (can be 0 for none)
 * @param client_app_id/stack - client app ID to declare for future flow (can be 0 for none)
 * @param payload_app_id/stack - payload app ID to declare for future flow (can be 0 for none)
 * @param app_id_to_snort/stack - AppID's app ID entry to convert to Snort app ID (see note below)
 * @return int - number of elements on stack, which is 1 if successful, 0 otherwise.
 *
 * Notes: For app_id_to_snort, use the app ID that AppID knows about (it'll
 * probably be a repeat of one of the other 3 app IDs given here).  For
 * example, for "FTP Data", use 166.  Internally, this'll be converted to the
 * app ID that Snort recognizes ("ftp-data").  For this to really mean
 * anything, the app IDs entry in appMapping.data should have a Snort app ID
 * defined.
 *
 * Example: createFutureFlow("192.168.0.200", 0, "192.168.0.100", 20, 6, 166, 0, 0, 166)
 */
static int createFutureFlow(lua_State* L)
{
    sfip_t client_addr;
    sfip_t server_addr;
    IpProtocol proto;
    uint16_t client_port, server_port;
    char* pattern;
    AppId service_app_id, client_app_id, payload_app_id, app_id_to_snort;
    int16_t snort_app_id;
    AppIdData* fp;

    auto& ud = *UserData<Detector>::check(L, DETECTOR, 1);

    /*check inputs and whether this function is called in context of a packet */
    if ( !ud->validateParams.pkt )
    {
        return 0;
    }

    pattern = (char*)lua_tostring(L, 2);
    if (!ConvertStringToAddress(pattern, &client_addr))
        return 0;

    client_port = lua_tonumber(L, 3);

    pattern = (char*)lua_tostring(L, 4);
    if (!ConvertStringToAddress(pattern, &server_addr))
        return 0;

    server_port = lua_tonumber(L, 5);

    proto = (IpProtocol)lua_tonumber(L, 6);

    service_app_id = lua_tointeger(L, 7);
    client_app_id  = lua_tointeger(L, 8);
    payload_app_id = lua_tointeger(L, 9);

    app_id_to_snort = lua_tointeger(L, 10);
    if (app_id_to_snort > APP_ID_NONE)
    {
        AppInfoTableEntry* entry = appInfoEntryGet(app_id_to_snort, pAppidActiveConfig);
        if (nullptr == entry)
            return 0;
        snort_app_id = entry->snortId;
    }
    else
    {
        snort_app_id = 0;
    }

    fp = AppIdEarlySessionCreate(ud->validateParams.flowp,
        ud->validateParams.pkt,
        &client_addr, client_port, &server_addr, server_port, proto,
        snort_app_id,
        APPID_EARLY_SESSION_FLAG_FW_RULE);
    if (fp)
    {
        fp->serviceAppId = service_app_id;
        fp->ClientAppId  = client_app_id;
        fp->payloadAppId = payload_app_id;
        setAppIdFlag(fp, APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_NOT_A_SERVICE |
            APPID_SESSION_PORT_SERVICE_DONE);
        fp->rnaServiceState = RNA_STATE_FINISHED;
        fp->rnaClientState  = RNA_STATE_FINISHED;

        return 1;
    }
    else
        return 0;
}

static const luaL_reg Detector_methods[] =
{
    /* Obsolete API names.  No longer use these!  They are here for backward
     * compatibility and will eventually be removed. */
    /*  - "memcmp" is now "matchSimplePattern" (below) */
    { "memcmp",                   Detector_memcmp },
    /*  - "getProtocolType" is now "getL4Protocol" (below) */
    { "getProtocolType",          Detector_getProtocolType },
    /*  - "inCompatibleData" is now "markIncompleteData" (below) */
    { "inCompatibleData",         service_inCompatibleData },
    /*  - "addDataId" is now "addAppIdDataToFlow" (below) */
    { "addDataId",                service_addDataId },
    /*  - "service_inCompatibleData" is now "service_markIncompleteData" (below) */
    { "service_inCompatibleData", service_inCompatibleData },
    /*  - "service_addDataId" is now "service_addAppIdDataToFlow" (below) */
    { "service_addDataId",        service_addDataId },

    { "getPacketSize",            Detector_getPacketSize },
    { "getPacketDir",             Detector_getPacketDir },
    { "matchSimplePattern",       Detector_memcmp },
    { "getPcreGroups",            Detector_getPcreGroups },
    { "getL4Protocol",            Detector_getProtocolType },
    { "getPktSrcAddr",            Detector_getPktSrcIPAddr },
    { "getPktDstAddr",            Detector_getPktDstIPAddr },
    { "getPktSrcPort",            Detector_getPktSrcPort },
    { "getPktDstPort",            Detector_getPktDstPort },
    { "getPktCount",              Detector_getPktCount },
    { "getFlow",                  Detector_getFlow },
    { "htons",                    Detector_htons },
    { "htonl",                    Detector_htonl },
    { "log",                      Detector_logMessage },
    { "addHttpPattern",           Detector_addHttpPattern },
    { "addAppUrl",                Detector_addAppUrl },
    { "addRTMPUrl",               Detector_addRTMPUrl },
    { "addContentTypePattern",    Detector_addContentTypePattern },
    { "addSSLCertPattern",        Detector_addSSLCertPattern },
    { "addSipUserAgent",          Detector_addSipUserAgent },
    { "addSipServer",             Detector_addSipServer },
    { "addSSLCnamePattern",       Detector_addSSLCnamePattern },
    { "addHostPortApp",           Detector_addHostPortApp },
    { "addDNSHostPattern",        Detector_addDNSHostPattern },

    /*Obsolete - new detectors should not use this API */
    { "init",                     service_init },
    { "registerPattern",          service_registerPattern },
    { "getServiceID",             service_getServiceId },
    { "addPort",                  service_addPorts },
    { "removePort",               service_removePorts },
    { "setServiceName",           service_setServiceName },
    { "getServiceName",           service_getServiceName },
    { "isCustomDetector",         service_isCustomDetector },
    { "setValidator",             service_setValidator },
    { "addService",               service_addService },
    { "failService",              service_failService },
    { "inProcessService",         service_inProcessService },
    { "markIncompleteData",       service_inCompatibleData },
    { "analyzePayload",           service_analyzePayload },
    { "addAppIdDataToFlow",       service_addDataId },

    /*service API */
    { "service_init",             service_init },
    { "service_registerPattern",  service_registerPattern },
    { "service_getServiceId",     service_getServiceId },
    { "service_addPort",          service_addPorts },
    { "service_removePort",       service_removePorts },
    { "service_setServiceName",   service_setServiceName },
    { "service_getServiceName",   service_getServiceName },
    { "service_isCustomDetector", service_isCustomDetector },
    { "service_setValidator",     service_setValidator },
    { "service_addService",       service_addService },
    { "service_failService",      service_failService },
    { "service_inProcessService", service_inProcessService },
    { "service_markIncompleteData", service_inCompatibleData },
    { "service_analyzePayload",   service_analyzePayload },
    { "service_addAppIdDataToFlow", service_addDataId },
    { "service_addClient",        service_addClient },

    /*client init API */
    { "client_init",              client_init },
    { "client_registerPattern",   client_registerPattern },
    { "client_getServiceId",      service_getServiceId },

    /*client service API */
    { "client_addApp",            client_addApp },
    { "client_addInfo",           client_addInfo },
    { "client_addUser",           client_addUser },
    { "client_addPayload",        client_addPayload },

    //HTTP Multi Pattern engine
    { "CHPCreateApp",             Detector_CHPCreateApp },
    { "CHPAddAction",             Detector_CHPAddAction },
    { "CHPMultiCreateApp",        Detector_CHPMultiCreateApp },// allows multiple detectors, same
                                                               // appId
    { "CHPMultiAddAction",        Detector_CHPMultiAddAction },

    //App Forecasting engine
    { "AFAddApp",                 Detector_AFAddApp },

    { "portOnlyService",          Detector_portOnlyService },

    /* Length-based detectors. */
    { "AddLengthBasedDetector",   Detector_lengthAppCacheAdd },

    { "registerAppId",           common_registerAppId },

    { "open_createApp",           openCreateApp },
    { "open_addClientApp",        openAddClientApp },
    { "open_addServiceApp",       openAddServiceApp },
    { "open_addPayloadApp",       openAddPayloadApp },
    { "open_addHttpPattern",      openAddHttpPattern },
    { "open_addUrlPattern",       openAddUrlPattern },

    { "addPortPatternClient",     addPortPatternClient },
    { "addPortPatternService",    addPortPatternService },

    { "createFutureFlow",         createFutureFlow },

    { 0, 0 }
};

/**This function performs a clean exit on an api instance. It is called when RNA is performing
 * a clean exit.
 */
void Detector_fini(void* data)
{
    lua_State* myLuaState;
    Detector* detector = (Detector*)data;

    DebugFormat(DEBUG_APPID,"Finishing detector %s\n",detector->server.serviceModule.name);

    myLuaState = detector->myLuaState;

    if ( !detector->packageInfo.server.cleanFunctionName.empty() && lua_checkstack(myLuaState, 1))
    {
        lua_getglobal(myLuaState, detector->packageInfo.server.cleanFunctionName.c_str());

        if (lua_pcall(myLuaState, 0, 0, 0))
        {
            /*See comment at first lua_pcall() */
            ErrorMessage("%s: error running %s in lua: %s", detector->server.serviceModule.name,
                detector->packageInfo.server.cleanFunctionName.c_str(), lua_tostring(myLuaState,
                -1));
        }
    }
    else if ( !detector->packageInfo.client.cleanFunctionName.empty() && lua_checkstack(myLuaState,
        1))
    {
        lua_getglobal(myLuaState, detector->packageInfo.client.cleanFunctionName.c_str());

        if (lua_pcall(myLuaState, 0, 0, 0))
        {
            /*See comment at first lua_pcall() */
            ErrorMessage("%s: error running %s in lua: %s", detector->server.serviceModule.name,
                detector->packageInfo.client.cleanFunctionName.c_str(), lua_tostring(myLuaState,
                -1));
        }
    }
    else
    {
        ErrorMessage("%s: DetectorFini not provided\n", detector->name.c_str());
    }

    freeDetector(detector);

    /*lua_close will perform garbage collection after killing lua script. */
    /**Design: Lua_state does not allow me to store user variables so detectors store lua_state.
     * There is one lua_state for each lua file, which can have only one
     * detectors. So if lua detector creates a detector, registers a pattern
     * and then loses reference then lua will garbage collect but we should not free the buffer.
     *
     */
    lua_close(myLuaState);
}

/**Garbage collector hook function. Called when Lua side garbage collects detector api instance. Current design is to allocate
 * one of each luaState, detector and detectorUserData buffers, and hold these buffers till RNA exits. SigHups processing
 * reuses the buffers and calls DetectorInit to reinitialize. RNA ensures that UserData<Detector> is not garbage collected, by
 * creating a reference in LUA_REGISTRY table. The reference is released only on RNA exit.
 *
 * If in future, one needs to free any of these buffers then one should consider references to detector buffer in  RNAServiceElement
 * stored in flows and hostServices  data structures. Other detectors at this time create one static instance for the lifetime of RNA,
 * and therefore we have adopted the same principle for Lua Detecotors.
 */
static int Detector_gc(lua_State*)
{
    return 0;
}

/*convert detector to string for printing */
static int Detector_tostring(lua_State* L)
{
    lua_pushfstring(L, "Detector (%p)", UserData<Detector>::check(L, DETECTOR, 1));
    return 1;
}

static const luaL_reg Detector_meta[] =
{
    { "__gc",       Detector_gc }, // FIXIT-M J As of right now, Detector_gc is a no-op
    { "__tostring", Detector_tostring },
    { 0, 0 }
};

/**Registers C functions as an API, enabling Lua detector to call these functions. This function
 * should be called once before loading any lua detectors. This function itself is not part of API
 * and therefore can not be called by a Lua detection.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return methodArray/stack - array of newly created methods
 */
int Detector_register(lua_State* L)
{
    /* populates a new table with Detector_methods (method_table), add the table to the globals and
       stack*/
    luaL_openlib(L, DETECTOR, Detector_methods, 0);

    /* create metatable for Foo, add it to the Lua registry, metatable on stack */
    luaL_newmetatable(L, DETECTOR);

    /* populates table on stack with Detector_meta methods, puts the metatable on stack*/
    luaL_openlib(L, nullptr, Detector_meta, 0);

    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);             /* dup methods table*/
    lua_settable(L, -3);                /* metatable.__index = methods */

    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);             /* dup methods table*/
    lua_settable(L, -3);                /* hide metatable:
                                           metatable.__metatable = methods */
    lua_pop(L, 1);                    /* drop metatable */
    return 1;                         /* return methods on the stack */
}

/** @} */ /* end of LuaDetectorBaseApi */

static void FreeHTTPListElement(HTTPListElement* element)
{
    if (element)
    {
        if (element->detectorHTTPPattern.pattern)
            snort_free(element->detectorHTTPPattern.pattern);
        snort_free(element);
    }
}

static void FreeCHPAppListElement(CHPListElement* element)
{
    if (element)
    {
        if (element->chp_action.pattern)
            snort_free(element->chp_action.pattern);
        if (element->chp_action.action_data)
            snort_free(element->chp_action.action_data);
        free (element);
    }
}

static void FreeDetectorAppUrlPattern(DetectorAppUrlPattern* pattern)
{
    if (pattern)
    {
        if (pattern->userData.query.pattern)
            snort_free(*(void**)&pattern->userData.query.pattern);
        if (pattern->patterns.host.pattern)
            snort_free(*(void**)&pattern->patterns.host.pattern);
        if (pattern->patterns.path.pattern)
            snort_free(*(void**)&pattern->patterns.path.pattern);
        if (pattern->patterns.scheme.pattern)
            snort_free(*(void**)&pattern->patterns.scheme.pattern);
        // FIXIT - pattern still allocated with calloc/realloc
        snort_free(pattern);
    }
}

void CleanHttpPatternLists(AppIdConfig* pConfig)
{
    HTTPListElement* element;
    CHPListElement* chpe;
    size_t i;

    for (i = 0; i < pConfig->httpPatternLists.appUrlList.usedCount; i++)
    {
        FreeDetectorAppUrlPattern(pConfig->httpPatternLists.appUrlList.urlPattern[i]);
        pConfig->httpPatternLists.appUrlList.urlPattern[i] = nullptr;
    }
    for (i = 0; i < pConfig->httpPatternLists.RTMPUrlList.usedCount; i++)
    {
        FreeDetectorAppUrlPattern(pConfig->httpPatternLists.RTMPUrlList.urlPattern[i]);
        pConfig->httpPatternLists.RTMPUrlList.urlPattern[i] = nullptr;
    }
    if (pConfig->httpPatternLists.appUrlList.urlPattern)
    {
        snort_free(pConfig->httpPatternLists.appUrlList.urlPattern);
        pConfig->httpPatternLists.appUrlList.urlPattern = nullptr;
    }
    pConfig->httpPatternLists.appUrlList.allocatedCount = 0;
    if (pConfig->httpPatternLists.RTMPUrlList.urlPattern)
    {
        snort_free(pConfig->httpPatternLists.RTMPUrlList.urlPattern);
        pConfig->httpPatternLists.RTMPUrlList.urlPattern = nullptr;
    }
    pConfig->httpPatternLists.RTMPUrlList.allocatedCount = 0;
    pConfig->httpPatternLists.appUrlList.usedCount = 0;
    pConfig->httpPatternLists.RTMPUrlList.usedCount = 0;
    while ((element = pConfig->httpPatternLists.clientAgentPatternList))
    {
        pConfig->httpPatternLists.clientAgentPatternList = element->next;
        FreeHTTPListElement(element);
    }
    while ((element = pConfig->httpPatternLists.hostPayloadPatternList))
    {
        pConfig->httpPatternLists.hostPayloadPatternList = element->next;
        FreeHTTPListElement(element);
    }
    while ((element = pConfig->httpPatternLists.urlPatternList))
    {
        pConfig->httpPatternLists.urlPatternList = element->next;
        FreeHTTPListElement(element);
    }
    while ((element = pConfig->httpPatternLists.contentTypePatternList))
    {
        pConfig->httpPatternLists.contentTypePatternList = element->next;
        FreeHTTPListElement(element);
    }
    while ((chpe = pConfig->httpPatternLists.chpList))
    {
        pConfig->httpPatternLists.chpList = chpe->next;
        FreeCHPAppListElement(chpe);
    }
}

// -----------------------------------------------------------------------------
// Detector
// -----------------------------------------------------------------------------

Detector::~Detector()
{
    if ( server.pServiceElement )
        delete server.pServiceElement;

    // release the reference of the userdata on the lua side
    if ( detectorUserDataRef != LUA_REFNIL )
        luaL_unref(myLuaState, LUA_REGISTRYINDEX, detectorUserDataRef);

    delete[] validatorBuffer;
}

