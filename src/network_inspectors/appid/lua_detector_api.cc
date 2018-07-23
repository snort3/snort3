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

// lua_detector_api.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lua_detector_api.h"

#include <lua.hpp>
#include <pcre.h>
#include <unordered_map>

#include "log/messages.h"
#include "main/snort_types.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "app_forecast.h"
#include "app_info_table.h"
#include "appid_inspector.h"
#include "client_plugins/client_discovery.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/detector_http.h"
#include "detector_plugins/detector_pattern.h"
#include "detector_plugins/detector_sip.h"
#include "detector_plugins/http_url_patterns.h"
#include "host_port_app_cache.h"
#include "lua_detector_flow_api.h"
#include "lua_detector_module.h"
#include "lua_detector_util.h"
#include "service_plugins/service_discovery.h"
#include "service_plugins/service_ssl.h"

using namespace snort;

#define OVECCOUNT 30    /* should be a multiple of 3 */

enum LuaLogLevels
{
    LUA_LOG_CRITICAL = 0,
    LUA_LOG_ERR = 1,
    LUA_LOG_WARN = 2,
    LUA_LOG_NOTICE = 3,
    LUA_LOG_INFO = 4,
    LUA_LOG_TRACE = 5,
};

ProfileStats luaDetectorsPerfStats;
ProfileStats luaCiscoPerfStats;
ProfileStats luaCustomPerfStats;

static std::unordered_map<AppId, CHPApp*>* CHP_glossary = nullptr; // tracks http multipatterns

void init_chp_glossary()
{
    CHP_glossary = new std::unordered_map<AppId, CHPApp*>;
}

void free_chp_glossary()
{
    if (!CHP_glossary)
        return;

    for (auto& entry : *CHP_glossary)
    {
        if (entry.second)
            snort_free(entry.second);
    }
    delete CHP_glossary;
    CHP_glossary = nullptr;
}

static inline int convert_string_to_address(const char* string, SfIp* address)
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
        if (address->set(&buf, af) != SFIP_SUCCESS)
            return 0;
    }
    else
        return 0;

    return 1;    // success
}

static inline bool lua_params_validator(LuaDetectorParameters& ldp, bool packet_context)
{
    if ( packet_context )
    {
        assert(ldp.asd);
        assert(ldp.pkt);
    }
    else
    {
        assert(!ldp.pkt);
    }

#ifdef NDEBUG
    UNUSED(ldp);
#endif

    return true;
}

int init(lua_State* L, int result)
{
    lua_getglobal(L,"is_control");
    auto res = lua_toboolean(L, -1);
    lua_pop(L, 1);

    if (result)
        lua_pushnumber(L, 0);

    return res;
}

// Creates a new detector instance. Creates a new detector instance and leaves the instance
// on stack. This is the first call by a lua detector to create an instance. Later calls
// provide the detector instance.
//
// lua params:
//  #1 - serviceName/stack - name of service
//  #2 - pValidator/stack - service validator function name
//  #3 - pFini/stack - service clean exit function name
//  return - a detector instance or none
static int service_init(lua_State* L)
{
    auto& ud = *UserData<LuaServiceObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    // auto pServiceName = luaL_checkstring(L, 2);
    auto pValidator = luaL_checkstring(L, 3);
    auto pFini = luaL_checkstring(L, 4);

    lua_getfield(L, LUA_REGISTRYINDEX, ud->lsd.package_info.name.c_str());
    lua_getfield(L, -1, pValidator);
    if (lua_isfunction(L, -1))
    {
        lua_pop(L, 1);
        lua_getfield(L, -1, pFini);
        if (lua_isfunction(L, -1))
        {
            lua_pop(L, 1);
            return 1;
        }
    }

    ErrorMessage("%s: attempted setting validator/fini to non-function\n",
        ud->sd->get_name().c_str());
    lua_pop(L, 1);
    return 0;
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
static int service_register_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaServiceObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L, 1)) return 1;

    int index = 1;

    // FIXIT-M  none of these params check for signedness casting issues
    // FIXIT-M May want to create a lua_toipprotocol() so we can handle
    //          error checking in that function.
    IpProtocol protocol = (IpProtocol)lua_tonumber(L, ++index);
    if (protocol > IpProtocol::RESERVED)
    {
        ErrorMessage("Invalid protocol value %u\n", (unsigned)protocol);
        return -1;
    }

    const char* pattern = lua_tostring(L, ++index);
    size_t size = lua_tonumber(L, ++index);
    unsigned int position = lua_tonumber(L, ++index);

    if ( protocol == IpProtocol::TCP)
        ServiceDiscovery::get_instance().register_tcp_pattern(ud->sd, (const uint8_t*)pattern,
            size, position, 0);
    else
        ServiceDiscovery::get_instance().register_udp_pattern(ud->sd, (const uint8_t*)pattern,
            size, position, 0);

    lua_pushnumber(L, 0);
    return 1;
}

static int common_register_application_id(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L, 1)) return 1;

    auto ad = ud->get_detector();

    int index = 1;
    AppId appId = lua_tonumber(L, ++index);

    if ( ad->is_client() )
        ad->register_appid(appId, APPINFO_FLAG_CLIENT_ADDITIONAL);
    else
        ad->register_appid(appId, APPINFO_FLAG_SERVICE_ADDITIONAL);

    AppInfoManager::get_instance().set_app_info_active(appId);

    lua_pushnumber(L, 0);
    return 1;
}

//  Callback could be used either at init
//  or during packet processing
static int detector_htons(lua_State* L)
{
    unsigned short aShort = lua_tonumber(L, 2);

    lua_pushnumber(L, htons(aShort));
    return 1;
}

//  Callback could be used either at init
//  or during packet processing
static int detector_htonl(lua_State* L)
{
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
//  Callback could be used either at init
//  or during packet processing
static int detector_log_message(lua_State* L)
{
    const auto& name = (*UserData<LuaObject>::check(L, DETECTOR, 1))->get_detector()->get_name();

    unsigned int level = lua_tonumber(L, 2);
    const char* message = lua_tostring(L, 3);

    switch ( level )
    {
    case LUA_LOG_CRITICAL:
        FatalError("%s:%s\n", name.c_str(), message);
        break;

    case LUA_LOG_ERR:
    case LUA_LOG_WARN:
        ErrorMessage("%s:%s\n", name.c_str(), message);
        break;

    case LUA_LOG_NOTICE:
    case LUA_LOG_INFO:
        LogMessage("%s:%s\n", name.c_str(), message);
        break;

    case LUA_LOG_TRACE:
        trace_logf(appid_module, "%s:%s\n", name.c_str(), message);
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
static int service_analyze_payload(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    lsd->ldp.asd->payload.set_id(lua_tonumber(L, 2));
    return 0;
}

// FIXIT-M - the comments and code below for service_get_service_id don't appear to be useful
//           the ud->server.service_id field is set to APP_ID_UNKNOWN at init time and never
// updated
//           is this function ever used?
/**design: don't store service_id in detector structure since a single detector
 * can get service_id for multiple protocols. For example SIP which gets Id for RTP and
 * SIP services.
 */

// Get service id from database, given service name. Lua detectors call this function at init time
// get get a service Id (an integer) from database.
// @param serviceName/stack - Name of service
// @return service_id/stack - service_id if successful, -1 otherwise.
static int service_get_service_id(lua_State* L)
{
    auto ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(false);

    lua_pushnumber(L, lsd->service_id);
    return 1;
}

// Add port for a given service. Lua detectors call this function to register ports on which a
// given service is expected to run.
// @param protocol/stack - protocol type. Values can be {tcp=6, udp=17 }
// @param port/stack - port number to register.
// @return status/stack - 0 if successful, -1 otherwise.
static int service_add_ports(lua_State* L)
{
    auto& ud = *UserData<LuaServiceObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L, 1)) return 1;

    ServiceDetectorPort pp;
    pp.proto = (IpProtocol)lua_tonumber(L, 2);
    pp.port = lua_tonumber(L, 3);
    pp.reversed_validation = lua_tonumber(L, 5);

    if ( ((pp.proto != IpProtocol::UDP) && (pp.proto != IpProtocol::TCP)) || !pp.port )
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    if ( ud->sd->get_handler().add_service_port(ud->sd, pp) )
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    lua_pushnumber(L, 0);
    return 1;
}

// Remove all ports for a given service. Lua detectors call this function to remove ports for this
// service when exiting. This function is not used currently by any detectors.
// @return status/stack - 0 if successful, -1 otherwise.
static int service_remove_ports(lua_State* L)
{
    if (!init(L, 1)) return 1;

    // FIXIT-L - do we need to support removing ports registered by specific detector...
    lua_pushnumber(L, 0);
    return 1;
}

// Set service name. Lua detectors call this function to set service name. It is preferred to set
// service name when a detector is created. Afterwards there is rarely a need to change service
// name.
// @param serviceName/stack - Name of service
// @return status/stack - 0 if successful, -1 otherwise.
static int service_set_service_name(lua_State* L)
{
    if (!init(L, 1)) return 1;

    lua_pushnumber(L, 0);
    return 1;
}

/**Get service name. Lua detectors call this function to get service name. There is
 * rarely a need to change service name.
 * Callback could be used either at init or during packet processing
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1.
 * @return serviceName/stack - service name if successful, nil otherwise.
 */
static int service_get_service_name(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    lua_pushstring(L, ud->get_detector()->get_name().c_str());
    return 1;
}

/**Is this a customer defined detector. Lua detectors can call this function to verify if the detector
 * was created by Sourcefire or not.
 * Callback could be used either at init or during packet processing
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1.
 * @return integer/stack - -1 if failed, 0 if sourcefire created, 1 otherwise.
 */
static int service_is_custom_detector(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    lua_pushnumber(L, ud->get_detector()->is_custom_detector());
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
static int service_set_validator(lua_State* L)
{
    auto& ud = *UserData<LuaServiceObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L, 1)) return 1;

    const char* pValidator = lua_tostring(L, 2);
    lua_getfield(L, LUA_REGISTRYINDEX, ud->lsd.package_info.name.c_str());
    lua_getfield(L, -1, pValidator);
    if (!lua_isfunction(L, -1))
    {
        ErrorMessage("%s: attempted setting validator to non-function\n",
            ud->sd->get_name().c_str());

        lua_pop(L, 1);
        lua_pushnumber(L, -1);
        return 1;
    }

    lua_pop(L, 1);
    ud->lsd.package_info.validateFunctionName = pValidator;
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
static int service_add_data_id(lua_State* L)
{
    auto& ud = *UserData<LuaServiceObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    uint16_t sport = lua_tonumber(L, 2);
    lsd->ldp.asd->add_flow_data_id(sport, ud->sd);
    lua_pushnumber(L, 0);
    return 1;
}

/** Add service id to a flow. Positive identification by a detector.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @param service_id/stack - id of service postively identified on this flow.
 * @param vendorName/stack - name of vendor of service. This is optional.
 * @param version/stack - version of service. This is optional.
 * @return int - Number of elements on stack, which is always 1.
 * @return int/stack - values from enum APPID_STATUS_CODE
 */
static int service_add_service(lua_State* L)
{
    auto& ud = *UserData<LuaServiceObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    AppId service_id = lua_tonumber(L, 2);
    const char* vendor = luaL_optstring(L, 3, nullptr);
    const char* version = luaL_optstring(L, 4, nullptr);

    /*Phase2 - discuss AppIdServiceSubtype will be maintained on lua side therefore the last
      parameter on the following call is nullptr. Subtype is not displayed on DC at present. */
    unsigned int retValue = ud->sd->add_service(*lsd->ldp.asd, lsd->ldp.pkt, lsd->ldp.dir,
        AppInfoManager::get_instance().get_appid_by_service_id(service_id),
        vendor, version, nullptr);

    lua_pushnumber(L, retValue);
    return 1;
}

/**Function confirms the flow is not running this service.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1.
 * @return int/stack - values from enum APPID_STATUS_CODE
 */
static int service_fail_service(lua_State* L)
{
    auto& ud = *UserData<LuaServiceObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    ServiceDiscovery& sdm = static_cast<ServiceDiscovery&>(ud->sd->get_handler());
    unsigned int retValue = sdm.fail_service(*lsd->ldp.asd, lsd->ldp.pkt,
        lsd->ldp.dir, nullptr);
    lua_pushnumber(L, retValue);
    return 1;
}

/**Detector use this function to indicate the flow may belong to this flow.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1.
 * @return int/stack - values from enum APPID_STATUS_CODE
 */
static int service_in_process_service(lua_State* L)
{
    auto& ud = *UserData<LuaServiceObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    unsigned int retValue = ud->sd->service_inprocess(*lsd->ldp.asd,
        lsd->ldp.pkt, lsd->ldp.dir);
    lua_pushnumber(L, retValue);
    return 1;
}

/**Detector use this function to indicate error in service identification.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1.
 * @return int/stack - values from enum APPID_STATUS_CODE
 */
static int service_set_incompatible_data(lua_State* L)
{
    auto& ud = *UserData<LuaServiceObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    unsigned int retValue = ud->sd->incompatible_data(*lsd->ldp.asd,
        lsd->ldp.pkt, lsd->ldp.dir);
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
static int detector_get_packet_size(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    lua_pushnumber(L, lsd->ldp.size);
    return 1;
}

/**Get packet direction. A flow/session maintains initiator and responder sides. A packet direction
 * is determined wrt to the original initiator.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1 if successful, 0 otherwise.
 * @return packetDir/stack - direction of packet on stack, if successful.
 */
static int detector_get_packet_direction(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    lua_pushnumber(L, lsd->ldp.dir);
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
static int detector_get_pcre_groups(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    int ovector[OVECCOUNT];
    const char* error;
    int erroffset;

    const char* pattern = lua_tostring(L, 2);
    unsigned int offset = lua_tonumber(L, 3);     /*offset can be zero, no check necessary. */

    /*compile the regular expression pattern, and handle errors */
    pcre* re = pcre_compile(pattern,  // the pattern
        PCRE_DOTALL,                  // default options - dot matches all inc \n
        &error,                       // for error message
        &erroffset,                   // for error offset
        nullptr);                     // use default character tables

    if (re == nullptr)
    {
        ErrorMessage("PCRE compilation failed at offset %d: %s\n", erroffset, error);
        return 0;
    }

    /*pattern match against the subject string. */
    int rc = pcre_exec(re,            // compiled pattern
        nullptr,                      // no extra data
        (const char*)lsd->ldp.data,   // subject string
        lsd->ldp.size,                 // length of the subject
        offset,                       // offset 0
        0,                            // default options
        ovector,                      // output vector for substring information
        OVECCOUNT);                   // number of elements in the output vector

    if ( rc >= 0 )
    {
        if (rc == 0)
        {
            /*overflow of matches */
            rc = OVECCOUNT / 3;
            WarningMessage("ovector only has room for %d captured substrings\n", rc - 1);
        }

        lua_checkstack(L, rc);
        for (int i = 0; i < rc; i++)
        {
            lua_pushlstring(L, (const char*)lsd->ldp.data + ovector[2*i], ovector[2*i+1] -
                ovector[2*i]);
        }
    }
    else
    {
        // log errors except no matches
        if ( rc != PCRE_ERROR_NOMATCH)
            WarningMessage("PCRE regular expression group match failed. rc: %d\n", rc);
        rc = 0;
    }

    pcre_free(re);
    return rc;
}

/**Performs a simple memory comparison.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @param pattern/stack - pattern to be matched.
 * @param patternLength/stack - length of pattern
 * @param offset/stack - offset into packet payload where matching should start.
 *
 * @return int - Number of group matches.  May be 1 if successful, and 0 if error is encountered.
 * @return memCmpResult/stack - returns -1,0,1 based on memcmp result.
 */
static int detector_memcmp(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    const char* pattern = lua_tostring(L, 2);
    unsigned int patternLen = lua_tonumber(L, 3);
    unsigned int offset = lua_tonumber(L, 4);     /*offset can be zero, no check necessary. */
    int rc = memcmp(lsd->ldp.data + offset, pattern, patternLen);
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
static int detector_get_protocol_type(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    if ( !lsd->ldp.pkt->has_ip() )
    {
        // FIXIT-M J why the inconsistent use of checkstack?
        lua_checkstack (L, 1);
        lua_pushnumber(L, 0);
        return 1;
    }

    lua_checkstack (L, 1);
    // FIXIT-M is this conversion to double valid?
    lua_pushnumber(L, (double)lsd->ldp.pkt->get_ip_proto_next() );
    return 1;
}

/**Get source IP address from IP header.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return IPv4/stack - Source IPv4 address.
 */
static int detector_get_packet_src_addr(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    const SfIp* ipAddr = lsd->ldp.pkt->ptrs.ip_api.get_src();
    lua_checkstack (L, 1);
    lua_pushnumber(L, ipAddr->get_ip4_value());
    return 1;
}

/**Get destination IP address from IP header.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return IPv4/stack - destination IPv4 address.
 */
static int detector_get_packet_dst_addr(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    const SfIp* ipAddr = lsd->ldp.pkt->ptrs.ip_api.get_dst();
    lua_checkstack (L, 1);
    lua_pushnumber(L, ipAddr->get_ip4_value());
    return 1;
}

/**Get source port number from IP header.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return portNumber/stack - source port number.
 */
static int detector_get_packet_src_port(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    unsigned int port = lsd->ldp.pkt->ptrs.sp;
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
static int detector_get_packet_dst_port(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    unsigned int port = lsd->ldp.pkt->ptrs.dp;
    lua_checkstack (L, 1);
    lua_pushnumber(L, port);
    return 1;
}

/**Get packet count. This is used mostly for printing packet sequence
 * number when RNA is being tested with a pcap file.
 * Callback could be used either at init or during packet processing
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return packetCount/stack - Total packet processed by RNA.
**/
static int detector_get_packet_count(lua_State* L)
{
    lua_checkstack (L, 1);
    lua_pushnumber(L, appid_stats.processed_packets);
    return 1;
}

static int client_register_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L, 1)) return 1;

    int index = 1;

    IpProtocol protocol = (IpProtocol)lua_tonumber(L, ++index);
    const char* pattern = lua_tostring(L, ++index);
    size_t size = lua_tonumber(L, ++index);
    unsigned int position = lua_tonumber(L, ++index);

    /*Note: we can not give callback into lua directly so we have to
      give a local callback function, which will do demuxing and
      then call lua callback function. */

    /*mpse library does not hold reference to pattern therefore we don't need to allocate it. */

    if ( protocol == IpProtocol::TCP)
        ClientDiscovery::get_instance().register_tcp_pattern(ud->cd, (const uint8_t*)pattern,
            size, position, 0);
    else
        ClientDiscovery::get_instance().register_udp_pattern(ud->cd, (const uint8_t*)pattern,
            size, position, 0);

    lua_pushnumber(L, 0);
    return 1;   /*number of results */
}

/**Creates a new detector instance. Creates a new detector instance and leaves the instance
 * on stack. This is the first call by a lua detector to create an instance. Later calls
 * provide the detector instance.
 * Called at detector initialization
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
    return 0;
}

static int service_add_client(lua_State* L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    AppId client_id = lua_tonumber(L, 2);
    AppId service_id = lua_tonumber(L, 3);
    const char* version = lua_tostring(L, 4);

    if ( !version )
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    ud->cd->add_app(*lsd->ldp.asd, service_id, client_id, version);
    lua_pushnumber(L, 0);
    return 1;
}

static int client_add_application(lua_State* L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    unsigned int service_id = lua_tonumber(L, 2);
    unsigned int productId = lua_tonumber(L, 4);
    const char* version = lua_tostring(L, 5);
    ud->cd->add_app(*lsd->ldp.asd,
        AppInfoManager::get_instance().get_appid_by_service_id(service_id),
        AppInfoManager::get_instance().get_appid_by_client_id(productId), version);

    lua_pushnumber(L, 0);
    return 1;
}

static int client_add_info(lua_State* L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    const char* info = lua_tostring(L, 2);
    ud->cd->add_info(*lsd->ldp.asd, info);
    lua_pushnumber(L, 0);
    return 1;
}

static int client_add_user(lua_State* L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    const char* userName = lua_tostring(L, 2);
    unsigned int service_id = lua_tonumber(L, 3);
    ud->cd->add_user(*lsd->ldp.asd, userName,
        AppInfoManager::get_instance().get_appid_by_service_id(service_id), true);
    lua_pushnumber(L, 0);
    return 1;
}

static int client_add_payload(lua_State* L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    unsigned int payloadId = lua_tonumber(L, 2);
    ud->cd->add_payload(*lsd->ldp.asd,
        AppInfoManager::get_instance().get_appid_by_payload_id(payloadId));

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
static int detector_get_flow(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    auto df = new DetectorFlow();
    df->asd = lsd->ldp.asd;
    UserData<DetectorFlow>::push(L, DETECTORFLOW, df);
    df->myLuaState = L;
    lua_pushvalue(L, -1);
    df->userDataRef = luaL_ref(L, LUA_REGISTRYINDEX);
    LuaDetectorManager::add_detector_flow(df);
    return 1;
}

static int detector_add_http_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    enum httpPatternType pat_type = (enum httpPatternType)lua_tointeger(L, ++index);
    if (pat_type < HTTP_PAYLOAD || pat_type > HTTP_URL)
    {
        ErrorMessage("Invalid HTTP pattern type.");
        return 0;
    }

    DHPSequence seq  = (DHPSequence)lua_tointeger(L, ++index);
    AppInfoManager& aim = AppInfoManager::get_instance();
    uint32_t service_id = aim.get_appid_by_service_id((uint32_t)lua_tointeger(L, ++index));
    uint32_t client_id = aim.get_appid_by_client_id((uint32_t)lua_tointeger(L, ++index));
    /*uint32_t client_app_type =*/ lua_tointeger(L, ++index);
    uint32_t payload_id = aim.get_appid_by_payload_id((uint32_t)lua_tointeger(L, ++index));
    /*uint32_t payload_type    =*/ lua_tointeger(L, ++index);

    size_t pattern_size = 0;
    const uint8_t* pattern_str = (const uint8_t*)lua_tolstring(L, ++index, &pattern_size);
    uint32_t app_id = lua_tointeger(L, ++index);
    DetectorHTTPPattern pattern;
    if ( pattern.init(pattern_str, pattern_size, seq, service_id, client_id,
        payload_id, app_id) )
    {
        HttpPatternMatchers::get_instance()->insert_http_pattern(pat_type, pattern);
        aim.set_app_info_active(service_id);
        aim.set_app_info_active(client_id);
        aim.set_app_info_active(payload_id);
        aim.set_app_info_active(app_id);
    }

    return 0;
}

// for Lua this looks something like: addSSLCertPattern(<appId>, '<pattern string>')
static int detector_add_ssl_cert_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    uint8_t type = lua_tointeger(L, ++index);
    AppId app_id  = (AppId)lua_tointeger(L, ++index);
    size_t pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &pattern_size);
    if (!tmp_string || !pattern_size)
    {
        ErrorMessage("Invalid SSL Host pattern string");
        return 0;
    }

    uint8_t* pattern_str = (uint8_t*)snort_strdup(tmp_string);
    if (!ssl_add_cert_pattern(pattern_str, pattern_size, type, app_id))
    {
        snort_free(pattern_str);
        ErrorMessage("Failed to add an SSL pattern list member");
        return 0;
    }

    AppInfoManager::get_instance().set_app_info_active(app_id);
    return 0;
}

// for Lua this looks something like: addDNSHostPattern(<appId>, '<pattern string>')
static int detector_add_dns_host_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    uint8_t type = lua_tointeger(L, ++index);
    AppId app_id = (AppId)lua_tointeger(L, ++index);

    size_t pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &pattern_size);
    if (!tmp_string || !pattern_size)
    {
        ErrorMessage("LuaDetectorApi:Invalid DNS Host pattern string");
        return 0;
    }

    uint8_t* pattern_str = (uint8_t*)snort_strdup(tmp_string);
    if (!dns_add_host_pattern(pattern_str, pattern_size, type, app_id))
    {
        snort_free(pattern_str);
        ErrorMessage("LuaDetectorApi:Failed to add an SSL pattern list member");
    }

    return 0;
}

static int detector_add_ssl_cname_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    uint8_t type = lua_tointeger(L, ++index);
    AppId app_id  = (AppId)lua_tointeger(L, ++index);

    size_t pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &pattern_size);
    if (!tmp_string || !pattern_size)
    {
        ErrorMessage("Invalid SSL Host pattern string");
        return 0;
    }

    uint8_t* pattern_str = (uint8_t*)snort_strdup(tmp_string);
    if (!ssl_add_cname_pattern(pattern_str, pattern_size, type, app_id))
    {
        snort_free(pattern_str);
        ErrorMessage("Failed to add an SSL pattern list member");
        return 0;
    }

    AppInfoManager::get_instance().set_app_info_active(app_id);
    return 0;
}

static int detector_add_host_port_application(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    SfIp ip_addr;
    int index = 1;

    uint8_t type = lua_tointeger(L, ++index);
    AppId app_id  = (AppId)lua_tointeger(L, ++index);
    size_t ipaddr_size = 0;
    const char* ip_str= lua_tolstring(L, ++index, &ipaddr_size);
    if (!ip_str || !ipaddr_size || !convert_string_to_address(ip_str, &ip_addr))
    {
        ErrorMessage("%s: Invalid IP address: %s\n",__func__, ip_str);
        return 0;
    }

    unsigned port  = lua_tointeger(L, ++index);
    unsigned proto  = lua_tointeger(L, ++index);
    if (proto > (unsigned)IpProtocol::RESERVED)
    {
        ErrorMessage("%s:Invalid protocol value %u\n",__func__, proto);
        return 0;
    }

    if (!HostPortCache::add(&ip_addr, (uint16_t)port, (IpProtocol)proto, type, app_id))
        ErrorMessage("%s:Failed to backend call\n",__func__);

    return 0;
}

static int detector_add_content_type_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    size_t stringSize = 0;
    int index = 1;

    const char* tmp_string = lua_tolstring(L, ++index, &stringSize);
    if (!tmp_string || !stringSize)
    {
        ErrorMessage("Invalid HTTP Header string");
        return 0;
    }
    uint8_t* pattern = (uint8_t*)snort_strdup(tmp_string);
    AppId appId = lua_tointeger(L, ++index);

    DetectorHTTPPattern detector;
    detector.pattern = pattern;
    detector.pattern_size = strlen((char*)pattern);
    detector.app_id = appId;
    HttpPatternMatchers::get_instance()->insert_content_type_pattern(detector);
    AppInfoManager::get_instance().set_app_info_active(appId);

    return 0;
}

static int create_chp_application(AppId appIdInstance, unsigned app_type_flags, int num_matches)
{
    CHPApp* new_app = (CHPApp*)snort_calloc(sizeof(CHPApp));
    new_app->appIdInstance = appIdInstance;
    new_app->app_type_flags = app_type_flags;
    new_app->num_matches = num_matches;

    if (CHP_glossary->insert(std::make_pair(appIdInstance, new_app)).second == false)
    {
        ErrorMessage("LuaDetectorApi:Failed to add CHP for appId %d, instance %d",
            CHP_APPIDINSTANCE_TO_ID(appIdInstance), CHP_APPIDINSTANCE_TO_INSTANCE(appIdInstance));
        snort_free(new_app);
        return -1;
    }
    return 0;
}

static int detector_chp_create_application(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    AppId appId = lua_tointeger(L, ++index);
    AppId appIdInstance = CHP_APPID_SINGLE_INSTANCE(appId); // Last instance for the old API

    unsigned app_type_flags = lua_tointeger(L, ++index);
    int num_matches = lua_tointeger(L, ++index);

    // We only want one of these for each appId.
    if (CHP_glossary->find(appIdInstance) != CHP_glossary->end())
    {
        ErrorMessage(
            "LuaDetectorApi:Attempt to add more than one CHP for appId %d - use CHPMultiCreateApp",
            appId);
        return 0;
    }

    create_chp_application(appIdInstance, app_type_flags, num_matches);
    return 0;
}

static inline int get_chp_key_pattern_boolean(lua_State* L, int index)
{
    return (0 != lua_tointeger(L, index));
}

static inline int get_chp_pattern_type(lua_State* L, int index, HttpFieldIds* pattern_type)
{
    *pattern_type = (HttpFieldIds)lua_tointeger(L, index);
    if ( *pattern_type >= NUM_HTTP_FIELDS )
    {
        ErrorMessage("LuaDetectorApi:Invalid CHP Action pattern type.");
        return -1;
    }
    return 0;
}

static inline int get_chp_pattern_data_and_size(lua_State* L, int index, char** pattern_data,
    size_t* pattern_size)
{
    const char* tmp_string; // Lua owns this pointer
    *pattern_size = 0;
    *pattern_data = nullptr;
    tmp_string = lua_tolstring(L, index, pattern_size);
    // non-empty pattern required
    if (!tmp_string || !*pattern_size)
    {
        ErrorMessage("LuaDetectorApi:Invalid CHP Action PATTERN string.");
        return -1;
    }
    *pattern_data = snort_strdup(tmp_string);
    return 0;
}

static inline int get_chp_action_type(lua_State* L, int index, ActionType* action_type)
{
    *action_type = (ActionType)lua_tointeger(L, index);
    if (*action_type < NO_ACTION || *action_type > MAX_ACTION_TYPE)
    {
        WarningMessage(
            "LuaDetectorApi:Unsupported CHP Action type: %d, possible version mismatch.",
            *action_type);
        return -1;
    }
    return 0;
}

static inline int get_chp_action_data(lua_State* L, int index, char** action_data)
{
    // An empty string is translated into a nullptr pointer because the action data is optional
    size_t action_data_size = 0;
    const char* tmp_string = lua_tolstring(L, index, &action_data_size);
    if (action_data_size)
        *action_data = snort_strdup(tmp_string);
    else
        *action_data = nullptr;

    return 0;
}

static int add_chp_pattern_action(AppId appIdInstance, int isKeyPattern, HttpFieldIds patternType,
    size_t patternSize, char* patternData, ActionType actionType, char* optionalActionData)
{
    //find the CHP App for this
    auto chp_entry = CHP_glossary->find(appIdInstance);
    if (chp_entry == CHP_glossary->end() or !chp_entry->second)
    {
        ErrorMessage(
            "LuaDetectorApi:Invalid attempt to add a CHP action for unknown appId %d, instance %d. - pattern:\"%s\" - action \"%s\"\n",
            CHP_APPIDINSTANCE_TO_ID(appIdInstance), CHP_APPIDINSTANCE_TO_INSTANCE(appIdInstance),
            patternData, optionalActionData ? optionalActionData : "");
        snort_free(patternData);
        if (optionalActionData)
            snort_free(optionalActionData);
        return 0;
    }

    CHPApp* chpapp = chp_entry->second;
    AppInfoManager& app_info_mgr = AppInfoManager::get_instance();

    if (isKeyPattern)
    {
        chpapp->key_pattern_count++;
        chpapp->key_pattern_length_sum += patternSize;
    }

    if (chpapp->ptype_scan_counts[patternType] == 0)
        chpapp->num_scans++;

    unsigned precedence = chpapp->ptype_scan_counts[patternType]++;
    // at runtime we'll want to know how many of each type of pattern we are looking for.
    if (actionType == REWRITE_FIELD || actionType == INSERT_FIELD)
    {
        if (!app_info_mgr.get_app_info_flags(CHP_APPIDINSTANCE_TO_ID(appIdInstance),
            APPINFO_FLAG_SUPPORTED_SEARCH))
        {
            ErrorMessage(
                "LuaDetectorApi: CHP action type, %d, requires previous use of action type, %d, (see appId %d, pattern=\"%s\").\n",
                actionType, GET_OFFSETS_FROM_REBUILT,
                CHP_APPIDINSTANCE_TO_ID(appIdInstance), patternData);
            snort_free(patternData);
            if (optionalActionData)
                snort_free(optionalActionData);
            return 0;
        }
        switch (patternType)
        {
        // permitted pattern type (modifiable HTTP/SPDY request field)
        case REQ_AGENT_FID:
        case REQ_HOST_FID:
        case REQ_REFERER_FID:
        case REQ_URI_FID:
        case REQ_COOKIE_FID:
            break;
        default:
            ErrorMessage(
                "LuaDetectorApi: CHP action type, %d, on unsupported pattern type, %d, (see appId %d, pattern=\"%s\").\n",
                actionType, patternType, CHP_APPIDINSTANCE_TO_ID(appIdInstance), patternData);
            snort_free(patternData);
            if (optionalActionData)
                snort_free(optionalActionData);
            return 0;
        }
    }
    else if (actionType != ALTERNATE_APPID && actionType != DEFER_TO_SIMPLE_DETECT)
        chpapp->ptype_req_counts[patternType]++;

    CHPListElement* chpa = (CHPListElement*)snort_calloc(sizeof(CHPListElement));
    chpa->chp_action.appIdInstance = appIdInstance;
    chpa->chp_action.precedence = precedence;
    chpa->chp_action.key_pattern = isKeyPattern;
    chpa->chp_action.ptype = patternType;
    chpa->chp_action.psize = patternSize;
    chpa->chp_action.pattern = patternData;
    chpa->chp_action.action = actionType;
    chpa->chp_action.action_data = optionalActionData;
    chpa->chp_action.chpapp = chpapp; // link this struct to the Glossary entry
    HttpPatternMatchers::get_instance()->insert_chp_pattern(chpa);

    /* Set the safe-search bits in the appId entry */
    if (actionType == GET_OFFSETS_FROM_REBUILT)
        app_info_mgr.set_app_info_flags(CHP_APPIDINSTANCE_TO_ID(appIdInstance),
            APPINFO_FLAG_SEARCH_ENGINE |
            APPINFO_FLAG_SUPPORTED_SEARCH);
    else if (actionType == SEARCH_UNSUPPORTED)
        app_info_mgr.set_app_info_flags(CHP_APPIDINSTANCE_TO_ID(appIdInstance),
            APPINFO_FLAG_SEARCH_ENGINE);
    else if (actionType == DEFER_TO_SIMPLE_DETECT && strcmp(patternData,"<ignore-all-patterns>") ==
        0)
        HttpPatternMatchers::get_instance()->remove_http_patterns_for_id(appIdInstance);

    return 0;
}

static int detector_add_chp_action(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    HttpFieldIds ptype;
    size_t psize;
    char* pattern;
    ActionType action;
    char* action_data;
    int index = 1;

    // Parameter 1
    AppId appId = lua_tointeger(L, ++index);
    AppId appIdInstance = CHP_APPID_SINGLE_INSTANCE(appId); // Last instance for the old API

    // Parameter 2
    int key_pattern = get_chp_key_pattern_boolean(L, ++index);

    // Parameter 3
    if (get_chp_pattern_type(L, ++index, &ptype))
        return 0;

    // Parameter 4
    if (get_chp_pattern_data_and_size(L, ++index, &pattern, &psize))
        return 0;

    // Parameter 5
    if (get_chp_action_type(L, ++index, &action))
    {
        snort_free(pattern);
        return 0;
    }

    // Parameter 6
    if (get_chp_action_data(L, ++index, &action_data))
    {
        snort_free(pattern);
        return 0;
    }

    return add_chp_pattern_action(appIdInstance, key_pattern, ptype, psize, pattern,
        action, action_data);
}

static int detector_create_chp_multi_application(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    int control = init(L);

    AppId appIdInstance = APP_ID_UNKNOWN;
    int instance;
    int index = 1;

    AppId appId = lua_tointeger(L, ++index);
    unsigned app_type_flags = lua_tointeger(L, ++index);
    int num_matches = lua_tointeger(L, ++index);

    for (instance=0; instance < CHP_APPID_INSTANCE_MAX; instance++ )
    {
        appIdInstance = (appId << CHP_APPID_BITS_FOR_INSTANCE) + instance;
        if (CHP_glossary->find(appIdInstance) != CHP_glossary->end())
            continue;
        break;
    }
    
    if (!control)
    {
        lua_pushnumber(L, appIdInstance);
        return 1;
    }
    
    // We only want a maximum of these for each appId.
    if (instance == CHP_APPID_INSTANCE_MAX)
    {
        ErrorMessage("LuaDetectorApi:Attempt to create more than %d CHP for appId %d",
            CHP_APPID_INSTANCE_MAX, appId);
        return 0;
    }

    if ( create_chp_application(appIdInstance, app_type_flags, num_matches) )
        return 0;

    lua_pushnumber(L, appIdInstance);
    return 1;
}

static int detector_add_chp_multi_action(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    HttpFieldIds ptype;
    size_t psize;
    char* pattern;
    ActionType action;
    char* action_data;
    int index = 1;

    // Parameter 1
    AppId appIdInstance = lua_tointeger(L, ++index);

    // Parameter 2
    int key_pattern = get_chp_key_pattern_boolean(L, ++index);

    // Parameter 3
    if (get_chp_pattern_type(L, ++index, &ptype))
        return 0;

    // Parameter 4
    if (get_chp_pattern_data_and_size(L, ++index, &pattern, &psize))
        return 0;

    // Parameter 5
    if (get_chp_action_type(L, ++index, &action))
    {
        snort_free(pattern);
        return 0;
    }

    // Parameter 6
    if (get_chp_action_data(L, ++index, &action_data))
    {
        snort_free(pattern);
        return 0;
    }

    return add_chp_pattern_action(appIdInstance, key_pattern, ptype, psize, pattern,
        action, action_data);
}

static int detector_port_only_service(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    AppId appId = lua_tointeger(L, ++index);
    uint16_t port = lua_tointeger(L, ++index);
    uint8_t protocol = lua_tointeger(L, ++index);

    AppIdConfig* config = ud->get_detector()->get_handler().get_inspector().get_appid_config();
    if (port == 0)
        config->ip_protocol[protocol] = appId;
    else if (protocol == 6)
        config->tcp_port_only[port] = appId;
    else if (protocol == 17)
        config->udp_port_only[port] = appId;

    AppInfoManager::get_instance().set_app_info_active(appId);

    return 0;
}

/* Add a length-based detector.  This is done by adding a new length sequence
 * to the cache.
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
static int detector_add_length_app_cache(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L, 1)) return 1;

    int i;
    const char* str_ptr;
    int index = 1;

    AppId appId = lua_tonumber(L, ++index);
    IpProtocol proto = (IpProtocol)lua_tonumber(L, ++index);
    uint8_t sequence_cnt = lua_tonumber(L, ++index);
    const char* sequence_str = lua_tostring(L, ++index);

    if (((proto != IpProtocol::TCP) && (proto != IpProtocol::UDP))
        || ((sequence_cnt == 0) || (sequence_cnt > LENGTH_SEQUENCE_CNT_MAX))
        || ((sequence_str == nullptr) || (strlen(sequence_str) == 0)))
    {
        ErrorMessage("LuaDetectorApi:Invalid input (%d,%u,%u,\"%s\")!",
            appId, (unsigned)proto, (unsigned)sequence_cnt, sequence_str ? sequence_str : "");
        lua_pushnumber(L, -1);
        return 1;
    }

    LengthKey length_sequence;
    memset(length_sequence.sequence, 0, sizeof(length_sequence.sequence));
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

        uint16_t length = (uint16_t)atoi(str_ptr);

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

    if ( !add_length_app_cache(length_sequence, appId) )
    {
        ErrorMessage("LuaDetectorApi:Could not add entry to cache!");
        lua_pushnumber(L, -1);
        return 1;
    }

    lua_pushnumber(L, 0);
    return 1;
}

static int detector_add_af_application(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    AppId indicator = (AppId)lua_tointeger(L, ++index);
    AppId forecast  = (AppId)lua_tointeger(L, ++index);
    AppId target    = (AppId)lua_tointeger(L, ++index);
    add_af_indicator(indicator, forecast, target);

    return 0;
}

static int detector_add_url_application(lua_State* L)
{
    // Verify detector user data and that we are NOT in packet context
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    uint32_t service_id      = lua_tointeger(L, ++index);
    uint32_t client_app      = lua_tointeger(L, ++index);
    /*uint32_t client_app_type =*/ lua_tointeger(L, ++index);
    uint32_t payload_id         = lua_tointeger(L, ++index);
    /*uint32_t payload_type    =*/ lua_tointeger(L, ++index);

    /* Verify that host pattern is a valid string */
    size_t host_pattern_size = 0;
    uint8_t* host_pattern = nullptr;
    const char* tmp_string = lua_tolstring(L, ++index, &host_pattern_size);
    if (!tmp_string || !host_pattern_size)
    {
        ErrorMessage("Invalid host pattern string.");
        return 0;
    }
    else
        host_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that path pattern is a valid string */
    size_t path_pattern_size = 0;
    uint8_t* path_pattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &path_pattern_size);
    if (!tmp_string || !path_pattern_size )
    {
        ErrorMessage("Invalid path pattern string.");
        snort_free(host_pattern);
        return 0;
    }
    else
        path_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that scheme pattern is a valid string */
    size_t schemePatternSize;
    uint8_t* schemePattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &schemePatternSize);
    if (!tmp_string || !schemePatternSize )
    {
        ErrorMessage("Invalid scheme pattern string.");
        snort_free(path_pattern);
        snort_free(host_pattern);
        return 0;
    }
    else
        schemePattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that query pattern is a valid string */
    size_t query_pattern_size;
    uint8_t* query_pattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &query_pattern_size);
    if (tmp_string && query_pattern_size)
        query_pattern = (uint8_t*)snort_strdup(tmp_string);

    uint32_t appId = lua_tointeger(L, ++index);
    AppInfoManager& app_info_manager = AppInfoManager::get_instance();
    DetectorAppUrlPattern* pattern =
        (DetectorAppUrlPattern*)snort_calloc(sizeof(DetectorAppUrlPattern));
    pattern->userData.service_id        = app_info_manager.get_appid_by_service_id(service_id);
    pattern->userData.client_id        = app_info_manager.get_appid_by_client_id(client_app);
    pattern->userData.payload_id           = app_info_manager.get_appid_by_payload_id(payload_id);
    pattern->userData.appId             = appId;
    pattern->userData.query.pattern     = query_pattern;
    pattern->userData.query.patternSize = query_pattern_size;
    pattern->patterns.host.pattern      = host_pattern;
    pattern->patterns.host.patternSize  = (int)host_pattern_size;
    pattern->patterns.path.pattern      = path_pattern;
    pattern->patterns.path.patternSize  = (int)path_pattern_size;
    pattern->patterns.scheme.pattern    = schemePattern;
    pattern->patterns.scheme.patternSize = (int)schemePatternSize;
    HttpPatternMatchers::get_instance()->insert_url_pattern(pattern);

    app_info_manager.set_app_info_active(pattern->userData.service_id);
    app_info_manager.set_app_info_active(pattern->userData.client_id);
    app_info_manager.set_app_info_active(pattern->userData.payload_id);
    app_info_manager.set_app_info_active(appId);

    return 0;
}

static int detector_add_rtmp_url(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    uint32_t service_id      = lua_tointeger(L, ++index);
    uint32_t client_app      = lua_tointeger(L, ++index);
    /*uint32_t client_app_type =*/ lua_tointeger(L, ++index);
    uint32_t payload_id         = lua_tointeger(L, ++index);
    /*uint32_t payload_type    =*/ lua_tointeger(L, ++index);

    /* Verify that host pattern is a valid string */
    size_t host_pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &host_pattern_size);
    if (!tmp_string || !host_pattern_size)
    {
        ErrorMessage("Invalid host pattern string.");
        return 0;
    }
    uint8_t* host_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that path pattern is a valid string */
    size_t path_pattern_size = 0;
    tmp_string = lua_tolstring(L, ++index, &path_pattern_size);
    if (!tmp_string || !path_pattern_size)
    {
        ErrorMessage("Invalid path pattern string.");
        snort_free(host_pattern);
        return 0;
    }
    uint8_t* path_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that scheme pattern is a valid string */
    size_t schemePatternSize;
    tmp_string = lua_tolstring(L, ++index, &schemePatternSize);
    if (!tmp_string || !schemePatternSize)
    {
        ErrorMessage("Invalid scheme pattern string.");
        snort_free(path_pattern);
        snort_free(host_pattern);
        return 0;
    }
    uint8_t* schemePattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that query pattern is a valid string */
    size_t query_pattern_size;
    uint8_t* query_pattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &query_pattern_size);
    if (tmp_string  && query_pattern_size)
        query_pattern = (uint8_t*)snort_strdup(tmp_string);

    uint32_t appId = lua_tointeger(L, ++index);

    /* Allocate memory for data structures */
    DetectorAppUrlPattern* pattern =
        (DetectorAppUrlPattern*)snort_calloc(sizeof(DetectorAppUrlPattern));

    /* we want to put these patterns in just like for regular Urls, but we do NOT need legacy IDs for them.
     * so just use the appID for service, client, or payload_id ID */
    pattern->userData.service_id        = service_id;
    pattern->userData.client_id        = client_app;
    pattern->userData.payload_id           = payload_id;
    pattern->userData.appId             = appId;
    pattern->userData.query.pattern     = query_pattern;
    pattern->userData.query.patternSize = query_pattern_size;
    pattern->patterns.host.pattern      = host_pattern;
    pattern->patterns.host.patternSize  = (int)host_pattern_size;
    pattern->patterns.path.pattern      = path_pattern;
    pattern->patterns.path.patternSize  = (int)path_pattern_size;
    pattern->patterns.scheme.pattern    = schemePattern;
    pattern->patterns.scheme.patternSize = (int)schemePatternSize;
    HttpPatternMatchers::get_instance()->insert_rtmp_url_pattern(pattern);

    AppInfoManager& app_info_manager = AppInfoManager::get_instance();
    app_info_manager.set_app_info_active(pattern->userData.service_id);
    app_info_manager.set_app_info_active(pattern->userData.client_id);
    app_info_manager.set_app_info_active(pattern->userData.payload_id);
    app_info_manager.set_app_info_active(appId);

    return 0;
}

/*Lua should inject patterns in <clientAppId, clientVersion, multi-Pattern> format. */
static int detector_add_sip_user_agent(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    uint32_t client_app = lua_tointeger(L, ++index);
    const char* clientVersion = lua_tostring(L, ++index);
    if (!clientVersion )
    {
        ErrorMessage("Invalid sip client version string.");
        return 0;
    }

    /* Verify that ua pattern is a valid string */
    const char* uaPattern = lua_tostring(L, ++index);
    if (!uaPattern)
    {
        ErrorMessage("Invalid sip ua pattern string.");
        return 0;
    }

    SipUdpClientDetector::sipUaPatternAdd(client_app, clientVersion, uaPattern);

    AppInfoManager::get_instance().set_app_info_active(client_app);

    return 0;
}

static int create_custom_application(lua_State* L)
{ 
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    int control = init(L);

    int index = 1;
    AppId appId;

    /* Verify that host pattern is a valid string */
    size_t appNameLen = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &appNameLen);
    if (!tmp_string || !appNameLen)
    {
        ErrorMessage("Invalid appName string.");
        lua_pushnumber(L, APP_ID_NONE);
        return 1;   /*number of results */
    }

    if (control)
    {
        AppInfoTableEntry* entry = AppInfoManager::get_instance().add_dynamic_app_entry(tmp_string);
        appId = entry->appId;
    }
    else 
        appId  = AppInfoManager::get_instance().get_appid_by_name(tmp_string);
       
    if (appId != APP_ID_NONE)
        lua_pushnumber(L, appId);
    else
        lua_pushnumber(L, APP_ID_NONE);
    return 1;   /*number of results */
}

static int add_client_application(lua_State* L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    unsigned int service_id = lua_tonumber(L, 2);
    unsigned int client_id = lua_tonumber(L, 3);

    ud->cd->add_app(*lsd->ldp.asd, service_id, client_id, "");
    lua_pushnumber(L, 0);
    return 1;
}

/** Add service id to a flow. Positive identification by a detector.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @param service_id/stack - id of service postively identified on this flow.
 * @param vendorName/stack - name of vendor of service. This is optional.
 * @param version/stack - version of service. This is optional.
 * @return int - Number of elements on stack, which is always 1.
 * @return int/stack - values from enum APPID_STATUS_CODE
 */
static int add_service_application(lua_State* L)
{
    auto& ud = *UserData<LuaServiceObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    unsigned service_id = lua_tonumber(L, 2);

    /*Phase2 - discuss AppIdServiceSubtype will be maintained on lua side therefore the last
      parameter on the following call is nullptr.
      Subtype is not displayed on DC at present. */
    unsigned retValue = ud->sd->add_service(*lsd->ldp.asd, lsd->ldp.pkt,
        lsd->ldp.dir, service_id);

    lua_pushnumber(L, retValue);
    return 1;
}

static int add_payload_application(lua_State* L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    unsigned payload_id = lua_tonumber(L, 2);
    ud->cd->add_payload(*lsd->ldp.asd, payload_id);
    lua_pushnumber(L, 0);
    return 1;
}

static int add_http_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    /* Verify valid pattern type */
    enum httpPatternType pat_type = (enum httpPatternType)lua_tointeger(L, ++index);
    if (pat_type < HTTP_PAYLOAD || pat_type > HTTP_URL)
    {
        ErrorMessage("Invalid HTTP pattern type.");
        return 0;
    }

    /* Verify valid DHSequence */
    DHPSequence seq  = (DHPSequence)lua_tointeger(L, ++index);
    uint32_t service_id = lua_tointeger(L, ++index);
    uint32_t client_id   = lua_tointeger(L, ++index);
    uint32_t payload_id = lua_tointeger(L, ++index);

    size_t pattern_size = 0;
    const uint8_t* pattern_str = (const uint8_t*)lua_tolstring(L, ++index, &pattern_size);
    DetectorHTTPPattern pattern;
    if ( pattern.init(pattern_str, pattern_size, seq, service_id, client_id,
        payload_id, APP_ID_NONE) )
    {
        HttpPatternMatchers::get_instance()->insert_http_pattern(pat_type, pattern);
        AppInfoManager& app_info_manager = AppInfoManager::get_instance();
        app_info_manager.set_app_info_active(service_id);
        app_info_manager.set_app_info_active(client_id);
        app_info_manager.set_app_info_active(payload_id);
    }

    return 0;
}

static int add_url_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    uint32_t service_id = lua_tointeger(L, ++index);
    uint32_t clientAppId   = lua_tointeger(L, ++index);
    uint32_t payload_id = lua_tointeger(L, ++index);

    /* Verify that host pattern is a valid string */
    size_t host_pattern_size = 0;
    uint8_t* host_pattern = nullptr;
    const char* tmp_string = lua_tolstring(L, ++index, &host_pattern_size);
    if ( !tmp_string || !host_pattern_size )
    {
        ErrorMessage("Invalid host pattern string.");
        return 0;
    }
    host_pattern = (uint8_t* )snort_strdup(tmp_string);

    /* Verify that path pattern is a valid string */
    size_t path_pattern_size = 0;
    uint8_t* path_pattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &path_pattern_size);
    if ( !tmp_string || !path_pattern_size )
    {
        ErrorMessage("Invalid path pattern string.");
        snort_free(host_pattern);
        return 0;
    }
    path_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that scheme pattern is a valid string */
    size_t schemePatternSize;
    uint8_t* schemePattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &schemePatternSize);
    if (!tmp_string || !schemePatternSize)
    {
        ErrorMessage("Invalid scheme pattern string.");
        snort_free(path_pattern);
        snort_free(host_pattern);
        return 0;
    }
    schemePattern = (uint8_t*)snort_strdup(tmp_string);

    /* Allocate memory for data structures */
    DetectorAppUrlPattern* pattern =
        (DetectorAppUrlPattern*)snort_calloc(sizeof(DetectorAppUrlPattern));
    pattern->userData.service_id        = service_id;
    pattern->userData.client_id        = clientAppId;
    pattern->userData.payload_id           = payload_id;
    pattern->userData.appId             = APP_ID_NONE;
    pattern->userData.query.pattern     = nullptr;
    pattern->userData.query.patternSize = 0;
    pattern->patterns.host.pattern      = host_pattern;
    pattern->patterns.host.patternSize  = (int)host_pattern_size;
    pattern->patterns.path.pattern      = path_pattern;
    pattern->patterns.path.patternSize  = (int)path_pattern_size;
    pattern->patterns.scheme.pattern    = schemePattern;
    pattern->patterns.scheme.patternSize = (int)schemePatternSize;
    HttpPatternMatchers::get_instance()->insert_app_url_pattern(pattern);

    AppInfoManager& app_info_manager = AppInfoManager::get_instance();
    app_info_manager.set_app_info_active(service_id);
    app_info_manager.set_app_info_active(clientAppId);
    app_info_manager.set_app_info_active(payload_id);

    return 0;
}

/* Add a port and pattern based detection for client application. Both port and pattern criteria
 * must be met before client application is deemed detected.
 *
 * @param lua_State* - Lua state variable.
 * @param proto/stack        - Protocol (IPPROTO_TCP/DC.ipproto.tcp (6) or
 *                             IPPROTO_UDP/DC.ipproto.udp (17)).
 * @param port/stack - port number to register.
 * @param pattern/stack - pattern to be matched.
 * @param patternLength/stack - length of pattern
 * @param offset/stack - offset into packet payload where matching should start.
 * @param appId/stack        - App ID to use for this detector.
 * @return int - Number of elements on stack, which is always 0.
 */
static int add_port_pattern_client(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    size_t patternSize = 0;
    int index = 1;

    IpProtocol protocol = (IpProtocol)lua_tonumber(L, ++index);
    uint16_t port = 0;      //port      = lua_tonumber(L, ++index);  FIXIT-L - why commented out?
    const char* pattern = lua_tolstring(L, ++index, &patternSize);
    unsigned position = lua_tonumber(L, ++index);
    AppId appId = lua_tointeger(L, ++index);
    if (appId <= APP_ID_NONE || !pattern || !patternSize ||
        (protocol != IpProtocol::TCP && protocol != IpProtocol::UDP))
    {
        ErrorMessage("addPortPatternClient(): Invalid input in %s\n", ud->get_detector()->get_name().c_str());
        return 0;
    }

    PortPatternNode* pPattern  = (decltype(pPattern))snort_calloc(sizeof(PortPatternNode));
    pPattern->pattern  = (decltype(pPattern->pattern))snort_calloc(patternSize);
    pPattern->appId = appId;
    pPattern->protocol = protocol;
    pPattern->port = port;
    memcpy(pPattern->pattern, pattern, patternSize);
    pPattern->length = patternSize;
    pPattern->offset = position;
    pPattern->detectorName = snort_strdup(ud->get_detector()->get_name().c_str());
    PatternClientDetector::insert_client_port_pattern(pPattern);

    AppInfoManager::get_instance().set_app_info_active(appId);

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
 * @param patternLength/stack - length of pattern
 * @param offset/stack - offset into packet payload where matching should start.
 * @param appId/stack        - App ID to use for this detector.
 * @return int - Number of elements on stack, which is always 0.
 */
static int add_port_pattern_service(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    size_t patternSize = 0;
    int index = 1;

    IpProtocol protocol = (IpProtocol)lua_tonumber(L, ++index);
    uint16_t port = lua_tonumber(L, ++index);
    const char* pattern = lua_tolstring(L, ++index, &patternSize);
    unsigned position = lua_tonumber(L, ++index);
    AppId appId = lua_tointeger(L, ++index);

    PortPatternNode* pPattern = (decltype(pPattern))snort_calloc(sizeof(PortPatternNode));
    pPattern->pattern  = (decltype(pPattern->pattern))snort_calloc(patternSize);
    pPattern->appId = appId;
    pPattern->protocol = protocol;
    pPattern->port = port;
    memcpy(pPattern->pattern, pattern, patternSize);
    pPattern->length = patternSize;
    pPattern->offset = position;
    pPattern->detectorName = snort_strdup(ud->get_detector()->get_name().c_str());
    PatternServiceDetector::insert_service_port_pattern(pPattern);
    AppInfoManager::get_instance().set_app_info_active(appId);

    return 0;
}

/*Lua should inject patterns in <clientAppId, clientVersion, multi-Pattern> format. */
static int detector_add_sip_server(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L)) return 0;

    int index = 1;

    uint32_t client_app = lua_tointeger(L, ++index);
    const char* clientVersion = lua_tostring(L, ++index);
    if (!clientVersion )
    {
        ErrorMessage("Invalid sip client version string.");
        return 0;
    }

    /* Verify that ua pattern is a valid string */
    const char* uaPattern = lua_tostring(L, ++index);
    if (!uaPattern)
    {
        ErrorMessage("Invalid sip ua pattern string.");
        return 0;
    }

    SipUdpClientDetector::sipServerPatternAdd(client_app, clientVersion, uaPattern);
    AppInfoManager::get_instance().set_app_info_active(client_app);

    return 0;
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
 * @param service_id/stack - service app ID to declare for future flow (can be 0 for none)
 * @param client_id/stack - client app ID to declare for future flow (can be 0 for none)
 * @param payload_id/stack - payload app ID to declare for future flow (can be 0 for none)
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
static int create_future_flow(lua_State* L)
{
    auto ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    SfIp client_addr;
    SfIp server_addr;
    SnortProtocolId snort_protocol_id = UNKNOWN_PROTOCOL_ID;

    const char* pattern = lua_tostring(L, 2);
    if (!convert_string_to_address(pattern, &client_addr))
        return 0;

    uint16_t client_port = lua_tonumber(L, 3);

    pattern = lua_tostring(L, 4);
    if (!convert_string_to_address(pattern, &server_addr))
        return 0;

    uint16_t server_port = lua_tonumber(L, 5);
    IpProtocol proto = (IpProtocol)lua_tonumber(L, 6);
    AppId service_id = lua_tointeger(L, 7);
    AppId client_id  = lua_tointeger(L, 8);
    AppId payload_id = lua_tointeger(L, 9);
    AppId app_id_to_snort = lua_tointeger(L, 10);
    if (app_id_to_snort > APP_ID_NONE)
    {
        AppInfoTableEntry* entry = AppInfoManager::get_instance().get_app_info_entry(
            app_id_to_snort);
        if (!entry)
            return 0;
        snort_protocol_id = entry->snort_protocol_id;
    }

    AppIdSession* fp = AppIdSession::create_future_session(lsd->ldp.pkt,  &client_addr,
        client_port, &server_addr, server_port, proto, snort_protocol_id,
        APPID_EARLY_SESSION_FLAG_FW_RULE, ud->get_detector()->get_handler().get_inspector());
    if (fp)
    {
        fp->service.set_id(service_id);
        fp->client.set_id(client_id);
        fp->payload.set_id(payload_id);
        fp->set_session_flags(APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_NOT_A_SERVICE |
            APPID_SESSION_PORT_SERVICE_DONE);
        fp->service_disco_state = APPID_DISCO_STATE_FINISHED;
        fp->client_disco_state  = APPID_DISCO_STATE_FINISHED;

        return 1;
    }
    else
        return 0;
}

static const luaL_Reg detector_methods[] =
{
    /* Obsolete API names.  No longer use these!  They are here for backward
     * compatibility and will eventually be removed. */
    { "memcmp",                   detector_memcmp },                 //  - "memcmp" is now
                                                                     // "matchSimplePattern"
                                                                     // (below)
    { "getProtocolType",          detector_get_protocol_type },      //  - "getProtocolType" is now
                                                                     // "getL4Protocol" (below)
    { "inCompatibleData",         service_set_incompatible_data },   //  - "inCompatibleData" is
                                                                     // now "markIncompleteData"
                                                                     // (below)
    { "addDataId",                service_add_data_id },             //  - "addDataId" is now
                                                                     // "addAppIdDataToFlow"
                                                                     // (below)
    { "service_inCompatibleData", service_set_incompatible_data },   //  - "service_inCompatibleData"
                                                                     // is now
                                                                     // "service_markIncompleteData"
                                                                     // (below)
    { "service_addDataId",        service_add_data_id },             //  - "service_addDataId" is
                                                                     // now
                                                                     // "service_addAppIdDataToFlow"
                                                                     // (below)

    { "getPacketSize",            detector_get_packet_size },
    { "getPacketDir",             detector_get_packet_direction },
    { "matchSimplePattern",       detector_memcmp },
    { "getPcreGroups",            detector_get_pcre_groups },
    { "getL4Protocol",            detector_get_protocol_type },
    { "getPktSrcAddr",            detector_get_packet_src_addr },
    { "getPktDstAddr",            detector_get_packet_dst_addr },
    { "getPktSrcPort",            detector_get_packet_src_port },
    { "getPktDstPort",            detector_get_packet_dst_port },
    { "getPktCount",              detector_get_packet_count },
    { "getFlow",                  detector_get_flow },
    { "htons",                    detector_htons },
    { "htonl",                    detector_htonl },
    { "log",                      detector_log_message },
    { "addHttpPattern",           detector_add_http_pattern },
    { "addAppUrl",                detector_add_url_application },
    { "addRTMPUrl",               detector_add_rtmp_url },
    { "addContentTypePattern",    detector_add_content_type_pattern },
    { "addSSLCertPattern",        detector_add_ssl_cert_pattern },
    { "addSipUserAgent",          detector_add_sip_user_agent },
    { "addSipServer",             detector_add_sip_server },
    { "addSSLCnamePattern",       detector_add_ssl_cname_pattern },
    { "addHostPortApp",           detector_add_host_port_application },
    { "addDNSHostPattern",        detector_add_dns_host_pattern },

    /*Obsolete - new detectors should not use this API */
    { "init",                     service_init },
    { "registerPattern",          service_register_pattern },
    { "getServiceID",             service_get_service_id },
    { "addPort",                  service_add_ports },
    { "removePort",               service_remove_ports },
    { "setServiceName",           service_set_service_name },
    { "getServiceName",           service_get_service_name },
    { "isCustomDetector",         service_is_custom_detector },
    { "setValidator",             service_set_validator },
    { "addService",               service_add_service },
    { "failService",              service_fail_service },
    { "inProcessService",         service_in_process_service },
    { "markIncompleteData",       service_set_incompatible_data },
    { "analyzePayload",           service_analyze_payload },
    { "addAppIdDataToFlow",       service_add_data_id },

    /*service API */
    { "service_init",               service_init },
    { "service_registerPattern",    service_register_pattern },
    { "service_getServiceId",       service_get_service_id },
    { "service_addPort",            service_add_ports },
    { "service_removePort",         service_remove_ports },
    { "service_setServiceName",     service_set_service_name },
    { "service_getServiceName",     service_get_service_name },
    { "service_isCustomDetector",   service_is_custom_detector },
    { "service_setValidator",       service_set_validator },
    { "service_addService",         service_add_service },
    { "service_failService",        service_fail_service },
    { "service_inProcessService",   service_in_process_service },
    { "service_markIncompleteData", service_set_incompatible_data },
    { "service_analyzePayload",     service_analyze_payload },
    { "service_addAppIdDataToFlow", service_add_data_id },
    { "service_addClient",          service_add_client },

    /*client init API */
    { "client_init",              client_init },
    { "client_registerPattern",   client_register_pattern },
    { "client_getServiceId",      service_get_service_id },

    /*client service API */
    { "client_addApp",            client_add_application },
    { "client_addInfo",           client_add_info },
    { "client_addUser",           client_add_user },
    { "client_addPayload",        client_add_payload },

    //HTTP Multi Pattern engine
    { "CHPCreateApp",             detector_chp_create_application },
    { "CHPAddAction",             detector_add_chp_action },
    { "CHPMultiCreateApp",        detector_create_chp_multi_application }, // multiple detectors,
                                                                           // same appId
    { "CHPMultiAddAction",        detector_add_chp_multi_action },

    //App Forecasting engine
    { "AFAddApp",                 detector_add_af_application },

    { "portOnlyService",          detector_port_only_service },

    /* Length-based detectors. */
    { "AddLengthBasedDetector",   detector_add_length_app_cache },

    { "registerAppId",            common_register_application_id },

    { "open_createApp",           create_custom_application },
    { "open_addClientApp",        add_client_application },
    { "open_addServiceApp",       add_service_application },
    { "open_addPayloadApp",       add_payload_application },
    { "open_addHttpPattern",      add_http_pattern },
    { "open_addUrlPattern",       add_url_pattern },

    { "addPortPatternClient",     add_port_pattern_client },
    { "addPortPatternService",    add_port_pattern_service },

    { "createFutureFlow",         create_future_flow },

    { nullptr, nullptr }
};

/* Garbage collector hook function. Called when Lua side garbage collects detector
 * api instance. Current design is to allocate one of each luaState, detector and
 * detectorUserData buffers, and hold these buffers till RNA exits. SigHups processing
 * reuses the buffers and calls DetectorInit to reinitialize. RNA ensures that
 * UserData<LuaDetectionState> is not garbage collected, by creating a reference in LUA_REGISTRY
 * table. The reference is released only on RNA exit.
 *
 * If in future, one needs to free any of these buffers then one should consider
 * references to detector buffer in  ServiceDetector stored in flows and hostServices
 * data structures. Other detectors at this time create one static instance for the
 * lifetime of RNA, and therefore we have adopted the same principle for Lua Detectors.
 */
static int Detector_gc(lua_State*)
{
    return 0;
}

/*convert detector to string for printing */
static int Detector_tostring(lua_State* L)
{
    lua_pushfstring(L, "Detector (%p)", (*UserData<LuaObject>::check(L, DETECTOR, 1))->get_detector());
    return 1;
}

static const luaL_Reg Detector_meta[] =
{
    { "__gc",       Detector_gc },
    { "__tostring", Detector_tostring },
    { nullptr, nullptr }
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
int register_detector(lua_State* L)
{
    // populates new table from detector_methods and add it to the globals and stack
    luaL_openlib(L, DETECTOR, detector_methods, 0);

    // create metatable for Foo, add it to the Lua registry, metatable on stack
    luaL_newmetatable(L, DETECTOR);

    // populates table on stack with Detector_meta methods, puts the metatable on stack
    luaL_openlib(L, nullptr, Detector_meta, 0);

    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);             /* dup methods table*/
    lua_settable(L, -3);              /* metatable.__index = methods */
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);             /* dup methods table*/
    lua_settable(L, -3);              /* hide metatable: metatable.__metatable = methods */
    lua_pop(L, 1);                    /* drop metatable */
    return 1;                         /* return methods on the stack */
}

int LuaStateDescriptor::lua_validate(AppIdDiscoveryArgs& args)
{
    Profile lua_detector_context(luaCustomPerfStats);

    auto my_lua_state = lua_detector_mgr? lua_detector_mgr->L : nullptr;
    if (!my_lua_state)
    {
        ErrorMessage("lua detector %s: no LUA state\n", package_info.name.c_str());
        return APPID_ENULL;
    }

    // get the table for this chunk (env)
    lua_getfield(my_lua_state, LUA_REGISTRYINDEX, package_info.name.c_str());
    ldp.data = args.data;
    ldp.size = args.size;
    ldp.dir = args.dir;
    ldp.asd = &args.asd;
    ldp.pkt = args.pkt;
    const char* validateFn = package_info.validateFunctionName.c_str();

    if ( (!validateFn) || (validateFn[0] == '\0'))
    {
        ldp.pkt = nullptr;
        return APPID_NOMATCH;
    }
    else if ( !lua_checkstack(my_lua_state, 1) )
    {
        static bool logged_stack_error = false;
        if (!logged_stack_error)
        {
            logged_stack_error = true;
            ErrorMessage("lua detector %s: LUA stack can not grow, %s\n",
                package_info.name.c_str(), lua_tostring(my_lua_state, -1));
        }
        ldp.pkt = nullptr;
        return APPID_ENOMEM;
    }

    lua_getfield(my_lua_state, -1, validateFn); // get the function we want to call

    if ( lua_pcall(my_lua_state, 0, 1, 0) )
    {
        // Runtime Lua errors are suppressed in production code since detectors are written for
        // efficiency and with defensive minimum checks. Errors are dealt as exceptions
        // that don't impact processing by other detectors or future packets by the same detector.
        ErrorMessage("lua detector %s: error validating %s\n",
            package_info.name.c_str(), lua_tostring(my_lua_state, -1));
        ldp.pkt = nullptr;
        return APPID_ENULL;
    }

    /**detectorFlows must be destroyed after each packet is processed.*/
    LuaDetectorManager::free_detector_flows();

    /* retrieve result */
    if ( !lua_isnumber(my_lua_state, -1) )
    {
        ErrorMessage("lua detector %s: returned non-numeric value\n", package_info.name.c_str());
        ldp.pkt = nullptr;
        return APPID_ENULL;
    }

    int rc = lua_tonumber(my_lua_state, -1);
    lua_pop(my_lua_state, 1);
    ldp.pkt = nullptr;
    return rc;
}

static inline void init_lsd(LuaStateDescriptor* lsd, const std::string& detector_name,
    lua_State* L)
{
    lsd->service_id = APP_ID_UNKNOWN;
    get_lua_field(L, -1, "init", lsd->package_info.initFunctionName);
    get_lua_field(L, -1, "clean", lsd->package_info.cleanFunctionName);
    get_lua_field(L, -1, "validate", lsd->package_info.validateFunctionName);
    get_lua_field(L, -1, "minimum_matches", lsd->package_info.minimum_matches);
    lsd->package_info.name = detector_name;
    lua_pop(L, 1);    // pop client table
    lua_pop(L, 1);    // pop DetectorPackageInfo table
}

LuaServiceDetector::LuaServiceDetector(AppIdDiscovery* sdm, const std::string& detector_name,
    const std::string& logging_name, bool is_custom, unsigned min_match, IpProtocol protocol)
{
    handler = sdm;
    name = detector_name;
    log_name = logging_name;
    custom_detector = is_custom;
    minimum_matches = min_match;
    proto = protocol;
    handler->register_detector(name, this, proto);
}


LuaServiceObject::LuaServiceObject(AppIdDiscovery* sdm, const std::string& detector_name,
    const std::string& log_name, bool is_custom, IpProtocol protocol, lua_State* L)
{
    init_lsd(&lsd, detector_name, L);

    if (init(L))
    {
        sd = new LuaServiceDetector(sdm, detector_name,
            log_name, is_custom, lsd.package_info.minimum_matches, protocol);
    }
    else
    {
	    AppIdDetector *ad = nullptr;
	    AppIdDetectors *appid_detectors = nullptr;

	    if (protocol == IpProtocol::TCP)
        {
            appid_detectors = ServiceDiscovery::get_instance().get_tcp_detectors();
	        auto detector = appid_detectors->find(detector_name);
            if (detector != appid_detectors->end())
                ad = detector->second;  
        }
	    else if (protocol == IpProtocol::UDP)
        {
            appid_detectors = ServiceDiscovery::get_instance().get_udp_detectors();
	        auto detector = appid_detectors->find(detector_name);
            if (detector != appid_detectors->end())
                ad = detector->second;  
        }
	    sd = (ServiceDetector*)ad;
    }  

    UserData<LuaServiceObject>::push(L, DETECTOR, this);

    lua_pushvalue(L, -1);

    // FIXIT-M: RELOAD - go back to using lua reference 
    // instead of using a string for lookups
    // lsd.detector_user_data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    
    // FIXIT-H: The control and thread states have the same initialization
    // sequence, the stack index shouldn't change between the states, maybe
    // use a common index for a detector between all the states
    std::string name = detector_name + "_";
    lua_setglobal(L, name.c_str());
}

int LuaServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    //FIXIT-M: RELOAD - use lua references to get user data object from stack
    auto my_lua_state = lua_detector_mgr? lua_detector_mgr->L : nullptr;
    lua_settop(my_lua_state,0);
    std::string name = this->name + "_";
    lua_getglobal(my_lua_state, name.c_str());
    auto& ud = *UserData<LuaServiceObject>::check(my_lua_state, DETECTOR, 1);
    return ud->lsd.lua_validate(args);
}

LuaClientDetector::LuaClientDetector(AppIdDiscovery* cdm, const std::string& detector_name,
    const std::string& logging_name, bool is_custom, unsigned min_match, IpProtocol protocol)
{
    handler = cdm;
    name = detector_name;
    log_name = logging_name;
    custom_detector = is_custom;
    minimum_matches = min_match;
    proto = protocol;
    handler->register_detector(name, this, proto);
}

LuaClientObject::LuaClientObject(AppIdDiscovery* cdm, const std::string& detector_name,
    const std::string& log_name, bool is_custom, IpProtocol protocol, lua_State* L)
{
    init_lsd(&lsd, detector_name, L);

    if (init(L))
    {
        cd = new LuaClientDetector(cdm, detector_name,
            log_name, is_custom, lsd.package_info.minimum_matches, protocol);
    }
    else
    {
	    AppIdDetector *ad = nullptr;
	    AppIdDetectors *appid_detectors = nullptr;

	    if (protocol == IpProtocol::TCP)
        {
            appid_detectors = ClientDiscovery::get_instance().get_tcp_detectors();
	        auto detector = appid_detectors->find(detector_name);
            if (detector != appid_detectors->end())
                ad = detector->second;  
        }
	    else if (protocol == IpProtocol::UDP)
        {
            appid_detectors = ClientDiscovery::get_instance().get_udp_detectors();
	        auto detector = appid_detectors->find(detector_name);
            if (detector != appid_detectors->end())
                ad = detector->second;  
        }
	    cd = (ClientDetector*)ad;
    }  
    
    UserData<LuaClientObject>::push(L, DETECTOR, this);

    lua_pushvalue(L, -1);

    // FIXIT-M: RELOAD - go back to using lua reference 
    // instead of using a string for lookups
    // lsd.detector_user_data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    
    // FIXIT-H: The control and thread states have the same initialization
    // sequence, the stack index shouldn't change between the states, maybe
    // use a common index for a detector between all the states
    std::string name = detector_name + "_";
    lua_setglobal(L, name.c_str());
}


LuaStateDescriptor* LuaObject::validate_lua_state(bool packet_context)
{
    lua_params_validator(lsd.ldp, packet_context);
    return &lsd;
}

int LuaClientDetector::validate(AppIdDiscoveryArgs& args)
{
    //FIXIT-M: RELOAD - use lua references to get user data object from stack
    auto my_lua_state = lua_detector_mgr? lua_detector_mgr->L : nullptr;
    std::string name = this->name + "_";
    lua_settop(my_lua_state,0); //set stack index to 0
    lua_getglobal(my_lua_state, name.c_str());
    auto& ud = *UserData<LuaClientObject>::check(my_lua_state, DETECTOR, 1);
    return ud->lsd.lua_validate(args);
}
