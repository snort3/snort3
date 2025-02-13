//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
#include <unordered_map>

#include "detection/fp_config.h"
#include "framework/mpse.h"
#include "host_tracker/cache_allocator.cc"
#include "host_tracker/host_cache.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "managers/mpse_manager.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "trace/trace_api.h"
#include "utils/snort_pcre.h"

#include "app_info_table.h"
#include "appid_debug.h"
#include "appid_inspector.h"
#include "appid_peg_counts.h"
#include "client_plugins/client_discovery.h"
#include "detector_plugins/cip_patterns.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/detector_pattern.h"
#include "detector_plugins/detector_sip.h"
#include "detector_plugins/http_url_patterns.h"
#include "detector_plugins/ssh_patterns.h"
#include "host_port_app_cache.h"
#include "lua_detector_flow_api.h"
#include "lua_detector_module.h"
#include "lua_detector_util.h"
#include "service_plugins/service_discovery.h"
#include "service_plugins/service_ssl.h"

using namespace snort;
using namespace std;

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

static CHPGlossary* CHP_glossary = nullptr; // tracks http multipatterns
static CHPGlossary* old_CHP_glossary = nullptr;

void init_chp_glossary()
{
    assert(!old_CHP_glossary);
    old_CHP_glossary = CHP_glossary;
    CHP_glossary = new CHPGlossary;
}

static void free_chp_glossary(CHPGlossary*& glossary)
{

    if (glossary)
    {
        for (auto& entry : *glossary)
            delete entry.second;
        delete glossary;
        glossary = nullptr;
    }
}

void free_current_chp_glossary()
{
    free_chp_glossary(CHP_glossary);
}

void free_old_chp_glossary()
{
    free_chp_glossary(old_CHP_glossary);
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
    if (packet_context)
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

static inline int toipprotocol(lua_State *L, int index,
    IpProtocol &proto, bool print_err = true)
{
    unsigned tmp_proto = lua_tointeger(L, index);

    if (tmp_proto > (unsigned)IpProtocol::RESERVED)
    {
        if (print_err)
            APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "Invalid protocol value %u\n", tmp_proto);
        return -1;
    }

    proto = static_cast<IpProtocol>(tmp_proto);
    return 0;
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
    if (!init(L))
        return 0;

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

    APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "%s: attempted setting validator/fini to non-function\n",
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

    IpProtocol protocol;
    if (toipprotocol(L, ++index, protocol))
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    const char* pattern = lua_tostring(L, ++index);
    size_t size = lua_tonumber(L, ++index);
    unsigned int position = lua_tonumber(L, ++index);

    if (protocol == IpProtocol::TCP)
        ud->get_odp_ctxt().get_service_disco_mgr().register_tcp_pattern(ud->sd, (const uint8_t*)pattern,
            size, position, 0);
    else
        ud->get_odp_ctxt().get_service_disco_mgr().register_udp_pattern(ud->sd, (const uint8_t*)pattern,
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

    if (ad->is_client())
        ad->register_appid(appId, APPINFO_FLAG_CLIENT_ADDITIONAL, ud->get_odp_ctxt());
    else
        ad->register_appid(appId, APPINFO_FLAG_SERVICE_ADDITIONAL, ud->get_odp_ctxt());

    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(appId);

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

    switch (level)
    {
    case LUA_LOG_CRITICAL:
        APPID_LOG(nullptr, TRACE_CRITICAL_LEVEL, "%s:%s\n", name.c_str(), message);
        break;

    case LUA_LOG_ERR:
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "%s:%s\n", name.c_str(), message);
        break;

    case LUA_LOG_WARN:
        APPID_LOG(nullptr, TRACE_WARNING_LEVEL, "%s:%s\n", name.c_str(), message);
        break;

    case LUA_LOG_NOTICE:
    case LUA_LOG_INFO:
        APPID_LOG(nullptr, TRACE_INFO_LEVEL, "%s:%s\n", name.c_str(), message);
        break;

    case LUA_LOG_TRACE:
        debug_logf(appid_trace, nullptr, "%s:%s\n", name.c_str(), message);
        break;

    default:
        break;
    }

    return 0;
}

static int detector_log_snort_message(lua_State* L)
{
    const auto& name = (*UserData<LuaObject>::check(L, DETECTOR, 1))->get_detector()->get_name();

    unsigned int level = lua_tonumber(L, 2);
    const char* message = lua_tostring(L, 3);

    switch (level)
    {
    case LUA_LOG_CRITICAL:
        APPID_LOG(nullptr, TRACE_CRITICAL_LEVEL, "%s:%s\n", name.c_str(), message);
        break;

    case LUA_LOG_ERR:
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "%s:%s\n", name.c_str(), message);
        break;

    case LUA_LOG_WARN:
        APPID_LOG(nullptr, TRACE_WARNING_LEVEL, "%s:%s\n", name.c_str(), message);
        break;

    case LUA_LOG_NOTICE:
    case LUA_LOG_INFO:
        if ( !appidDebug or !appidDebug->is_enabled() )
            return 0;
        APPID_LOG(nullptr, TRACE_INFO_LEVEL, "AppIdDbg %s:%s\n", name.c_str(), message);
        break;

    case LUA_LOG_TRACE:
        auto curr_packet = (Analyzer::get_local_analyzer() and snort::DetectionEngine::get_context()) ? snort::DetectionEngine::get_current_packet() : nullptr;
        APPID_LOG(curr_packet, TRACE_DEBUG_LEVEL, curr_packet ? "%s:%s\n" : "AppIdDbg %s:%s\n", name.c_str(), message);
        break;
    }

    return 0;
}

/** Add a netbios domain
 *  lua params:
 *    1 - the netbios domain
 */
static int service_add_netbios_domain(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);
    const char* netbios_domain = lua_tostring(L, 2);
    lsd->ldp.asd->set_netbios_domain(*lsd->ldp.change_bits, netbios_domain);
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

    lsd->ldp.asd->set_payload_id(lua_tonumber(L, 2));
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

    if (toipprotocol(L, 2, pp.proto))
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    pp.port = lua_tonumber(L, 3);
    pp.reversed_validation = lua_tonumber(L, 5);

    if (((pp.proto != IpProtocol::UDP) and (pp.proto != IpProtocol::TCP)) or !pp.port)
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    if (ud->sd->get_handler().add_service_port(ud->sd, pp))
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
 * was created by odp or not.
 * Callback could be used either at init or during packet processing
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is always 1.
 * @return integer/stack - -1 if failed, 0 if odp created, 1 otherwise.
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
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "%s: attempted setting validator to non-function\n",
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
    unsigned int retValue = ud->sd->add_service(*lsd->ldp.change_bits, *lsd->ldp.asd, lsd->ldp.pkt,
        lsd->ldp.dir, lsd->ldp.asd->get_odp_ctxt().get_app_info_mgr().get_appid_by_service_id(service_id),
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

    pcre2_match_data* match_data;
    PCRE2_UCHAR error[128];
    PCRE2_SIZE erroffset;
    int errorcode;

    const char* pattern = lua_tostring(L, 2);
    unsigned int offset = lua_tonumber(L, 3);     /*offset can be zero, no check necessary. */

    /*compile the regular expression pattern, and handle errors */
    pcre2_code* re = pcre2_compile((PCRE2_SPTR)pattern,  // the pattern
        PCRE2_ZERO_TERMINATED,         // assume zero terminated strings
        PCRE2_DOTALL,                  // default options - dot matches all inc \n
        &errorcode,                    // for error message
        &erroffset,                    // for error offset
        nullptr);                      // default character tables

    if (re == nullptr)
    {
        pcre2_get_error_message(errorcode, error, 128);
        APPID_LOG(lsd->ldp.pkt, TRACE_ERROR_LEVEL, "PCRE compilation failed at offset %d: %s\n", erroffset, error);
        return 0;
    }

    match_data = pcre2_match_data_create(OVECCOUNT, NULL);
    if (!match_data)
    {
        appid_log(lsd->ldp.pkt, TRACE_ERROR_LEVEL, "PCRE failed to allocate mem for match_data\n");
        return 0;
    }

    int rc = pcre2_match(re,         // compiled pattern
        (PCRE2_SPTR)lsd->ldp.data,   // subject string
        (PCRE2_SIZE)lsd->ldp.size,   // length of the subject
        (PCRE2_SIZE)offset,          // offset 0
        0,                           // default options
        match_data,                  // match data for match results
        NULL);                       // no match context

    if (rc >= 0)
    {
        if (rc == 0)
        {
            /*overflow of matches */
            rc = OVECCOUNT / 3;
            APPID_LOG(lsd->ldp.pkt, TRACE_WARNING_LEVEL, "ovector only has room for %d captured substrings\n", rc - 1);
        }

        if (!lua_checkstack(L, rc))
        {
            APPID_LOG(lsd->ldp.pkt, TRACE_WARNING_LEVEL, "Cannot grow Lua stack by %d slots to hold "
                "PCRE matches\n", rc);
            return 0;
        }

        PCRE2_SIZE* ovector = pcre2_get_ovector_pointer(match_data);
        for (int i = 0; i < rc; i++)
        {
            lua_pushlstring(L, (const char*)lsd->ldp.data + ovector[2*i], ovector[2*i+1] -
                ovector[2*i]);
        }
    }
    else
    {
        // log errors except no matches
        if (rc != PCRE2_ERROR_NOMATCH)
            APPID_LOG(lsd->ldp.pkt, TRACE_WARNING_LEVEL, "PCRE regular expression group match failed. rc: %d\n", rc);
        rc = 0;
    }

    pcre2_match_data_free(match_data);
    pcre2_code_free(re);
    return rc;
}

/** Extracts a specific substring of packet data.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object,
 * @param offset/stack - the offset at which we want our substring to start.
 * @param len/stack - the number of bytes we want in our buffer
 *
 * @return substring/stack - the requested substring.
 */
static int detector_get_substr(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);
    unsigned int offset = lua_tonumber(L, 2);
    unsigned int substr_len = lua_tonumber(L, 3);
    if (offset + substr_len > lsd->ldp.size)
    {
        APPID_LOG(lsd->ldp.pkt, TRACE_WARNING_LEVEL, "Requested substr end offset %d is greater than data size %d\n",
            offset + substr_len, lsd->ldp.size);
        return 0;
    }
    lua_pushlstring(L, (const char*)lsd->ldp.data + offset, substr_len);
    return 1;
}

/** Searches through packet data for a substr, and returns starting index if found.
 *
 *  Lazy search; only returns index to first match.
 */
static int detector_find_substr(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);
    unsigned int offset = lua_tonumber(L, 2);
    size_t substr_len = 0;
    const char* substr = lua_tolstring(L, 3, &substr_len);

    for (unsigned int i = 0; i + offset <= lsd->ldp.size - substr_len; i++)
    {
        if (*((const char*)lsd->ldp.data + i + offset) == *substr)
        {
            if (substr_len == 1)
            {
                lua_pushnumber(L, offset + i);
                return 1;
            }

            for (unsigned int j = 1; j < substr_len; j++)
            {
                if (*((const char*)lsd->ldp.data + i + j + offset) != *(substr + j))
                    break;
                else if (j == substr_len - 1)
                {
                    lua_pushnumber(L, offset + i);
                    return 1;
                }
            }
        }
    }

    return 0;
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

    if (!lsd->ldp.pkt->has_ip())
    {
        lua_pushnumber(L, 0);
        return 1;
    }

    // FIXIT-M is this conversion to double valid?
    lua_pushnumber(L, (double)lsd->ldp.pkt->get_ip_proto_next());
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
    lua_pushnumber(L, port);
    return 1;
}

/**Get packet count. This is used mostly for printing packet sequence
 * number when appid is being tested with a pcap file.
 * Callback could be used either at init or during packet processing
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return packetCount/stack - Total packet processed by appid.
**/
static int detector_get_packet_count(lua_State* L)
{
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

    IpProtocol protocol;
    if (toipprotocol(L, ++index, protocol))
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    const char* pattern = lua_tostring(L, ++index);
    size_t size = lua_tonumber(L, ++index);
    unsigned int position = lua_tonumber(L, ++index);

    /*Note: we can not give callback into lua directly so we have to
      give a local callback function, which will do demuxing and
      then call lua callback function. */

    /*mpse library does not hold reference to pattern therefore we don't need to allocate it. */

    if (protocol == IpProtocol::TCP)
        ud->get_odp_ctxt().get_client_disco_mgr().register_tcp_pattern(ud->cd, (const uint8_t*)pattern,
            size, position, 0);
    else
        ud->get_odp_ctxt().get_client_disco_mgr().register_udp_pattern(ud->cd, (const uint8_t*)pattern,
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

    if (!version)
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    ud->cd->add_app(*lsd->ldp.asd, service_id, client_id, version, *lsd->ldp.change_bits);
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
    OdpContext& odp_ctxt = lsd->ldp.asd->get_odp_ctxt();
    ud->cd->add_app(*lsd->ldp.pkt, *lsd->ldp.asd, lsd->ldp.dir,
        odp_ctxt.get_app_info_mgr().get_appid_by_service_id(service_id),
        odp_ctxt.get_app_info_mgr().get_appid_by_client_id(productId), version,
        *lsd->ldp.change_bits);

    lua_pushnumber(L, 0);
    return 1;
}

static int client_add_info(lua_State*)
{
    // Deprecated API. But because we are in packet context, silently ignore
    return -1;
}

static int client_add_user(lua_State* L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    const char* userName = lua_tostring(L, 2);
    unsigned int service_id = lua_tonumber(L, 3);
    ud->cd->add_user(*lsd->ldp.asd, userName,
        lsd->ldp.asd->get_odp_ctxt().get_app_info_mgr().get_appid_by_service_id(service_id), true,
        *lsd->ldp.change_bits);
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
        lsd->ldp.asd->get_odp_ctxt().get_app_info_mgr().get_appid_by_payload_id(payloadId));

    lua_pushnumber(L, 0);
    return 1;
}

/** Add a alpn to service app mapping.
 *  @param Lua_State* - Lua state variable.
 *  @param appid/stack - the AppId to map the data to.
 *  @param alpn  - application protocol negotiations string.
 */
static int add_alpn_to_service_mapping(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;
    int index = 1;

    uint32_t appid = lua_tointeger(L, ++index);

    // Verify that alpn is a valid string
    size_t pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &pattern_size);
    if (!tmp_string or !pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid alpn service string: appid %u.\n", appid);
        return 0;
    }
    const std::string service_name(tmp_string);
    const std::string detector_name = ud->get_detector()->get_name();

    ud->get_odp_ctxt().get_alpn_matchers().add_alpn_pattern(appid, service_name, detector_name);

    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(appid);

    return 0;
}


/** Add a fp process to client app mapping.
 *  @param Lua_State* - Lua state variable.
 *  @param appid/stack - the AppId to map the fp data to
 *  @param process_name/stack - encrypted fingerprint process name
 *  @param process_score - encrypted fingerprint process_score
 */
static int add_process_to_client_mapping(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;
    int index = 1;

    uint32_t appid = lua_tointeger(L, ++index);

    // Verify that process_name is a valid string
    size_t pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &pattern_size);
    if (!tmp_string or !pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid eve process_name string: appid %u.\n", appid);
        return 0;
    }
    const std::string process_name(tmp_string);
    uint8_t process_score = lua_tointeger(L, ++index);
    const std::string detector_name = ud->get_detector()->get_name();

    ud->get_odp_ctxt().get_eve_ca_matchers().add_eve_ca_pattern(appid, process_name,
        process_score, detector_name, true);

    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(appid);

    return 0;
}

/** Add a fp process name regex to client app mapping.
 *  @param Lua_State* - Lua state variable.
 *  @param appid/stack - the AppId to map the fp data to
 *  @param process_name/stack - encrypted fingerprint process name regex
 *  @param process_score - encrypted fingerprint process_score
 */
static int add_process_to_client_mapping_regex(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    const FastPatternConfig* const fp = SnortConfig::get_conf()->fast_pattern_config;
    if (!MpseManager::is_regex_capable(fp->get_search_api())){
        APPID_LOG(nullptr, TRACE_WARNING_LEVEL, "WARNING: appid: Regex patterns require usage of "
            "regex capable search engine like hyperscan in %s\n", ud->get_detector()->get_name().c_str());
            return 0;
    }

    int index = 1;
    uint32_t appid = lua_tointeger(L, ++index);

    // Verify that process_name is a valid string
    size_t pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &pattern_size);
    if (!tmp_string or !pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid eve process_name regex string: appid %u.\n", appid);
        return 0;
    }
    const std::string process_name(tmp_string);
    uint8_t process_score = lua_tointeger(L, ++index);
    const std::string detector_name = ud->get_detector()->get_name();

    ud->get_odp_ctxt().get_eve_ca_matchers().add_eve_ca_pattern(appid, process_name,
        process_score, detector_name, false);

    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(appid);

    return 0;
}

/**Get flow object from a detector object. The flow object is then used with flowApi.
 * A new copy of flow object is provided with every call. This can be optimized by maintaining
 * a single copy.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return packetCount/stack - Total packet processed by appid.
 * @todo maintain a single copy and return the same copy with every call to Detector_getFlow().
 */
static int detector_get_flow(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    auto df = odp_thread_local_ctxt->get_detector_flow();
    if (!df)
    {
        df = new DetectorFlow(L, lsd->ldp.asd);
        odp_thread_local_ctxt->set_detector_flow(df);
    }
    UserData<DetectorFlow>::push(L, DETECTORFLOW, df);
    lua_pushvalue(L, -1);
    df->userDataRef = luaL_ref(L, LUA_REGISTRYINDEX);
    return 1;
}

static int detector_add_http_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    int index = 1;

    enum httpPatternType pat_type = (enum httpPatternType)lua_tointeger(L, ++index);
    if (pat_type < HTTP_PAYLOAD or pat_type > HTTP_URL)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid HTTP pattern type in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }

    DHPSequence seq  = (DHPSequence)lua_tointeger(L, ++index);
    AppInfoManager& aim = ud->get_odp_ctxt().get_app_info_mgr();
    uint32_t service_id = aim.get_appid_by_service_id((uint32_t)lua_tointeger(L, ++index));
    uint32_t client_id = aim.get_appid_by_client_id((uint32_t)lua_tointeger(L, ++index));
    /*uint32_t client_app_type =*/ lua_tointeger(L, ++index);
    uint32_t payload_id = aim.get_appid_by_payload_id((uint32_t)lua_tointeger(L, ++index));
    /*uint32_t payload_type    =*/ lua_tointeger(L, ++index);

    size_t pattern_size = 0;
    const uint8_t* pattern_str = (const uint8_t*)lua_tolstring(L, ++index, &pattern_size);
    if (!pattern_str or !pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid HTTP pattern string in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }

    uint32_t app_id = lua_tointeger(L, ++index);
    DetectorHTTPPattern pattern;
    if (pattern.init(pattern_str, pattern_size, seq, service_id, client_id,
        payload_id, app_id))
    {
        ud->get_odp_ctxt().get_http_matchers().insert_http_pattern(pat_type, pattern);
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
    if (!init(L))
        return 0;

    int index = 1;

    uint8_t type = lua_tointeger(L, ++index);
    AppId app_id = (AppId)lua_tointeger(L, ++index);
    size_t pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &pattern_size);
    if (!tmp_string or !pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid SSL Host pattern string in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }

    uint8_t* pattern_str = (uint8_t*)snort_strdup(tmp_string);
    ud->get_odp_ctxt().get_ssl_matchers().add_cert_pattern(pattern_str, pattern_size, type, app_id,
        false);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(app_id);

    return 0;
}

static int detector_add_ssl_cert_regex_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    const FastPatternConfig* const fp = SnortConfig::get_conf()->fast_pattern_config;
    if (!MpseManager::is_regex_capable(fp->get_search_api())){
        APPID_LOG(nullptr, TRACE_WARNING_LEVEL, "WARNING: appid: Regex patterns require usage of "
            "regex capable search engine like hyperscan in %s\n", ud->get_detector()->get_name().c_str());
            return 0;
    }

    int index = 1;

    uint8_t type = lua_tointeger(L, ++index);
    AppId app_id = (AppId)lua_tointeger(L, ++index);
    size_t pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &pattern_size);
    if (!tmp_string or !pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid SSL Host regex pattern string in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }

    uint8_t* pattern_str = (uint8_t*)snort_strdup(tmp_string);
    ud->get_odp_ctxt().get_ssl_matchers().add_cert_pattern(pattern_str, pattern_size, type, app_id,
        false, false);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(app_id);

    return 0;
}

static int detector_add_ssl_cname_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    int index = 1;

    uint8_t type = lua_tointeger(L, ++index);
    AppId app_id = (AppId)lua_tointeger(L, ++index);

    size_t pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &pattern_size);
    if (!tmp_string or !pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid SSL CN pattern string in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }

    uint8_t* pattern_str = (uint8_t*)snort_strdup(tmp_string);
    ud->get_odp_ctxt().get_ssl_matchers().add_cert_pattern(pattern_str, pattern_size, type, app_id,
        true);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(app_id);

    return 0;
}

static int detector_add_ssl_cname_regex_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    const FastPatternConfig* const fp = SnortConfig::get_conf()->fast_pattern_config;
    if (!MpseManager::is_regex_capable(fp->get_search_api())){
        APPID_LOG(nullptr, TRACE_WARNING_LEVEL, "WARNING: appid: Regex patterns require usage of "
            "regex capable search engine like hyperscan in %s\n", ud->get_detector()->get_name().c_str());
            return 0;
    }

    int index = 1;

    uint8_t type = lua_tointeger(L, ++index);
    AppId app_id = (AppId)lua_tointeger(L, ++index);

    size_t pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &pattern_size);
    if (!tmp_string or !pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid SSL CN regex pattern string in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }

    uint8_t* pattern_str = (uint8_t*)snort_strdup(tmp_string);
    ud->get_odp_ctxt().get_ssl_matchers().add_cert_pattern(pattern_str, pattern_size, type, app_id,
        true, false);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(app_id);

    return 0;
}

// for Lua this looks something like: addDNSHostPattern(<appId>, '<pattern string>')
static int detector_add_dns_host_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    int index = 1;

    uint8_t type = lua_tointeger(L, ++index);
    AppId app_id = (AppId)lua_tointeger(L, ++index);

    size_t pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &pattern_size);
    if (!tmp_string or !pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid DNS Host pattern string.\n");
        return 0;
    }

    uint8_t* pattern_str = (uint8_t*)snort_strdup(tmp_string);
    ud->get_odp_ctxt().get_dns_matchers().add_host_pattern(pattern_str, pattern_size, type, app_id);

    return 0;
}

static int detector_add_host_first_pkt_application(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    SfIp ip_address;
    int index = 1;

    /* Extract the three appIds and the reinspect flag */
    uint32_t protocol_appid = lua_tointeger(L, ++index);
    uint32_t client_appid = lua_tointeger(L, ++index);
    uint32_t web_appid = lua_tointeger(L, ++index);
    unsigned reinspect = lua_tointeger(L, ++index);

    /* Extract Network IP and netmask */
    size_t ipaddr_size = 0;
    uint32_t netmask32[4] = { 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu };
    bool netmask_parsed = false;
    const char* cidr_str = lua_tolstring(L, ++index, &ipaddr_size);
    vector<string> tokens;

    if (!cidr_str or !ipaddr_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "First packet API: No IP address provided\n");
        return 0;
    }

    if (strchr(cidr_str, '/') == nullptr)
    {
        if (!convert_string_to_address(cidr_str, &ip_address))
        {
            APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "First packet API: Invalid IP address: %s\n", cidr_str);
            return 0;
        }
    }
    else
    {
        stringstream ss(cidr_str);
        string temp_str;

        while (getline(ss, temp_str, '/'))
        {
            tokens.push_back(temp_str);
        }

        const char* netip_str = tokens[0].c_str();

        if (!netip_str or !convert_string_to_address(netip_str, &ip_address))
        {
            APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "First packet API: Invalid IP address: %s\n", netip_str);
            return 0;
        }

        if (all_of(tokens[1].begin(), tokens[1].end(), ::isdigit))
        {
            int bits = stoi(tokens[1].c_str());
            if (strchr(netip_str, '.'))
            {
                if (bits < 0 or bits > 32)
                {
                    APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "First packet API: Invalid IPv4 prefix range: %d\n", bits);
                    return 0;
                }
            }
            else if (strchr(netip_str, ':'))
            {
                if (bits < 0 or bits > 128) {
                    APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "First packet API: Invalid IPv6 prefix range: %d\n", bits);
                    return 0;
                }
            }

            if (bits < 32 and !strchr(netip_str, ':'))
                netmask32[3] = bits > 0 ? (0xFFFFFFFFu << (32 - bits)) : 0xFFFFFFFFu;
            else
            {
                for (int i = 3; i >= 0; --i)
                {
                    auto tmp_bits = 32 + (32 * i) - bits;

                    if (tmp_bits > 0)
                        netmask32[i] = tmp_bits >= 32 ? 0 : (0xFFFFFFFFu << tmp_bits);
                }
            }

            for (int i = 0; i < 4; i++)
            {
                netmask32[i] = (uint32_t)htonl(netmask32[i]);
            }

            netmask_parsed = true;
        }
        else
        {
            APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "First packet API: Invalid prefix bit: %s\n", tokens[1].c_str());
            return 0;
        }
    }

    unsigned port = lua_tointeger(L, ++index);
    IpProtocol proto;
    if (toipprotocol(L, ++index, proto))
        return 0;

    lua_getglobal(L, LUA_STATE_GLOBAL_SC_ID);
    const SnortConfig* sc = *static_cast<const SnortConfig**>(lua_touserdata(L, -1));
    lua_pop(L, 1);

    if (!ud->get_odp_ctxt().host_first_pkt_add(
        sc, &ip_address, netmask_parsed ? netmask32 : nullptr, (uint16_t)port, proto, protocol_appid, client_appid, web_appid, reinspect))
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "%s:Failed to backend call first pkt add\n", __func__);

    return 0;
}

static int detector_add_host_port_application(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    SfIp ip_address;
    int index = 1;

    uint8_t type = lua_tointeger(L, ++index);
    AppId app_id  = (AppId)lua_tointeger(L, ++index);
    size_t ipaddr_size = 0;
    const char* ip_str= lua_tolstring(L, ++index, &ipaddr_size);
    if (!ip_str or !ipaddr_size or !convert_string_to_address(ip_str, &ip_address))
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "%s: Invalid IP address: %s\n", __func__, ip_str);
        return 0;
    }

    unsigned port  = lua_tointeger(L, ++index);
    IpProtocol proto;
    if (toipprotocol(L, ++index, proto))
        return 0;

    lua_getglobal(L, LUA_STATE_GLOBAL_SC_ID);
    const SnortConfig* sc = *static_cast<const SnortConfig**>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    if (!ud->get_odp_ctxt().host_port_cache_add(
        sc, &ip_address, (uint16_t)port, proto, type, app_id))
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "%s:Failed to backend call\n", __func__);

    return 0;
}

static int detector_add_host_port_dynamic(lua_State* L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    if (!lsd->ldp.asd->get_odp_ctxt().is_host_port_app_cache_runtime)
        return 0;

    SfIp ip_address;
    int index = 1;

    uint8_t type = lua_tointeger(L, ++index);
    if (type != 1)
    {
        return 0;
    }
    AppId appid  = (AppId)lua_tointeger(L, ++index);
    size_t ipaddr_size = 0;
    const char* ip_str = lua_tolstring(L, ++index, &ipaddr_size);
    if (!ip_str or !ipaddr_size or !convert_string_to_address(ip_str, &ip_address))
        return 0;

    unsigned port = lua_tointeger(L, ++index);
    IpProtocol proto;
    if (toipprotocol(L, ++index, proto, false))
        return 0;

    bool added = false;
    std::lock_guard<std::mutex> lck(AppIdSession::inferred_svcs_lock);
    host_cache[ip_address]->add_service(port, proto, appid, true, &added);

    if (added)
    {
        AppIdSession::incr_inferred_svcs_ver();
        APPID_LOG(CURRENT_PACKET, TRACE_DEBUG_LEVEL, "Added hostPortCache entry ip=%s, port %d, ip_proto %u, "
            "type=%u, appId=%d\n", ip_str, port, (unsigned)proto, type, appid);
    }

    return 0;
}

static int detector_add_content_type_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    size_t stringSize = 0;
    int index = 1;

    const char* tmp_string = lua_tolstring(L, ++index, &stringSize);
    if (!tmp_string or !stringSize)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid HTTP Header string.\n");
        return 0;
    }
    uint8_t* pattern = (uint8_t*)snort_strdup(tmp_string);
    AppId appId = lua_tointeger(L, ++index);

    DetectorHTTPPattern detector;
    detector.pattern = pattern;
    detector.pattern_size = strlen((char*)pattern);
    detector.app_id = appId;
    ud->get_odp_ctxt().get_http_matchers().insert_content_type_pattern(detector);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(appId);

    return 0;
}


static int detector_add_ssh_client_pattern(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    size_t string_size = 0;
    int index = 1;

    const char* tmp_string = lua_tolstring(L, ++index, &string_size);
    if (!tmp_string || !string_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid SSH Client string.\n");
        return 0;
    }
    std::string pattern(tmp_string);
    AppId app_id = lua_tointeger(L, ++index);
    ud->get_odp_ctxt().get_ssh_matchers().add_ssh_pattern(pattern, app_id);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(app_id);

    return 0;
}

static int register_callback(lua_State* L, LuaObject& ud, AppInfoFlags flag)
{
    // Verify detector user data and that we are NOT in packet context
    ud.validate_lua_state(false);

    const char* callback = lua_tostring(L, 3);

    if (!callback or (callback[0] == '\0'))
    {
        lua_pushnumber(L, -1);
        return 1; // number of results
    }

    AppId app_id = lua_tonumber(L, 2);
    if (init(L))
    {
        // in control thread, update app info table. app info table is shared across all threads
        AppInfoTableEntry* entry = ud.get_odp_ctxt().get_app_info_mgr().get_app_info_entry(app_id);
        if (entry)
        {
            if (entry->flags & flag)
            {
                APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "AppId: detector callback already registered for app %d\n",
                    app_id);
                return 1;
            }
            entry->flags |= flag;
        }
        else
        {
            APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "AppId: detector callback cannot be registered for invalid app %d\n",
                app_id);
            return 1;
        }
    }
    else
    {
        // In packet thread, store Lua detectors objects with callback in a thread local list.
        // Note that Lua detector objects are thread local
        ud.set_cb_fn_name(callback);

        if (!odp_thread_local_ctxt->insert_cb_detector(app_id, &ud))
        {
            APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "AppId: detector callback already registered for app %d\n", app_id);
            return 1;
        }
    }

    lua_pushnumber(L, 0);

    return 1;
}

static int detector_register_client_callback(lua_State* L)
{
    const auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);

    return register_callback(L, *ud, APPINFO_FLAG_CLIENT_DETECTOR_CALLBACK);
}

static int detector_register_service_callback(lua_State* L)
{
    const auto& ud = *UserData<LuaServiceObject>::check(L, DETECTOR, 1);

    return register_callback(L, *ud, APPINFO_FLAG_SERVICE_DETECTOR_CALLBACK);
}

static int detector_callback(const uint8_t* data, uint16_t size, AppidSessionDirection dir,
    AppIdSession& asd, const Packet& p, LuaObject& ud, AppidChangeBits& change_bits)
{
    if (!data)
    {
        return -10;
    }

    auto my_lua_state = odp_thread_local_ctxt->get_lua_state();
    // when an ODP detector triggers the detector callback to be called, there are some elements
    // in the stack. Checking here to make sure the number of elements is not too many
    if (lua_gettop(my_lua_state) > 20)
        APPID_LOG(&p, TRACE_WARNING_LEVEL, "appid: leak of %d lua stack elements before detector callback\n",
            lua_gettop(my_lua_state));

    const string& cb_fn_name = ud.get_cb_fn_name();
    const char* detector_name = ud.get_detector()->get_name().c_str();

    lua_getfield(my_lua_state, LUA_REGISTRYINDEX, ud.lsd.package_info.name.c_str());

    ud.lsd.ldp.data = data;
    ud.lsd.ldp.size = size;
    ud.lsd.ldp.dir = dir;
    ud.lsd.ldp.asd = &asd;
    ud.lsd.ldp.pkt = &p;
    ud.lsd.ldp.change_bits = &change_bits;

    lua_getfield(my_lua_state, -1, cb_fn_name.c_str());
    if (lua_pcall(my_lua_state, 0, 1, 0))
    {
        APPID_LOG(&p, TRACE_ERROR_LEVEL, "Detector %s: Error validating %s\n", detector_name,
            lua_tostring(my_lua_state, -1));
        ud.lsd.ldp.pkt = nullptr;
        lua_settop(my_lua_state, 0);
        return -10;
    }

    // detector flows must be destroyed after each packet is processed
    odp_thread_local_ctxt->free_detector_flow();

    // retrieve result
    if (!lua_isnumber(my_lua_state, -1))
    {
        APPID_LOG(&p, TRACE_ERROR_LEVEL, "Detector %s: Validator returned non-numeric value\n", detector_name);
        ud.lsd.ldp.pkt = nullptr;
        lua_settop(my_lua_state, 0);
        return -10;
    }

    int ret = lua_tonumber(my_lua_state, -1);
    lua_pop(my_lua_state, 1);  // pop returned value
    ud.lsd.ldp.pkt = nullptr;
    lua_settop(my_lua_state, 0);

    return ret;
}

void check_detector_callback(const Packet& p, AppIdSession& asd, AppidSessionDirection dir,
    AppId app_id, AppidChangeBits& change_bits, AppInfoTableEntry* entry)
{
    if (!entry)
        entry = asd.get_odp_ctxt().get_app_info_mgr().get_app_info_entry(app_id);
    if (!entry)
        return;

    if (entry->flags & APPINFO_FLAG_CLIENT_DETECTOR_CALLBACK or
        entry->flags & APPINFO_FLAG_SERVICE_DETECTOR_CALLBACK)
    {
        LuaObject* ud = odp_thread_local_ctxt->get_cb_detector(app_id);
        assert(ud);

        if (ud->is_running())
            return;

        ud->set_running(true);

        int ret = detector_callback(p.data, p.dsize, dir, asd, p, *ud, change_bits);
        APPID_LOG(&p, TRACE_DEBUG_LEVEL, "%s detector callback returned %d\n",
            ud->get_detector()->get_name().empty() ? "UKNOWN" : ud->get_detector()->get_name().c_str(), ret);
        ud->set_running(false);
    }
}

static int create_chp_application(AppId appIdInstance, unsigned app_type_flags, int num_matches)
{
    CHPApp* new_app = new CHPApp();
    new_app->appIdInstance = appIdInstance;
    new_app->app_type_flags = app_type_flags;
    new_app->num_matches = num_matches;

    if (CHP_glossary->emplace(appIdInstance, new_app).second == false)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "LuaDetectorApi:Failed to add CHP for appId %d, instance %d",
            CHP_APPIDINSTANCE_TO_ID(appIdInstance), CHP_APPIDINSTANCE_TO_INSTANCE(appIdInstance));
        delete new_app;
        return -1;
    }
    return 0;
}

static int detector_chp_create_application(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    int index = 1;

    AppId appId = lua_tointeger(L, ++index);
    AppId appIdInstance = CHP_APPID_SINGLE_INSTANCE(appId); // Last instance for the old API

    unsigned app_type_flags = lua_tointeger(L, ++index);
    int num_matches = lua_tointeger(L, ++index);

    // We only want one of these for each appId.
    if (CHP_glossary->find(appIdInstance) != CHP_glossary->end())
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Attempt to add more than one CHP for appId %d - "
            "use CHPMultiCreateApp.\n", appId);
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
    if (*pattern_type >= NUM_HTTP_FIELDS)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid CHP Action pattern type.\n");
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
    if (!tmp_string or !*pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid CHP Action PATTERN string.\n");
        return -1;
    }
    *pattern_data = snort_strdup(tmp_string);
    return 0;
}

static inline int get_chp_action_type(lua_State* L, int index, ActionType& action_type)
{
    action_type = (ActionType)lua_tointeger(L, index);
    if (action_type < NO_ACTION or action_type > MAX_ACTION_TYPE)
    {
        APPID_LOG(nullptr, TRACE_WARNING_LEVEL, "appid: Unsupported CHP Action type: %d, "
            "possible version mismatch.\n", action_type);
        return -1;
    }

    switch (action_type)
    {
    case REWRITE_FIELD:
    case INSERT_FIELD:
    case SEARCH_UNSUPPORTED:
    case GET_OFFSETS_FROM_REBUILT:
        // Valid action types but not supported, silently ignore
        return -1;
    default:
        break;
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
    size_t patternSize, char* patternData, ActionType actionType, char* optionalActionData,
    OdpContext& odp_ctxt)
{
    //find the CHP App for this
    auto chp_entry = CHP_glossary->find(appIdInstance);
    if (chp_entry == CHP_glossary->end() or !chp_entry->second)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid attempt to add a CHP action for "
            "unknown appId %d, instance %d. - pattern:\"%s\" - action \"%s\"\n", CHP_APPIDINSTANCE_TO_ID(appIdInstance),
            CHP_APPIDINSTANCE_TO_INSTANCE(appIdInstance), patternData, optionalActionData ? optionalActionData : "");
        snort_free(patternData);
        if (optionalActionData)
            snort_free(optionalActionData);
        return 0;
    }

    CHPApp* chpapp = chp_entry->second;

    if (isKeyPattern)
    {
        chpapp->key_pattern_count++;
        chpapp->key_pattern_length_sum += patternSize;
    }

    if (chpapp->ptype_scan_counts[patternType] == 0)
        chpapp->num_scans++;

    unsigned precedence = chpapp->ptype_scan_counts[patternType]++;
    // at runtime we'll want to know how many of each type of pattern we are looking for.
    if (actionType != ALTERNATE_APPID and actionType != DEFER_TO_SIMPLE_DETECT)
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
    odp_ctxt.get_http_matchers().insert_chp_pattern(chpa);

    if (actionType == DEFER_TO_SIMPLE_DETECT and strcmp(patternData,"<ignore-all-patterns>") == 0)
        odp_ctxt.get_http_matchers().remove_http_patterns_for_id(appIdInstance);

    return 0;
}

static int detector_add_chp_action(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

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
    if (get_chp_action_type(L, ++index, action))
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
        action, action_data, ud->get_odp_ctxt());
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

    for (instance=0; instance < CHP_APPID_INSTANCE_MAX; instance++)
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
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "LuaDetectorApi:Attempt to create more than %d CHP for appId %d",
            CHP_APPID_INSTANCE_MAX, appId);
        return 0;
    }

    if (create_chp_application(appIdInstance, app_type_flags, num_matches))
        return 0;

    lua_pushnumber(L, appIdInstance);
    return 1;
}

static int detector_add_chp_multi_action(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

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
    if (get_chp_action_type(L, ++index, action))
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
        action, action_data, ud->get_odp_ctxt());
}

static int detector_port_only_service(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    int index = 1;

    AppId appId = lua_tointeger(L, ++index);
    uint16_t port = lua_tointeger(L, ++index);
    IpProtocol protocol;
    if (toipprotocol(L, ++index, protocol))
        return 0;

    if (port == 0)
        ud->get_odp_ctxt().add_protocol_service_id(protocol, appId);
    else
        ud->get_odp_ctxt().add_port_service_id(protocol, port, appId);

    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(appId);

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
    IpProtocol proto;
    if (toipprotocol(L, ++index, proto))
    {
        lua_pushnumber(L, -1);
        return 1;
    }

    uint8_t sequence_cnt = lua_tonumber(L, ++index);
    const char* sequence_str = lua_tostring(L, ++index);

    if (((proto != IpProtocol::TCP) and (proto != IpProtocol::UDP))
        or ((sequence_cnt == 0) or (sequence_cnt > LENGTH_SEQUENCE_CNT_MAX))
        or ((sequence_str == nullptr) or (strlen(sequence_str) == 0)))
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "LuaDetectorApi:Invalid input (%d,%u,%u,\"%s\")!",
            appId, (unsigned)proto, (unsigned)sequence_cnt, sequence_str ? sequence_str : "");
        lua_pushnumber(L, -1);
        return 1;
    }

    LengthKey length_sequence;
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
            APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "LuaDetectorApi:Invalid sequence string (\"%s\")!",
                sequence_str);
            lua_pushnumber(L, -1);
            return 1;
        }
        str_ptr++;

        if (*str_ptr != '/')
        {
            APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "LuaDetectorApi:Invalid sequence string (\"%s\")!",
                sequence_str);
            lua_pushnumber(L, -1);
            return 1;
        }
        str_ptr++;

        uint16_t length = (uint16_t)atoi(str_ptr);

        if (length == 0)
        {
            APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "LuaDetectorApi:Invalid sequence string (\"%s\")!",
                sequence_str);
            lua_pushnumber(L, -1);
            return 1;
        }
        length_sequence.sequence[i].length = length;

        while ((*str_ptr != ',') and (*str_ptr != 0))
        {
            str_ptr++;
        }

        last_one = (i == (sequence_cnt - 1));
        if ((!last_one and (*str_ptr != ','))
            or (last_one and (*str_ptr != 0)))
        {
            APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "LuaDetectorApi:Invalid sequence string (\"%s\")!",
                sequence_str);
            lua_pushnumber(L, -1);
            return 1;
        }
        str_ptr++;
    }

    if (!ud->get_odp_ctxt().length_cache_add(length_sequence, appId))
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "LuaDetectorApi:Could not add entry to cache!");
        lua_pushnumber(L, -1);
        return 1;
    }

    lua_pushnumber(L, 0);
    return 1;
}

static int detector_add_url_application(lua_State* L)
{
    // Verify detector user data and that we are NOT in packet context
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    int index = 1;

    uint32_t service_id      = lua_tointeger(L, ++index);
    uint32_t client_id       = lua_tointeger(L, ++index);
    lua_tointeger(L, ++index); //client_id_type
    uint32_t payload_id      = lua_tointeger(L, ++index);
    lua_tointeger(L, ++index); // payload_type

    /* Verify that host pattern is a valid string */
    size_t host_pattern_size = 0;
    uint8_t* host_pattern = nullptr;
    const char* tmp_string = lua_tolstring(L, ++index, &host_pattern_size);
    if (!tmp_string or !host_pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid host pattern string: service_id %u; "
            "client_id %u; payload_id %u.\n", service_id, client_id, payload_id);
        return 0;
    }
    else
        host_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that path pattern is a valid string */
    size_t path_pattern_size = 0;
    uint8_t* path_pattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &path_pattern_size);
    if (!tmp_string or !path_pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid path pattern string: service_id %u; "
            "client_id %u; payload %u.\n", service_id, client_id, payload_id);
        snort_free(host_pattern);
        return 0;
    }
    else
        path_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that scheme pattern is a valid string */
    size_t schemePatternSize;
    uint8_t* schemePattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &schemePatternSize);
    if (!tmp_string or !schemePatternSize)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid scheme pattern string: service_id %u; "
            "client_id %u; payload %u.\n", service_id, client_id, payload_id);
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
    if (tmp_string and query_pattern_size)
        query_pattern = (uint8_t*)snort_strdup(tmp_string);

    uint32_t appId = lua_tointeger(L, ++index);
    AppInfoManager& app_info_manager = ud->get_odp_ctxt().get_app_info_mgr();
    DetectorAppUrlPattern* pattern =
        (DetectorAppUrlPattern*)snort_calloc(sizeof(DetectorAppUrlPattern));
    pattern->userData.service_id        = app_info_manager.get_appid_by_service_id(service_id);
    pattern->userData.client_id        = app_info_manager.get_appid_by_client_id(client_id);
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
    pattern->is_literal = true;
    ud->get_odp_ctxt().get_http_matchers().insert_url_pattern(pattern);

    app_info_manager.set_app_info_active(pattern->userData.service_id);
    app_info_manager.set_app_info_active(pattern->userData.client_id);
    app_info_manager.set_app_info_active(pattern->userData.payload_id);
    app_info_manager.set_app_info_active(appId);

    return 0;
}

static int detector_add_url_application_regex(lua_State* L)
{
    // Verify detector user data and that we are NOT in packet context
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    const FastPatternConfig* const fp = SnortConfig::get_conf()->fast_pattern_config;
    if (!MpseManager::is_regex_capable(fp->get_search_api())){
        APPID_LOG(nullptr, TRACE_WARNING_LEVEL, "WARNING: appid: Regex patterns require usage of "
            "regex capable search engine like hyperscan in %s\n", ud->get_detector()->get_name().c_str());
            return 0;
    }


    int index = 1;

    uint32_t service_id      = lua_tointeger(L, ++index);
    uint32_t client_id       = lua_tointeger(L, ++index);
    lua_tointeger(L, ++index); //client_id_type
    uint32_t payload_id      = lua_tointeger(L, ++index);
    lua_tointeger(L, ++index); // payload_type

    /* Verify that host pattern is a valid string */
    size_t host_pattern_size = 0;
    uint8_t* host_pattern = nullptr;
    const char* tmp_string = lua_tolstring(L, ++index, &host_pattern_size);
    if (!tmp_string or !host_pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid host regex pattern string: service_id %u; "
            "client_id %u; payload_id %u.\n", service_id, client_id, payload_id);
        return 0;
    }
    else
        host_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that path pattern is a valid string */
    size_t path_pattern_size = 0;
    uint8_t* path_pattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &path_pattern_size);
    if (!tmp_string or !path_pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid path regex pattern string: service_id %u; "
            "client_id %u; payload %u.\n", service_id, client_id, payload_id);
        snort_free(host_pattern);
        return 0;
    }
    else
        path_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that scheme pattern is a valid string */
    size_t schemePatternSize;
    uint8_t* schemePattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &schemePatternSize);
    if (!tmp_string or !schemePatternSize)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid scheme regex pattern string: service_id %u; "
            "client_id %u; payload %u.\n", service_id, client_id, payload_id);
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
    if (tmp_string and query_pattern_size)
        query_pattern = (uint8_t*)snort_strdup(tmp_string);

    uint32_t appId = lua_tointeger(L, ++index);
    AppInfoManager& app_info_manager = ud->get_odp_ctxt().get_app_info_mgr();
    DetectorAppUrlPattern* pattern =
        (DetectorAppUrlPattern*)snort_calloc(sizeof(DetectorAppUrlPattern));
    pattern->userData.service_id        = app_info_manager.get_appid_by_service_id(service_id);
    pattern->userData.client_id        = app_info_manager.get_appid_by_client_id(client_id);
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
    pattern->is_literal = false;
    ud->get_odp_ctxt().get_http_matchers().insert_url_pattern(pattern);

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
    if (!init(L))
        return 0;

    int index = 1;

    uint32_t service_id      = lua_tointeger(L, ++index);
    uint32_t client_id       = lua_tointeger(L, ++index);
    lua_tointeger(L, ++index); // client_id_type
    uint32_t payload_id         = lua_tointeger(L, ++index);
    lua_tointeger(L, ++index); // payload_type

    /* Verify that host pattern is a valid string */
    size_t host_pattern_size = 0;
    const char* tmp_string = lua_tolstring(L, ++index, &host_pattern_size);
    if (!tmp_string or !host_pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid RTMP host pattern string: service_id %u; "
            "client_id %u; payload_id %u.\n", service_id, client_id, payload_id);
        return 0;
    }
    uint8_t* host_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that path pattern is a valid string */
    size_t path_pattern_size = 0;
    tmp_string = lua_tolstring(L, ++index, &path_pattern_size);
    if (!tmp_string or !path_pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid RTMP path pattern string: service_id %u; "
            "client_id %u; payload_id %u.\n", service_id, client_id, payload_id);
        snort_free(host_pattern);
        return 0;
    }
    uint8_t* path_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that scheme pattern is a valid string */
    size_t schemePatternSize;
    tmp_string = lua_tolstring(L, ++index, &schemePatternSize);
    if (!tmp_string or !schemePatternSize)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid RTMP scheme pattern string: service_id %u; "
            "client_id %u; payload_id %u.\n", service_id, client_id, payload_id);
        snort_free(path_pattern);
        snort_free(host_pattern);
        return 0;
    }
    uint8_t* schemePattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that query pattern is a valid string */
    size_t query_pattern_size;
    uint8_t* query_pattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &query_pattern_size);
    if (tmp_string  and query_pattern_size)
        query_pattern = (uint8_t*)snort_strdup(tmp_string);

    uint32_t appId = lua_tointeger(L, ++index);

    /* Allocate memory for data structures */
    DetectorAppUrlPattern* pattern =
        (DetectorAppUrlPattern*)snort_calloc(sizeof(DetectorAppUrlPattern));

    /* we want to put these patterns in just like for regular Urls, but we do NOT need legacy IDs for them.
     * so just use the appID for service, client, or payload_id ID */
    pattern->userData.service_id        = service_id;
    pattern->userData.client_id         = client_id;
    pattern->userData.payload_id        = payload_id;
    pattern->userData.appId             = appId;
    pattern->userData.query.pattern     = query_pattern;
    pattern->userData.query.patternSize = query_pattern_size;
    pattern->patterns.host.pattern      = host_pattern;
    pattern->patterns.host.patternSize  = (int)host_pattern_size;
    pattern->patterns.path.pattern      = path_pattern;
    pattern->patterns.path.patternSize  = (int)path_pattern_size;
    pattern->patterns.scheme.pattern    = schemePattern;
    pattern->patterns.scheme.patternSize = (int)schemePatternSize;
    pattern->is_literal = true;
    ud->get_odp_ctxt().get_http_matchers().insert_rtmp_url_pattern(pattern);

    AppInfoManager& app_info_manager = ud->get_odp_ctxt().get_app_info_mgr();
    app_info_manager.set_app_info_active(pattern->userData.service_id);
    app_info_manager.set_app_info_active(pattern->userData.client_id);
    app_info_manager.set_app_info_active(pattern->userData.payload_id);
    app_info_manager.set_app_info_active(appId);

    return 0;
}

/*Lua should inject patterns in <client_id, clientVersion, multi-Pattern> format. */
static int detector_add_sip_user_agent(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    int index = 1;

    uint32_t client_app = lua_tointeger(L, ++index);
    const char* client_version = lua_tostring(L, ++index);
    if (!client_version)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid sip client version string.\n");
        return 0;
    }

    /* Verify that ua pattern is a valid string */
    size_t ua_len = 0;
    const char* ua_pattern = lua_tolstring(L, ++index, &ua_len);
    if (!ua_pattern or !ua_len)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid sip ua pattern string.\n");
        return 0;
    }

    ud->get_odp_ctxt().get_sip_matchers().add_ua_pattern(client_app, client_version, ua_pattern);

    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(client_app);

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
    if (!tmp_string or !appNameLen)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "Invalid appName string.\n");
        lua_pushnumber(L, APP_ID_NONE);
        return 1;   /*number of results */
    }

    if (control)
    {
        AppInfoTableEntry* entry = ud->get_odp_ctxt().get_app_info_mgr().add_dynamic_app_entry(tmp_string);
        appId = entry->appId;
        AppIdPegCounts::add_app_peg_info(tmp_string, appId);
    }
    else
        appId  = ud->get_odp_ctxt().get_app_info_mgr().get_appid_by_name(tmp_string);

    lua_pushnumber(L, appId);
    return 1;   /*number of results */
}

static int add_client_application(lua_State* L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    unsigned int service_id = lua_tonumber(L, 2);
    unsigned int client_id = lua_tonumber(L, 3);

    ud->cd->add_app(*lsd->ldp.asd, service_id, client_id, "", *lsd->ldp.change_bits);
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
    unsigned retValue = ud->sd->add_service(*lsd->ldp.change_bits, *lsd->ldp.asd, lsd->ldp.pkt,
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
    if (!init(L))
        return 0;

    int index = 1;

    /* Verify valid pattern type */
    enum httpPatternType pat_type = (enum httpPatternType)lua_tointeger(L, ++index);
    if (pat_type < HTTP_PAYLOAD or pat_type > HTTP_URL)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid HTTP pattern type in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }

    /* Verify valid DHSequence */
    DHPSequence seq  = (DHPSequence)lua_tointeger(L, ++index);
    uint32_t service_id = lua_tointeger(L, ++index);
    uint32_t client_id   = lua_tointeger(L, ++index);
    uint32_t payload_id = lua_tointeger(L, ++index);

    size_t pattern_size = 0;
    const uint8_t* pattern_str = (const uint8_t*)lua_tolstring(L, ++index, &pattern_size);
    if (!pattern_str or !pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid HTTP pattern string in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }

    DetectorHTTPPattern pattern;
    if (pattern.init(pattern_str, pattern_size, seq, service_id, client_id,
        payload_id, APP_ID_NONE))
    {
        ud->get_odp_ctxt().get_http_matchers().insert_http_pattern(pat_type, pattern);
        AppInfoManager& app_info_manager = ud->get_odp_ctxt().get_app_info_mgr();
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
    if (!init(L))
        return 0;

    int index = 1;

    uint32_t service_id = lua_tointeger(L, ++index);
    uint32_t client_id  = lua_tointeger(L, ++index);
    uint32_t payload_id = lua_tointeger(L, ++index);

    /* Verify that host pattern is a valid string */
    size_t host_pattern_size = 0;
    uint8_t* host_pattern = nullptr;
    const char* tmp_string = lua_tolstring(L, ++index, &host_pattern_size);
    if (!tmp_string or !host_pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid host pattern string: service_id %u; "
            "client_id %u; payload_id %u.\n", service_id, client_id, payload_id);
        return 0;
    }
    host_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that path pattern is a valid string */
    size_t path_pattern_size = 0;
    uint8_t* path_pattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &path_pattern_size);
    if (!tmp_string or !path_pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid path pattern string: service_id %u; "
            "client_id %u; payload_id %u.\n", service_id, client_id, payload_id);
        snort_free(host_pattern);
        return 0;
    }
    path_pattern = (uint8_t*)snort_strdup(tmp_string);

    /* Verify that scheme pattern is a valid string */
    size_t schemePatternSize;
    uint8_t* schemePattern = nullptr;
    tmp_string = lua_tolstring(L, ++index, &schemePatternSize);
    if (!tmp_string or !schemePatternSize)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid scheme pattern string: service_id %u; "
            "client_id %u; payload_id %u.\n", service_id, client_id, payload_id);
        snort_free(path_pattern);
        snort_free(host_pattern);
        return 0;
    }
    schemePattern = (uint8_t*)snort_strdup(tmp_string);

    /* Allocate memory for data structures */
    DetectorAppUrlPattern* pattern =
        (DetectorAppUrlPattern*)snort_calloc(sizeof(DetectorAppUrlPattern));
    pattern->userData.service_id        = service_id;
    pattern->userData.client_id         = client_id;
    pattern->userData.payload_id        = payload_id;
    pattern->userData.appId             = APP_ID_NONE;
    pattern->userData.query.pattern     = nullptr;
    pattern->userData.query.patternSize = 0;
    pattern->patterns.host.pattern      = host_pattern;
    pattern->patterns.host.patternSize  = (int)host_pattern_size;
    pattern->patterns.path.pattern      = path_pattern;
    pattern->patterns.path.patternSize  = (int)path_pattern_size;
    pattern->patterns.scheme.pattern    = schemePattern;
    pattern->patterns.scheme.patternSize = (int)schemePatternSize;
    pattern->is_literal = true;
    ud->get_odp_ctxt().get_http_matchers().insert_app_url_pattern(pattern);

    AppInfoManager& app_info_manager = ud->get_odp_ctxt().get_app_info_mgr();
    app_info_manager.set_app_info_active(service_id);
    app_info_manager.set_app_info_active(client_id);
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
    if (!init(L))
        return 0;

    size_t pattern_size = 0;
    int index = 1;

    IpProtocol protocol;
    if (toipprotocol(L, ++index, protocol))
        return 0;

    uint16_t port = 0;      // port = lua_tonumber(L, ++index);  FIXIT-RC - why commented out?
    const char* pattern = lua_tolstring(L, ++index, &pattern_size);
    unsigned position = lua_tonumber(L, ++index);
    AppId appid = lua_tointeger(L, ++index);
    if (appid <= APP_ID_NONE or !pattern or !pattern_size or
        (protocol != IpProtocol::TCP and protocol != IpProtocol::UDP))
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: addPortPatternClient() - Invalid input in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }

    PortPatternNode* pPattern  = (decltype(pPattern))snort_calloc(sizeof(PortPatternNode));
    // cppcheck-suppress internalAstError
    pPattern->pattern  = (decltype(pPattern->pattern))snort_calloc(pattern_size);
    pPattern->appId = appid;
    pPattern->protocol = protocol;
    pPattern->port = port;
    memcpy(pPattern->pattern, pattern, pattern_size);
    pPattern->length = pattern_size;
    pPattern->offset = position;
    pPattern->detector_name = snort_strdup(ud->get_detector()->get_name().c_str());
    ud->get_odp_ctxt().get_client_pattern_detector().insert_client_port_pattern(pPattern);

    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(appid);

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
    if (!init(L))
        return 0;

    size_t pattern_size = 0;
    int index = 1;

    IpProtocol protocol;
    if (toipprotocol(L, ++index, protocol))
        return 0;

    uint16_t port = lua_tonumber(L, ++index);
    const char* pattern = lua_tolstring(L, ++index, &pattern_size);
    unsigned position = lua_tonumber(L, ++index);
    AppId appid = lua_tointeger(L, ++index);

    if (appid <= APP_ID_NONE or !pattern or !pattern_size or
        (protocol != IpProtocol::TCP and protocol != IpProtocol::UDP))
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: addPortPatternService() - Invalid input in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }

    PortPatternNode* pPattern = (decltype(pPattern))snort_calloc(sizeof(PortPatternNode));
    pPattern->pattern  = (decltype(pPattern->pattern))snort_calloc(pattern_size);
    pPattern->appId = appid;
    pPattern->protocol = protocol;
    pPattern->port = port;
    memcpy(pPattern->pattern, pattern, pattern_size);
    pPattern->length = pattern_size;
    pPattern->offset = position;
    pPattern->detector_name = snort_strdup(ud->get_detector()->get_name().c_str());
    ud->get_odp_ctxt().get_service_pattern_detector().insert_service_port_pattern(pPattern);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(appid);

    return 0;
}

/*Lua should inject patterns in <client_id, clientVersion, multi-Pattern> format. */
static int detector_add_sip_server(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    int index = 1;

    uint32_t client_app = lua_tointeger(L, ++index);
    const char* client_version = lua_tostring(L, ++index);
    if (!client_version)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid sip client version string.\n");
        return 0;
    }

    /* Verify that server pattern is a valid string */
    size_t pattern_size = 0;
    const char* server_pattern = lua_tolstring(L, ++index, &pattern_size);
    if (!server_pattern or !pattern_size)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid sip server pattern string.\n");
        return 0;
    }

    ud->get_odp_ctxt().get_sip_matchers().add_server_pattern(client_app, client_version, server_pattern);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(client_app);

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
    IpProtocol proto;
    if (toipprotocol(L, 6, proto))
        return 0;
    AppId service_id = lua_tointeger(L, 7);
    AppId client_id  = lua_tointeger(L, 8);
    AppId payload_id = lua_tointeger(L, 9);
    AppId app_id_to_snort = lua_tointeger(L, 10);
    OdpContext& odp_ctxt = lsd->ldp.asd->get_odp_ctxt();
    if (app_id_to_snort > APP_ID_NONE)
    {
        AppInfoTableEntry* entry = odp_ctxt.get_app_info_mgr().get_app_info_entry(
            app_id_to_snort);
        if (!entry)
            return 0;
        snort_protocol_id = entry->snort_protocol_id;
    }

    AppIdSession* fp = AppIdSession::create_future_session(lsd->ldp.pkt,  &client_addr,
        client_port, &server_addr, server_port, proto, snort_protocol_id, odp_ctxt);
    if (fp)
    {
        fp->set_service_id(service_id, odp_ctxt);
        fp->set_client_id(client_id);
        fp->set_payload_id(payload_id);
        fp->set_session_flags(APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_NOT_A_SERVICE |
            APPID_SESSION_PORT_SERVICE_DONE);
        fp->service_disco_state = APPID_DISCO_STATE_FINISHED;
        fp->client_disco_state  = APPID_DISCO_STATE_FINISHED;

        return 1;
    }
    else
        return 0;
}

static int is_midstream_session(lua_State *L)
{
    auto& ud = *UserData<LuaClientObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    if (lsd->ldp.pkt->flow->get_session_flags() & SSNFLAG_MIDSTREAM)
    {
        lua_pushnumber(L, 1);
        return 1;
    }

    lua_pushnumber(L, 0);
    return 0;
}

/**Check if traffic is going through an HTTP proxy.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return int/stack - 1 if traffic is going through a proxy, 0 otherwise.
 */
static int is_http_tunnel(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    const AppIdHttpSession* hsession = lsd->ldp.asd->get_http_session();

    if (hsession)
    {
        if (hsession->payload.get_id() == APP_ID_HTTP_TUNNEL or
            hsession->payload.get_id() == APP_ID_HTTP_SSL_TUNNEL)
            lua_pushboolean(L, 1);
        else
            lua_pushboolean(L, 0);

        return 1;
    }

    return 0;
}

/**Get destination IP tunneled through a proxy.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return IPv4/stack - destination IPv4 address.
 */
static int get_http_tunneled_ip(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    const AppIdHttpSession* hsession = lsd->ldp.asd->get_http_session();
    if (hsession)
    {
        const TunnelDest* tunnel_dest = hsession->get_tun_dest();

        if (tunnel_dest)
        {
            lua_pushnumber(L, tunnel_dest->ip.get_ip4_value());
            return 1;
        }
    }

    lua_pushnumber(L, 0);
    return 1;
}

/**Get port tunneled through a proxy.
 *
 * @param Lua_State* - Lua state variable.
 * @param detector/stack - detector object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return portNumber/stack - source port number.
 */
static int get_http_tunneled_port(lua_State* L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are in packet context
    LuaStateDescriptor* lsd = ud->validate_lua_state(true);

    const AppIdHttpSession* hsession = lsd->ldp.asd->get_http_session();
    if (hsession)
    {
        const TunnelDest* tunnel_dest = hsession->get_tun_dest();

        if (tunnel_dest)
        {
            lua_pushnumber(L, tunnel_dest->port);
            return 1;
        }
    }

    lua_pushnumber(L, 0);
    return 1;
}

/*Lua should inject patterns in <client_id, class_id> format. */
static int detector_add_cip_connection_class(lua_State *L)
{
    int index = 1;

    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    uint32_t app_id = lua_tointeger(L, ++index);
    uint32_t class_id = lua_tointeger(L, ++index);

    ud->get_odp_ctxt().get_cip_matchers().cip_add_connection_class(app_id, class_id);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(app_id);

    return 0;
}

/*Lua should inject patterns in <client_id, class_id, service_id> format. */
static int detector_add_cip_path(lua_State *L)
{
    int index = 1;

    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    uint32_t app_id = lua_tointeger(L, ++index);
    uint32_t class_id = lua_tointeger(L, ++index);
    uint8_t service_id = lua_tointeger(L, ++index);

    ud->get_odp_ctxt().get_cip_matchers().cip_add_path(app_id, class_id, service_id);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(app_id);

    return 0;
}

/*Lua should inject patterns in <client_id, class_id, is_class_instance, attribute_id> format. */
static int detector_add_cip_set_attribute(lua_State *L)
{
    int index = 1;

    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    uint32_t app_id = lua_tointeger(L, ++index);
    uint32_t class_id = lua_tointeger(L, ++index);
    bool is_class_instance = lua_toboolean(L, ++index);
    uint32_t attribute_id = lua_tointeger(L, ++index);

    ud->get_odp_ctxt().get_cip_matchers().cip_add_set_attribute(app_id, class_id, is_class_instance, attribute_id);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(app_id);

    return 0;
}

/*Lua should inject patterns in <client_id, service_id> format. */
static int detector_add_cip_extended_symbol_service(lua_State *L)
{
    int index = 1;

    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    uint32_t app_id = lua_tointeger(L, ++index);
    uint8_t service_id = lua_tointeger(L, ++index);

    ud->get_odp_ctxt().get_cip_matchers().cip_add_extended_symbol_service(app_id, service_id);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(app_id);

    return 0;
}

/*Lua should inject patterns in <client_id, service_id> format. */
static int detector_add_cip_service(lua_State *L)
{
    int index = 1;

    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    uint32_t app_id = lua_tointeger(L, ++index);
    uint8_t service_id = lua_tointeger(L, ++index);

    ud->get_odp_ctxt().get_cip_matchers().cip_add_service(app_id, service_id);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(app_id);

    return 0;
}

/*Lua should inject patterns in <client_id, enip_command_id> format. */
static int detector_add_enip_command(lua_State *L)
{
    int index = 1;

    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    // Verify detector user data and that we are NOT in packet context
    ud->validate_lua_state(false);
    if (!init(L))
        return 0;

    uint32_t app_id = lua_tointeger(L, ++index);
    uint16_t command_id = lua_tointeger(L, ++index);

    ud->get_odp_ctxt().get_cip_matchers().cip_add_enip_command(app_id, command_id);
    ud->get_odp_ctxt().get_app_info_mgr().set_app_info_active(app_id);

    return 0;
}

static int get_user_detector_data_item(lua_State *L)
{
    auto& ud = *UserData<LuaObject>::check(L, DETECTOR, 1);
    ud->validate_lua_state(true);
    const char* table = lua_tostring(L, 2);
    if (!table)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid detector data table string in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }
    const char* key = lua_tostring(L, 3);
    if (!key)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: Invalid detector data key string in %s.\n",
            ud->get_detector()->get_name().c_str());
        return 0;
    }

    const char* item = ud->get_odp_ctxt().get_user_data_map().get_user_data_value_str(table, key);
    if (item)
    {
        size_t item_len = strlen(item);
        lua_pushlstring(L, item, item_len);
    }
    else
    {
        lua_pushnil(L);
    }

    return 1;
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
    { "cLog",                     detector_log_snort_message},
    { "addHttpPattern",           detector_add_http_pattern },
    { "addAppUrl",                detector_add_url_application },
    { "addAppUrlRegex",           detector_add_url_application_regex },
    { "addRTMPUrl",               detector_add_rtmp_url },
    { "addContentTypePattern",    detector_add_content_type_pattern },
    { "addSSLCertPattern",        detector_add_ssl_cert_pattern },
    { "addSSLCnamePattern",       detector_add_ssl_cname_pattern },
    { "addSSLCertRegexPattern",   detector_add_ssl_cert_regex_pattern },
    { "addSSLCnameRegexPattern",  detector_add_ssl_cname_regex_pattern },
    { "addSipUserAgent",          detector_add_sip_user_agent },
    { "addSipServer",             detector_add_sip_server },
    { "addSSHPattern",            detector_add_ssh_client_pattern},
    { "addHostFirstPktApp",       detector_add_host_first_pkt_application },
    { "addHostPortApp",           detector_add_host_port_application },
    { "addHostPortAppDynamic",    detector_add_host_port_dynamic },
    { "addDNSHostPattern",        detector_add_dns_host_pattern },
    { "registerClientDetectorCallback",   detector_register_client_callback },
    { "registerServiceDetectorCallback",  detector_register_service_callback },
    { "getSubstr",                detector_get_substr },
    { "substrIndex",              detector_find_substr },

    /*Obsolete - new detectors should not use this API */
    { "init",                     service_init },
    { "registerPattern",          service_register_pattern },
    { "addPort",                  service_add_ports },
    { "addService",               service_add_service },
    { "failService",              service_fail_service },
    { "inProcessService",         service_in_process_service },
    { "analyzePayload",           service_analyze_payload },

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
    { "service_addNetbiosDomain",   service_add_netbios_domain },

    /*client init API */
    { "client_init",              client_init },
    { "client_registerPattern",   client_register_pattern },
    { "client_getServiceId",      service_get_service_id },

    /*client service API */
    { "client_addApp",            client_add_application },
    { "client_addInfo",           client_add_info },
    { "client_addUser",           client_add_user },
    { "client_addPayload",        client_add_payload },

    /* add client mapping for process name derived by fingerprinting */
    { "addProcessToClientMapping", add_process_to_client_mapping },
    { "addAlpnToServiceMapping",  add_alpn_to_service_mapping },
    { "addProcessToClientMappingRegex", add_process_to_client_mapping_regex },

    //HTTP Multi Pattern engine
    { "CHPCreateApp",             detector_chp_create_application },
    { "CHPAddAction",             detector_add_chp_action },
    { "CHPMultiCreateApp",        detector_create_chp_multi_application }, // multiple detectors,
                                                                           // same appId
    { "CHPMultiAddAction",        detector_add_chp_multi_action },

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
    { "isMidStreamSession",       is_midstream_session },

    { "isHttpTunnel",             is_http_tunnel },
    { "getHttpTunneledIp",        get_http_tunneled_ip },
    { "getHttpTunneledPort",      get_http_tunneled_port },

    { "getUserDetectorDataItem",   get_user_detector_data_item },

     /* CIP registration */
    {"addCipConnectionClass",    detector_add_cip_connection_class},
    {"addCipPath",               detector_add_cip_path},
    {"addCipSetAttribute",       detector_add_cip_set_attribute},
    {"addCipExtendedSymbolService", detector_add_cip_extended_symbol_service},
    {"addCipService",            detector_add_cip_service},
    {"addEnipCommand",           detector_add_enip_command},

    { nullptr, nullptr }
};

/* Garbage collector hook function. Called when Lua side garbage collects detector
 * api instance. Current design is to allocate one of each luaState, detector and
 * detectorUserData buffers, and hold these buffers till appid exits. SigHups processing
 * reuses the buffers and calls DetectorInit to reinitialize. AppId ensures that
 * UserData<LuaDetectionState> is not garbage collected, by creating a reference in LUA_REGISTRY
 * table. The reference is released only on appid exit.
 *
 * If in future, one needs to free any of these buffers then one should consider
 * references to detector buffer in  ServiceDetector stored in flows and hostServices
 * data structures. Other detectors at this time create one static instance for the
 * lifetime of appid, and therefore we have adopted the same principle for Lua Detectors.
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
    auto my_lua_state = odp_thread_local_ctxt->get_lua_state();
    if (!my_lua_state)
    {
        APPID_LOG(args.pkt, TRACE_ERROR_LEVEL, "lua detector %s: no LUA state\n", package_info.name.c_str());
        lua_settop(my_lua_state, 0);
        return APPID_ENULL;
    }

    // get the table for this chunk (env)
    lua_getfield(my_lua_state, LUA_REGISTRYINDEX, package_info.name.c_str());
    ldp.data = args.data;
    ldp.size = args.size;
    ldp.dir = args.dir;
    ldp.asd = &args.asd;
    ldp.change_bits = &args.change_bits;
    ldp.pkt = args.pkt;
    const char* validateFn = package_info.validateFunctionName.c_str();

    if ((!validateFn) or (validateFn[0] == '\0'))
    {
        ldp.pkt = nullptr;
        lua_settop(my_lua_state, 0);
        return APPID_NOMATCH;
    }

    lua_getfield(my_lua_state, -1, validateFn); // get the function we want to call

    if (lua_pcall(my_lua_state, 0, 1, 0))
    {
        // Runtime Lua errors are suppressed in production code since detectors are written for
        // efficiency and with defensive minimum checks. Errors are dealt as exceptions
        // that don't impact processing by other detectors or future packets by the same detector.
        APPID_LOG(args.pkt, TRACE_ERROR_LEVEL, "lua detector %s: error validating %s\n",
            package_info.name.c_str(), lua_tostring(my_lua_state, -1));
        ldp.pkt = nullptr;
        odp_thread_local_ctxt->free_detector_flow();
        lua_settop(my_lua_state, 0);
        return APPID_ENULL;
    }

    /**detectorFlows must be destroyed after each packet is processed.*/
    odp_thread_local_ctxt->free_detector_flow();

    /* retrieve result */
    if (!lua_isnumber(my_lua_state, -1))
    {
        APPID_LOG(args.pkt, TRACE_ERROR_LEVEL, "lua detector %s: returned non-numeric value\n",
            package_info.name.c_str());
        ldp.pkt = nullptr;
        lua_settop(my_lua_state, 0);
        return APPID_ENULL;
    }

    int rc = lua_tonumber(my_lua_state, -1);
    lua_pop(my_lua_state, 1);
    ldp.pkt = nullptr;
    lua_settop(my_lua_state, 0);

    return rc;
}

static bool init_lsd(LuaStateDescriptor* lsd, const std::string& detector_name,
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

    if (lsd->package_info.validateFunctionName.empty())
        return false;

    return true;
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
    const std::string& log_name, bool is_custom, IpProtocol protocol, lua_State* L,
    OdpContext& odp_ctxt) : LuaObject(odp_ctxt)
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
            appid_detectors = odp_ctxt.get_service_disco_mgr().get_tcp_detectors();
            auto detector = appid_detectors->find(detector_name);
            if (detector != appid_detectors->end())
                ad = detector->second;
        }
        else if (protocol == IpProtocol::UDP)
        {
            appid_detectors = odp_ctxt.get_service_disco_mgr().get_udp_detectors();
            auto detector = appid_detectors->find(detector_name);
            if (detector != appid_detectors->end())
                ad = detector->second;
        }
        sd = (ServiceDetector*)ad;
    }

    UserData<LuaServiceObject>::push(L, DETECTOR, this);

    lua_pushvalue(L, -1);

    // FIXIT-E: The control and thread states have the same initialization
    // sequence, the stack index shouldn't change between the states, maybe
    // use a common index for a detector between all the states
    std::string name = detector_name + "_";
    lua_setglobal(L, name.c_str());
}

int LuaServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    auto my_lua_state = odp_thread_local_ctxt->get_lua_state();
    if (lua_gettop(my_lua_state))
    	APPID_LOG(args.pkt, TRACE_WARNING_LEVEL, "appid: leak of %d lua stack elements before service validate\n",
        lua_gettop(my_lua_state));

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

LuaClientObject::LuaClientObject(const std::string& detector_name,
    const std::string& log_name, bool is_custom, IpProtocol protocol, lua_State* L,
    OdpContext& odp_ctxt, bool& has_validate) : LuaObject(odp_ctxt)
{
    has_validate = init_lsd(&lsd, detector_name, L);

    if (init(L))
    {
        cd = new LuaClientDetector(&(odp_ctxt.get_client_disco_mgr()), detector_name,
            log_name, is_custom, lsd.package_info.minimum_matches, protocol);
    }
    else
    {
        AppIdDetector *ad = nullptr;
        AppIdDetectors *appid_detectors = nullptr;

        if (protocol == IpProtocol::TCP)
        {
            appid_detectors = odp_ctxt.get_client_disco_mgr().get_tcp_detectors();
            auto detector = appid_detectors->find(detector_name);
            if (detector != appid_detectors->end())
                ad = detector->second;
        }
        else if (protocol == IpProtocol::UDP)
        {
            appid_detectors = odp_ctxt.get_client_disco_mgr().get_udp_detectors();
            auto detector = appid_detectors->find(detector_name);
            if (detector != appid_detectors->end())
                ad = detector->second;
        }
        cd = (ClientDetector*)ad;
    }

    UserData<LuaClientObject>::push(L, DETECTOR, this);

    lua_pushvalue(L, -1);

    // FIXIT-E: The control and thread states have the same initialization
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
    auto my_lua_state = odp_thread_local_ctxt->get_lua_state();
    if (lua_gettop(my_lua_state))
        APPID_LOG(args.pkt, TRACE_WARNING_LEVEL, "appid: leak of %d lua stack elements before client validate\n",
            lua_gettop(my_lua_state));

    std::string name = this->name + "_";
    lua_getglobal(my_lua_state, name.c_str());
    auto& ud = *UserData<LuaClientObject>::check(my_lua_state, DETECTOR, 1);
    return ud->lsd.lua_validate(args);
}
