//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// lua_detector_flow_api.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lua_detector_flow_api.h"

#include "appid_api.h"
#include "appid_inspector.h"
#include "lua_detector_api.h"
#include "lua_detector_module.h"
#include "lua_detector_util.h"

using namespace snort;

/* Lua flag bit/index to C flag value (0 for invalid). */
static const uint64_t FLAGS_TABLE_LUA_TO_C[32]
{
    0,                                /*  0 */
    0,                                /*  1 */
    0,                                /*  2 */
    0,                                /*  3 */
    0,                                /*  4 */
    0,                                /*  5 */
    0,                                /*  6 */
    0,                                /*  7 */
    0,                                /*  8 */
    0,                                /*  9 */
    0,                                /* 10 */
    0,                                /* 11 */
    0,                                /* 12 */
    0,                                /* 13 */
    0,                                /* 14 */
    0,                                /* 15 */
    0,                                /* 16 */
    0,                                /* 17 */
    0,                                /* 18 */
    0,                                /* 19 */
    0,                                /* 20 */
    0,                                /* 21 */
    APPID_SESSION_UDP_REVERSED,       /* 22: udpReversed */
    APPID_SESSION_INCOMPATIBLE,       /* 23: incompatible */
    APPID_SESSION_IGNORE_HOST,        /* 24: ignoreHost */
    0,                                /* 25: ignoreTcpSeq -- OBSOLETE */
    APPID_SESSION_CLIENT_DETECTED,    /* 26: ClientAppDetected */
    0,                                /* 27: gotBanner    -- OBSOLETE */
    APPID_SESSION_NOT_A_SERVICE,      /* 28: notAService */
    0,                                /* 29: logUnknown   -- OBSOLETE */
    APPID_SESSION_CONTINUE,           /* 30: continue */
    APPID_SESSION_SERVICE_DETECTED    /* 31: serviceDetected */
};

/* C flag bit/index to Lua flag value (0 for invalid). */
static const uint64_t FLAGS_TABLE_C_TO_LUA[32]
{
    0,                 /*  0 */
    0,                 /*  1 */
    0,                 /*  2 */
    0,                 /*  3 */
    0,                 /*  4 */
    0,                 /*  5 */
    0,                 /*  6 */
    0,                 /*  7 */
    0,                 /*  8 */
    0,                 /*  9 */
    0,                 /* 10 */
    0,                 /* 11 */
    0x00400000,        /* 12: APPID_SESSION_UDP_REVERSED */
    0,                 /* 13 */
    0x80000000,        /* 14: APPID_SESSION_SERVICE_DETECTED */
    0x04000000,        /* 15: APPID_SESSION_CLIENT_DETECTED */
    0x10000000,        /* 16: APPID_SESSION_NOT_A_SERVICE */
    0,                 /* 17 */
    0,                 /* 18 */
    0x40000000,        /* 19: APPID_SESSION_CONTINUE */
    0x01000000,        /* 20: APPID_SESSION_IGNORE_HOST */
    0x00800000,        /* 21: APPID_SESSION_INCOMPATIBLE */
    0,                 /* 22 */
    0,                 /* 23 */
    0,                 /* 24 */
    0,                 /* 25 */
    0,                 /* 26 */
    0,                 /* 27 */
    0,                 /* 28 */
    0,                 /* 29 */
    0,                 /* 30 */
    0                  /* 31 */
};

/* Convert flag bits used by the Lua code into what the C code uses. */
static inline uint64_t convert_flags_lua_to_c(uint64_t in)
{
    uint64_t out = 0;
    unsigned i;
    uint64_t msk;

    msk = 1;
    for (i = 0; i < 32; i++)
    {
        if (in & msk)
            out |= FLAGS_TABLE_LUA_TO_C[i];
        msk <<= 1;
    }

    return out;
}

/* Convert flag bits used by the C code into what the Lua code uses. */
static inline uint64_t convert_flags_c_to_lua(uint64_t in)
{
    uint64_t out = 0;
    unsigned i;
    uint64_t msk;

    msk = 1;
    for (i = 0; i < 32; i++)
    {
        if (in & msk)
            out |= FLAGS_TABLE_C_TO_LUA[i];
        msk <<= 1;
    }

    return out;
}

/**Sets a flow flag
 *
 * @param Lua_State* - Lua state variable.
 * @param detectorFlow/stack - UserData<DetectorFlow> object
 * @param flags/stack - flags to be set.
 * @return int - Number of elements on stack, which is 0
 */
static int set_detector_flow_flag(lua_State* L)
{
    uint64_t flags;

    auto& pLuaData = *UserData<DetectorFlow>::check(L, DETECTORFLOW, 1);
    // Verify detector user data and that we are in packet context
    assert(pLuaData.ptr);

    flags = lua_tonumber(L, 2);
    flags = convert_flags_lua_to_c(flags);

    pLuaData->asd->set_session_flags(flags);

    return 0;
}

/**Gets a flow flag value
 *
 * @param Lua_State* - Lua state variable.
 * @param detectorFlow/stack - UserData<DetectorFlow> object
 * @param flags/stack - flags to get.
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return flagValue/stack - value of a given flag.
 */
static int get_detector_flow_flag(lua_State* L)
{
    uint64_t flags;
    uint64_t ret;

    auto& pLuaData = *UserData<DetectorFlow>::check(L, DETECTORFLOW, 1);
    // Verify detector user data and that we are in packet context
    assert(pLuaData.ptr);

    flags = lua_tonumber(L, 2);
    flags = convert_flags_lua_to_c(flags);

    ret = pLuaData->asd->get_session_flags(flags);
    ret = convert_flags_c_to_lua(ret);
    lua_pushnumber(L, ret);

    return 1;
}

/**Clear a flow flag,
 *
 * @param Lua_State* - Lua state variable.
 * @param detectorFlow/stack - UserData<DetectorFlow> object
 * @param flags/stack - flags to be cleared.
 * @return int - Number of elements on stack, which is 0.
 */
static int clear_detector_flow_flag(lua_State* L)
{
    uint64_t flags;

    auto& pLuaData = *UserData<DetectorFlow>::check(L, DETECTORFLOW, 1);
    // Verify detector user data and that we are in packet context
    assert(pLuaData.ptr);

    flags = lua_tonumber(L, 2);
    flags = convert_flags_lua_to_c(flags);

    pLuaData->asd->clear_session_flags(flags);

    return 0;
}

/**Design: For simplicity reason I am passing flowkey (20 bytes) to lua detectors.
 * The key is used to index into local lua table and get any flow specific data that a detector needs.
 * This approach avoids embedding lua detector data into core engine flow data structure.
 *
 * For optimization, I could have created an integer index on C side. This can be taken up in future.
 */

/**Get flow key from a UserData<DetectorFlow> object
 *
 * @param Lua_State* - Lua state variable.
 * @param detectorflow/stack - UserData<DetectorFlow> object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return flowKey/stack - A 20 byte flow key
 */
static int get_detector_flow_key(lua_State* L)
{
    auto& pLuaData = *UserData<DetectorFlow>::check(L, DETECTORFLOW, 1);
    // Verify detector user data and that we are in packet context
    assert(pLuaData.ptr);

    lua_pushstring(L, pLuaData->asd->get_api().get_session_id().c_str());

    return 1;
}

static const luaL_Reg detector_flow_api[] =
{
    { "setFlowFlag",        set_detector_flow_flag },
    { "getFlowFlag",        get_detector_flow_flag },
    { "clearFlowFlag",      clear_detector_flow_flag },
    { "getFlowKey",         get_detector_flow_key },
    { nullptr, nullptr }
};

// lua_close will ensure that all detectors and flows get _gc called.
static int gc_detector_flow(lua_State*)
{
    return 0;
}

static int detector_flow_tostring(lua_State* L)
{
    char buff[32];
    snprintf(buff, sizeof(buff), "%p", (void*)UserData<DetectorFlow>::check(L, DETECTORFLOW, 1));
    lua_pushfstring(L, "UserData<DetectorFlow> (%s)", buff);
    return 1;
}

static const luaL_Reg detector_flow_meta[] =
{
    { "__gc",       gc_detector_flow },
    { "__tostring", detector_flow_tostring },
    { nullptr, nullptr }
};

/**Registers C functions as an API, enabling Lua detector to call these functions. This function
 * should be called once before loading any lua detectors. This function itself is not part of API
 * and therefore can not be called by a Lua detection.
 *
 * @param Lua_State* - Lua state variable.
 * @param detectorFlow/stack - UserData<DetectorFlow> object
 * @return int - Number of elements on stack, which is 1 if successful, 0 otherwise.
 * @return methodArray/stack - array of newly created methods
 */
int register_detector_flow_api(lua_State* L)
{
    /* populates a new table with Detector_methods (method_table), add the table to the globals and
       stack*/
    luaL_openlib(L, DETECTORFLOW, detector_flow_api, 0);

    /* create metatable for Foo, add it to the Lua registry, metatable on stack */
    luaL_newmetatable(L, DETECTORFLOW);

    /* populates table on stack with Detector_meta methods, puts the metatable on stack*/
    luaL_openlib(L, nullptr, detector_flow_meta, 0);

    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);             /* dup methods table*/
    lua_settable(L, -3);              /* metatable.__index = methods */

    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);               /* dup methods table*/
    lua_settable(L, -3);                /* hide metatable: metatable.__metatable = methods */
    lua_pop(L, 1);                      /* drop metatable */
    return 1;                           /* return methods on the stack */
}

