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

// lua_detector_flow_api.h author Sourcefire Inc.

#ifndef LUA_DETECTOR_FLOW_API_H
#define LUA_DETECTOR_FLOW_API_H

// This module supports API towards Lua detectors for performing specific operations on a flow
// object.
// The flow object on Lua side is a userData.

#include "lua_detector_util.h"

struct lua_State;
class AppIdSession;

struct DetectorFlow
{
    DetectorFlow(lua_State* myLuaState, AppIdSession* asd)
    : myLuaState(myLuaState), asd(asd) { }

    ~DetectorFlow()
    {
        /*The detectorUserData itself is a userdata and therefore be freed by Lua side. */
        if (userDataRef != LUA_REFNIL)
        {
            luaL_unref(myLuaState, LUA_REGISTRYINDEX, userDataRef);
            userDataRef = LUA_REFNIL;
        }
    }

    lua_State* myLuaState;
    AppIdSession* asd;
    int userDataRef;
};

int register_detector_flow_api(lua_State*);

#endif

