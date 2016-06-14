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

// lua_detector_flow_api.h author Sourcefire Inc.

#ifndef LUA_DETECTOR_FLOW_API_H
#define LUA_DETECTOR_FLOW_API_H

// This module supports API towards Lua detectors for performing specific operations on a flow object.
// The flow object on Lua side is a userData.

struct lua_State;
class AppIdData;

struct DetectorFlow
{
    // FIXIT-H J why is the lua state and user data ref on this object?
    lua_State* myLuaState;
    AppIdData* pFlow;
    int userDataRef;
};

int DetectorFlow_register(lua_State*);
void freeDetectorFlow(void* userdata);

#endif
