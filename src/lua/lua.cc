//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// lua.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lua.h"

#include <cassert>
#include <utility>

#include "log/messages.h"

namespace Lua
{
State::State(bool openlibs)
{
    state = luaL_newstate();

    if ( !state )
        snort::FatalError("Lua state instantiation failed\n");

    if ( openlibs )
        luaL_openlibs(state);
}

State::State(State&& o) :
    state { std::move(o.state) } { }

State::~State()
{
    if ( state )
        lua_close(state);
}

ManageStack::ManageStack(lua_State* L, int extra) :
    state ( L )
{
    top = lua_gettop(state);

    if ( extra > 0 )
        assert(lua_checkstack(state, extra));
}

ManageStack::~ManageStack()
{
    if ( lua_gettop(state) > top )
        lua_settop(state, top);
}
}

