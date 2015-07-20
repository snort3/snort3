//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
// piglet_runner.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet_runner.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "helpers/lua.h"

#include "piglet_manager.h"

namespace Piglet
{
using namespace std;

static inline int load_buffer(lua_State* L, string buffer, string filename)
{ return luaL_loadbuffer(L, buffer.c_str(), buffer.size(), filename.c_str()); }

static bool get_configuration(lua_State* L, Test& t)
{
    Lua::ManageStack ms(L);
    const Chunk* chunk = t.chunk;

    if ( load_buffer(L, chunk->buffer, chunk->filename) )
    {
        t << lua_tostring(L, -1);
        t.endl();
        return true;
    }

    if ( lua_pcall(L, 0, LUA_MULTRET, 0) )
    {
        t << lua_tostring(L, -1);
        t.endl();
        return true;
    }

    lua_getglobal(L, "piglet");
    if ( !lua_istable(L, -1) )
    {
        t << "global 'piglet' is not a table";
        t.endl();
        return true;
    }

    lua_getfield(L, -1, "name");
    t.name = lua_tostring(L, -1);
    lua_pop(L, 1);

    lua_getfield(L, -1, "type");
    t.type = lua_tostring(L, -1);
    lua_pop(L, 1);

    lua_getfield(L, -1, "target");
    t.target = lua_tostring(L, -1);
    lua_pop(L, 1);

    return false;
}

static bool run_test(lua_State* L, Test& t)
{
    Lua::ManageStack ms(L, 2);

    lua_getglobal(L, "piglet");
    if ( !lua_istable(L, -1) )
    {
        t << "global 'piglet' is not a table";
        t.endl();
        return true;
    }

    lua_getfield(L, -1, "test");
    if ( !lua_isfunction(L, -1) )
    {
        t << "'piglet.test' is not a function";
        t.endl();
        return true;
    }

    if ( lua_pcall(L, 0, 1, 0) )
    {
        t << lua_tostring(L, -1) << "";
        t.endl();
        return true;
    }

    t.result = lua_toboolean(L, -1);

    return false;
}

// -----------------------------------------------------------------------------
// Private Methods
// -----------------------------------------------------------------------------

void Runner::run(Test& t)
{
    Lua::State state { true };

    if ( get_configuration(state.get_ptr(), t) )
    {
        t << "couldn't configure test";
        t.endl();
        return;
    }

    auto p = Manager::instantiate(state, t.type, t.target);
    if ( p == nullptr )
    {
        t << "couldn't instantiate piglet";
        t.endl();
        return;
    }

    if ( p->setup() )
    {
        t << "couldn't setup piglet\n";
        t.endl();
    }
    else if ( run_test(state.get_ptr(), t) )
    {
        t << "error in entry point test()";
        t.endl();
    }

    Manager::destroy(p);
}

// -----------------------------------------------------------------------------
// Public Methods
// -----------------------------------------------------------------------------

Test Runner::run(const Chunk& c)
{
    Test test;
    test.chunk = &c;
    test.timer.start();

    run(test);

    test.timer.stop();

    return test;
}
} // namespace Piglet

