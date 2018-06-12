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
// piglet_runner.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "piglet_runner.h"

#include <cassert>

#include "lua/lua.h"
#include "lua/lua_table.h"
#include "lua/lua_util.h"

#include "piglet_api.h"
#include "piglet_manager.h"
#include "piglet_output.h"
#include "piglet_utils.h"

using namespace snort;

namespace Piglet
{
using namespace std;

static inline bool load_chunk(lua_State* L, const Chunk& chunk)
{
    return luaL_loadbuffer(
        L, chunk.buffer.c_str(), chunk.buffer.size(), chunk.filename.c_str());
}

static bool setup_globals(lua_State* L, Test& t)
{
    // Add script_dir env var
    Lua::set_script_dir(L, SCRIPT_DIR_VARNAME, t.chunk->filename);
    return false;
}

static bool configure_test(lua_State* L, Test& t)
{
    Lua::ManageStack ms(L);

    if ( setup_globals(L, t) )
    {
        t.set_error("couldn't setup globals");
        return true;
    }

    if ( load_chunk(L, *t.chunk) )
    {
        t.set_error("couldn't load test chunk");
        t.set_error(lua_tostring(L, -1));
        return true;
    }

    if ( lua_pcall(L, 0, LUA_MULTRET, 0) )
    {
        t.set_error("couldn't run test chunk");
        t.set_error(lua_tostring(L, -1));
        return true;
    }

    lua_getglobal(L, "plugin");

    if ( !lua_istable(L, -1) )
    {
        t.set_error("'plugin' table not found");
        return true;
    }

    Lua::Table table(L, -1);
    table.get_field("description", t.description);
    table.get_field("use_defaults", t.use_defaults);

    return false;
}

static bool run_test(lua_State* L, Test& t)
{
    Lua::ManageStack ms(L, 2);

    lua_getglobal(L, "plugin");
    if ( !lua_istable(L, -1) )
    {
        t.set_error("global 'plugin' is not a table");
        return true;
    }

    lua_getfield(L, -1, "test");
    if ( !lua_isfunction(L, -1) )
    {
        t.set_error("'plugin.test' is not a function");
        return true;
    }

    if ( lua_pcall(L, 0, 1, 0) )
    {
        t.set_error(lua_tostring(L, -1));
        return true;
    }

    if ( lua_toboolean(L, -1) )
        t.result = Test::PASSED;
    else
        t.result = Test::FAILED;

    return false;
}

// -----------------------------------------------------------------------------
// Private Methods
// -----------------------------------------------------------------------------

void Runner::run(const struct Output& output, Test& t, unsigned i)
{
    Lua::State state { true };

    if ( configure_test(state.get_ptr(), t) )
    {
        t.set_error("couldn't configure test");
        return;
    }

    auto p = Manager::instantiate(
        state, t.chunk->target, t.type, t.name, t.use_defaults);

    // FIXIT-L this injection is a hack so we can log the test header with
    // all the parsed information filled in

    if ( output.on_test_start )
        output.on_test_start(t, i);

    if ( p )
    {
        if ( p->setup() )
            t.set_error("environment setup failed");
        else if ( run_test(state.get_ptr(), t) )
            t.set_error("test function error");

        Manager::destroy(p);
    }
    else
    {
        t.set_error("couldn't instantiate piglet");
    }
}

// -----------------------------------------------------------------------------
// Public Methods
// -----------------------------------------------------------------------------

bool Runner::run_all(const struct Output& output, const vector<Chunk>& chunks)
{
    Summary summary;

    // FIXIT-L the checks for null belong somewhere else (maybe in Output?)
    if ( output.on_suite_start )
        output.on_suite_start(chunks);

    unsigned i = 0;
    for ( const auto& chunk : chunks )
    {
        Test test(chunk);

        run(output, test, i); // <-- RUN TEST

        // FIXIT-L this logic belongs somewhere else (maybe in Summary?)
        switch ( test.result )
        {
            case Test::PASSED:
                summary.passed++;
                break;

            case Test::FAILED:
                summary.failed++;
                break;

            case Test::ERROR:
                summary.errors++;
                break;

            default:
                assert(false);
                break;
        }

        if ( output.on_test_end )
            output.on_test_end(test, i++);
    }

    if ( output.on_suite_end )
        output.on_suite_end(summary);

    if ( summary.errors || summary.failed )
        return false;

    return true;
}

bool Runner::run_all(const struct Output& output)
{ return run_all(output, Manager::get_chunks()); }
} // namespace Piglet

