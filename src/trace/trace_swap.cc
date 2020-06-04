//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// trace_swap.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace_swap.h"

#include <lua.hpp>

#include "framework/module.h"
#include "log/messages.h"
#include "main/analyzer_command.h"
#include "main/snort_config.h"

#include "trace_api.h"
#include "trace_config.h"
#include "trace_parser.h"

using namespace snort;

const Command* TraceSwapParams::s_commands = nullptr;
const Parameter* TraceSwapParams::s_params = nullptr;

static int set(lua_State*);
static int clear(lua_State*);

void TraceSwapParams::set_params(const Parameter* params)
{
    const Parameter* modules_params = Parameter::find(params, "modules");
    const Parameter* constraints_params = Parameter::find(params, "constraints");

    assert(modules_params);
    assert(constraints_params);

    static const Parameter trace_params[] =
    {
        *modules_params,

        *constraints_params,

        { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
    };

    static const Command commands[] =
    {
        { "set", set, trace_params, "set modules traces and constraints" },

        { "clear", clear, nullptr, "clear modules traces and constraints" },

        { nullptr, nullptr, nullptr, nullptr }
    };

    s_params = trace_params;
    s_commands = commands;
}

const Command* TraceSwapParams::get_commands()
{ return s_commands; }

const Parameter* TraceSwapParams::get_params()
{ return s_params; }

class TraceSwap : public AnalyzerCommand
{
public:
    TraceSwap(TraceConfig* tc, bool set_traces = false, bool set_constraints = false)
        : trace_config(tc),
          is_set_traces(set_traces),
          is_set_constraints(set_constraints)
    { assert(trace_config); }
    ~TraceSwap() override;

    bool execute(Analyzer&, void**) override;
    const char* stringify() override
    { return "TRACE_SWAP"; }

private:
    void print_msg() const;

private:
    TraceConfig* trace_config = nullptr;
    bool is_set_traces;
    bool is_set_constraints;
};

TraceSwap::~TraceSwap()
{
    // Update configuration for the main thread
    // and set overlay TraceConfig
    TraceApi::thread_reinit(trace_config);
    SnortConfig::get_main_conf()->set_overlay_trace_config(trace_config);

    print_msg();
}

bool TraceSwap::execute(Analyzer&, void**)
{
    // Update configuration for packet threads
    TraceApi::thread_reinit(trace_config);

    print_msg();
    return true;
}

void TraceSwap::print_msg() const
{
    if ( is_set_traces and is_set_constraints )
        LogMessage("== set modules traces and constraints\n");
    else if ( !is_set_traces and !is_set_constraints )
        LogMessage("== clear modules traces and constraints\n");
    else if ( is_set_traces )
        LogMessage("== set modules traces\n");
    else if ( is_set_constraints )
        LogMessage("== set constraints\n");
}

static int set(lua_State* L)
{
    // Create an overlay TraceConfig based on the current configuration
    // It will be set in a SnortConfig during TraceSwap execution and owned by it after
    const SnortConfig* sc = SnortConfig::get_conf();
    TraceConfig* trace_config = new TraceConfig(sc->overlay_trace_config
        ? *sc->overlay_trace_config : *sc->trace_config);

    TraceParser trace_parser(trace_config);

    const Parameter* params_tree = TraceSwapParams::get_params();
    bool parse_err = false;
    bool set_traces = false;
    bool set_constraints = false;

    // Passed Lua entry check
    if ( lua_gettop(L) != 1 or !lua_istable(L, 1) )
    {
        LogMessage("== invalid Lua entry is provided, %s: %s\n",
            "use the outer table and pass options inside of it",
            "{ modules = {}, constraints = {} }");

        delete trace_config;
        return 0;
    }

    // Outer table traversal
    lua_pushnil(L);
    while ( lua_next(L, 1) )
    {
        const char* root_tbl_name = luaL_checkstring(L, -2);
        const Parameter* root_tbl_param = Parameter::find(params_tree, root_tbl_name);

        if ( !lua_istable(L, -1) or !root_tbl_param )
        {
            LogMessage("== invalid table is provided: %s\n", root_tbl_name);
            parse_err = true;
            lua_pop(L, 1);
            continue;
        }

        // "modules" table traversal
        if ( !strcmp(root_tbl_name, params_tree[0].name) )
        {
            set_traces = true;
            trace_parser.clear_traces();

            const Parameter* modules_param = (const Parameter*)root_tbl_param->range;

            int modules_tbl_idx = lua_gettop(L);
            lua_pushnil(L);
            while ( lua_next(L, modules_tbl_idx) )
            {
                const char* module_name = luaL_checkstring(L, -2);
                const Parameter* module_param = Parameter::find(modules_param, module_name);

                if ( !lua_istable(L, -1) or !module_param )
                {
                    LogMessage("== invalid table is provided: %s.%s\n", root_tbl_name,
                        module_name);

                    parse_err = true;
                    lua_pop(L, 1);
                    continue;
                }

                // Trace table traversal
                int module_tbl_idx = lua_gettop(L);
                lua_pushnil(L);
                while ( lua_next(L, module_tbl_idx) )
                {
                    const char* val_name = luaL_checkstring(L, -2);
                    const Parameter* trace_param = Parameter::find(
                        (const Parameter*)module_param->range, val_name);

                    Value val(false);
                    val.set(trace_param);

                    if ( lua_isnumber(L, -1) )
                        val.set((double)lua_tointeger(L, -1));
                    else
                        val.set(luaL_checkstring(L, -1));

                    if ( !trace_param or !trace_param->validate(val) or
                         !trace_parser.set_traces(module_name, val) )
                    {
                        LogMessage("== invalid trace value is provided: %s.%s.%s = %s\n",
                            root_tbl_name, module_name, val_name, val.get_as_string());

                        parse_err = true;
                    }

                    lua_pop(L, 1);
                }

                lua_pop(L, 1);
            }
        }
        // "constraints" table traversal
        else if ( !strcmp(root_tbl_name, params_tree[1].name) )
        {
            set_constraints = true;
            trace_parser.clear_constraints();

            const Parameter* constraints_param = (const Parameter*)root_tbl_param->range;

            int constraints_tbl_idx = lua_gettop(L);
            lua_pushnil(L);
            while ( lua_next(L, constraints_tbl_idx) )
            {
                const char* val_name = luaL_checkstring(L, -2);
                const Parameter* filter_param = Parameter::find(constraints_param, val_name);
                Value val(false);
                val.set(filter_param);

                if ( lua_isnumber(L, -1) )
                    val.set((double)lua_tointeger(L, -1));
                else
                    val.set(luaL_checkstring(L, -1));

                if ( !filter_param or !filter_param->validate(val) or
                     !trace_parser.set_constraints(val) )
                {
                    LogMessage("== invalid constraints value is provided: %s.%s = %s\n",
                        root_tbl_name, val_name, val.get_as_string());

                    parse_err = true;
                }

                lua_pop(L, 1);
            }
        }

        lua_pop(L, 1);
    }

    if ( !parse_err )
    {
        if ( !set_traces and !set_constraints )
        {
            trace_parser.clear_traces();
            trace_parser.clear_constraints();
        }

        main_broadcast_command(new TraceSwap(
            trace_parser.get_trace_config(), set_traces, set_constraints),
            true);
    }
    else
        delete trace_config;

    return 0;
}

static int clear(lua_State*)
{
    // Create an empty overlay TraceConfig
    // It will be set in a SnortConfig during TraceSwap execution and owned by it after
    main_broadcast_command(new TraceSwap(new TraceConfig()), true);
    return 0;
}

