//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "control/control.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/analyzer_command.h"
#include "main/snort_config.h"
#include "packet_io/packet_constraints.h"

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
    const Parameter* ntuple_params = Parameter::find(params, "ntuple");
    const Parameter* timestamp_params = Parameter::find(params, "timestamp");
    const Parameter* modules_params = Parameter::find(params, "modules");
    const Parameter* constraints_params = Parameter::find(params, "constraints");

    assert(ntuple_params);
    assert(timestamp_params);
    assert(modules_params);
    assert(constraints_params);

    static const Parameter trace_params[] =
    {
        *modules_params,

        *constraints_params,

        *ntuple_params,

        *timestamp_params,

        { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
    };

    static const Command commands[] =
    {
        { "set", set, trace_params,
          "set modules traces, constraints, ntuple and timestamp options" },

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

struct LogParams
{
    bool set_traces;
    bool set_constraints;
    bool set_ntuple;
    bool set_timestamp;

    bool is_set() const
    { return set_traces or set_constraints or set_ntuple or set_timestamp; }

    void print_msg() const
    {
        if ( set_traces and set_constraints )
            LogMessage("== set modules traces and constraints\n");
        else if ( !is_set() )
            LogMessage("== clear modules traces and constraints\n");
        else if ( set_traces )
            LogMessage("== set modules traces\n");
        else if ( set_constraints )
            LogMessage("== set constraints\n");

        if ( set_ntuple )
            LogMessage("== set ntuple option\n");

        if ( set_timestamp )
            LogMessage("== set timestamp option\n");
    }
};

class TraceSwap : public AnalyzerCommand
{
public:
    TraceSwap(TraceConfig* tc, const LogParams& lp)
        : trace_config(tc),
          log_params(lp)
    { assert(trace_config); }
    ~TraceSwap() override;

    bool execute(Analyzer&, void**) override;
    const char* stringify() override
    { return "TRACE_SWAP"; }

private:
    TraceConfig* trace_config = nullptr;
    LogParams log_params;
};

TraceSwap::~TraceSwap()
{
    // Update configuration for the main thread
    // and set overlay TraceConfig
    TraceApi::thread_reinit(trace_config);
    SnortConfig::get_main_conf()->set_overlay_trace_config(trace_config);

    log_params.print_msg();
}

bool TraceSwap::execute(Analyzer&, void**)
{
    // Update configuration for packet threads
    TraceApi::thread_reinit(trace_config);

    log_params.print_msg();
    return true;
}

static int set(lua_State* L)
{
    const SnortConfig* sc = SnortConfig::get_conf();

    if ( !sc->trace_config->initialized )
    {
        LogMessage("== WARNING: Trace module was not configured during "
            "initial startup. Ignoring the new trace configuration.\n");
        return 0;
    }

    // Create an overlay TraceConfig based on the current configuration
    // It will be set in a SnortConfig during TraceSwap execution and owned by it after
    TraceConfig* trace_config = new TraceConfig(sc->overlay_trace_config
        ? *sc->overlay_trace_config : *sc->trace_config);

    // Passed Lua entry check
    if ( lua_gettop(L) != 1 or !lua_istable(L, 1) )
    {
        LogMessage("== invalid Lua entry is provided, %s: %s\n",
            "use the outer table and pass options inside of it",
            "{ modules = {}, constraints = {} }");

        delete trace_config;
        return 0;
    }

    TraceParser trace_parser(*trace_config);
    const Parameter* params_tree = TraceSwapParams::get_params();
    LogParams log_params{};
    bool parse_err = false;

    // Outer table traversal
    lua_pushnil(L);
    while ( lua_next(L, 1) )
    {
        const char* root_element_key = luaL_checkstring(L, -2);
        const Parameter* root_parameter = Parameter::find(params_tree, root_element_key);

        // log n-tuple
        if ( !strcmp(root_element_key, params_tree[2].name) )
        {
            if ( lua_isboolean(L, -1) and root_parameter )
            {
                log_params.set_ntuple = true;
                trace_parser.get_trace_config().ntuple = bool(lua_toboolean(L, -1));
            }
            else
            {
                LogMessage("== invalid value for option: %s\n", root_element_key);
                parse_err = true;
            }

            lua_pop(L, 1);
            continue;
        }

        // log time stamp
        if ( !strcmp(root_element_key, params_tree[3].name) )
        {
            if ( lua_isboolean(L, -1) and root_parameter )
            {
                log_params.set_timestamp = true;
                trace_parser.get_trace_config().timestamp = bool(lua_toboolean(L, -1));
            }
            else
            {
                LogMessage("== invalid value for option: %s\n", root_element_key);
                parse_err = true;
            }

            lua_pop(L, 1);
            continue;
        }

        if ( !lua_istable(L, -1) or !root_parameter )
        {
            LogMessage("== invalid table is provided: %s\n", root_element_key);
            parse_err = true;
            lua_pop(L, 1);
            continue;
        }

        // "modules" table traversal
        else if ( !strcmp(root_element_key, params_tree[0].name) )
        {
            log_params.set_traces = true;
            trace_parser.clear_traces();

            const Parameter* modules_param = (const Parameter*)root_parameter->range;

            int modules_tbl_idx = lua_gettop(L);
            lua_pushnil(L);
            while ( lua_next(L, modules_tbl_idx) )
            {
                const char* option_name = luaL_checkstring(L, -2);
                const Parameter* option_param = Parameter::find(modules_param, option_name);

                // Trace table traversal
                if ( lua_istable(L, -1) and option_param )
                {
                    int module_tbl_idx = lua_gettop(L);
                    lua_pushnil(L);
                    while ( lua_next(L, module_tbl_idx) )
                    {
                        const char* val_name = luaL_checkstring(L, -2);
                        const Parameter* trace_param = Parameter::find(
                            (const Parameter*)option_param->range, val_name);

                        Value val(false);
                        val.set(trace_param);

                        if ( lua_isnumber(L, -1) )
                            val.set((double)lua_tointeger(L, -1));
                        else
                            val.set(luaL_checkstring(L, -1));

                        if ( !trace_param or !trace_param->validate(val) or
                            !trace_parser.set_traces(option_name, val) )
                        {
                            LogMessage("== invalid trace value is provided: %s.%s.%s = %s\n",
                                root_element_key, option_name, val_name,
                                val.get_as_string().c_str());

                            parse_err = true;
                        }

                        lua_pop(L, 1);
                    }
                }
                // Enable all option
                else if ( lua_isnumber(L, -1) and option_param )
                {
                    Value val((double)lua_tointeger(L, -1));
                    val.set(option_param);

                    if ( !option_param->validate(val) or
                        !trace_parser.set_traces(option_name, val) )
                    {
                        LogMessage("== invalid option value is provided: %s.%s = %s\n",
                            root_element_key, option_name, val.get_as_string().c_str());

                        parse_err = true;
                    }
                }
                // Error
                else
                {
                    LogMessage("== invalid option is provided: %s.%s\n", root_element_key,
                        option_name);

                    parse_err = true;
                }

                lua_pop(L, 1);
            }
        }
        // "constraints" table traversal
        else if ( !strcmp(root_element_key, params_tree[1].name) )
        {
            log_params.set_constraints = true;
            trace_parser.clear_constraints();

            const Parameter* constraints_param = (const Parameter*)root_parameter->range;

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
                else if ( lua_isboolean(L, -1) )
                    val.set(bool(lua_toboolean(L, -1)));
                else
                    val.set(luaL_checkstring(L, -1));

                if ( !filter_param or !filter_param->validate(val) or
                     !trace_parser.set_constraints(val) )
                {
                    LogMessage("== invalid constraints value is provided: %s.%s = %s\n",
                        root_element_key, val_name, val.get_as_string().c_str());

                    parse_err = true;
                }

                lua_pop(L, 1);
            }
        }

        lua_pop(L, 1);
    }

    if ( !parse_err )
    {
        if ( !log_params.is_set() )
        {
            trace_parser.clear_traces();
            trace_parser.clear_constraints();
        }

        if ( log_params.set_constraints )
            trace_parser.finalize_constraints();

        ControlConn* ctrlcon = ControlConn::query_from_lua(L);
        main_broadcast_command(new TraceSwap(&trace_parser.get_trace_config(), log_params), ctrlcon);
    }
    else
        delete trace_config;

    return 0;
}

static int clear(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    // Create an empty overlay TraceConfig
    // It will be set in a SnortConfig during TraceSwap execution and owned by it after
    main_broadcast_command(new TraceSwap(new TraceConfig, {}), ctrlcon);
    return 0;
}

