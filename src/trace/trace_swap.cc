//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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
#include "managers/trace_logger_manager.h"
#include "packet_io/packet_constraints.h"

#include "trace_api.h"
#include "trace_config.h"
#include "trace_parser.h"

using namespace snort;

const Parameter* TraceSwapParams::s_params = nullptr;

void TraceSwapParams::set_params(const Parameter* params)
{ s_params = params; }

const Parameter* TraceSwapParams::get_params()
{ return s_params; }

class TraceSwap : public AnalyzerCommand
{
public:
    TraceSwap(TraceConfig* tc, ControlConn* con) : AnalyzerCommand(con), trace_config(tc)
    { assert(trace_config); }

    ~TraceSwap() override;

    bool execute(Analyzer&, void**) override;

    const char* stringify() override
    { return "TRACE_SWAP"; }

private:
    TraceConfig* trace_config = nullptr;
};

TraceSwap::~TraceSwap()
{
    // Update configuration for the main thread
    TraceApi::thread_reinit(trace_config);
    SnortConfig::get_main_conf()->set_overlay_trace_config(trace_config);
    log_message("== trace.%s complete\n", (trace_config->initialized ? "set" : "clear"));
}

bool TraceSwap::execute(Analyzer&, void**)
{
    // Update configuration for packet threads
    TraceApi::thread_reinit(trace_config);
    return true;
}


bool TraceSwapParams::set_ntuple(lua_State* L, TraceParser& parser, const Parameter* root)
{
    if ( !lua_isboolean(L, -1) )
    {
        LogMessage(".. invalid value for option: %s\n", root->name);
        return false;
    }
    parser.get_trace_config().ntuple = bool(lua_toboolean(L, -1));
    return true;
}

bool TraceSwapParams::set_timestamp(lua_State* L, TraceParser& parser, const Parameter* root)
{
    if ( !lua_isboolean(L, -1) )
    {
        LogMessage(".. invalid value for option: %s\n", root->name);
        return false;
    }
    parser.get_trace_config().timestamp = bool(lua_toboolean(L, -1));
    return true;
}

bool TraceSwapParams::set_output(lua_State* L, TraceParser& parser, const Parameter* root)
{
    if ( !lua_isstring(L, -1) )
    {
        LogMessage(".. invalid value for option: %s\n", root->name);
        return false;
    }
    std::string outputs = lua_tostring(L, -1);

    std::stringstream ss(outputs);
    std::string tok;

    TraceConfig& tc = parser.get_trace_config();
    tc.output_traces.clear();

    while ( ss >> tok )
    {
        if ( tok != "none" )
            tc.output_traces.push_back(tok);
    }

    return true;
}

bool TraceSwapParams::set_modules(lua_State* L, TraceParser& parser, const Parameter* root)
{
    parser.clear_traces();

    bool error = false;
    const Parameter* modules_param = (const Parameter*)root->range;

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
                const Parameter* trace_param = Parameter::find((const Parameter*)option_param->range, val_name);

                Value val(false);
                val.set(trace_param);

                if ( lua_isnumber(L, -1) )
                    val.set((double)lua_tointeger(L, -1));
                else
                    val.set(luaL_checkstring(L, -1));

                if ( !trace_param or !trace_param->validate(val) or
                    !parser.set_traces(option_name, val) )
                {
                    LogMessage(".. invalid trace value: %s.%s.%s = %s\n",
                        root->name, option_name, val_name, val.get_as_string().c_str());

                    error = true;
                }
                lua_pop(L, 1);
            }
        }
        else if ( lua_isnumber(L, -1) and option_param )
        {
            Value val((double)lua_tointeger(L, -1));
            val.set(option_param);

            if ( !option_param->validate(val) or
                !parser.set_traces(option_name, val) )
            {
                LogMessage(".. invalid option value: %s.%s = %s\n",
                    root->name, option_name, val.get_as_string().c_str());

                error = true;
            }
        }
        else
        {
            LogMessage(".. invalid option: %s.%s\n", root->name, option_name);

            error = true;
        }
        lua_pop(L, 1);
    }
    return !error;
}

bool TraceSwapParams::set_constraints(lua_State* L, TraceParser& parser, const Parameter* root)
{
    parser.clear_constraints();

    bool error = false;
    const Parameter* constraints_param = (const Parameter*)root->range;

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
             !parser.set_constraints(val) )
        {
            LogMessage(".. invalid constraints value: %s.%s = %s\n",
                root->name, val_name, val.get_as_string().c_str());

            error = true;
        }
        lua_pop(L, 1);
    }
    return !error;
}

int TraceSwapParams::set(lua_State* L)
{
    const SnortConfig* sc = SnortConfig::get_conf();

    // Create an overlay TraceConfig based on the current configuration
    // It will be set in a SnortConfig during TraceSwap execution and owned by it after
    TraceConfig* trace_config = new TraceConfig(sc->overlay_trace_config
        ? *sc->overlay_trace_config : *sc->trace_config);

    // Passed Lua entry check
    if ( lua_gettop(L) != 1 or !lua_istable(L, 1) )
    {
        LogMessage(".. invalid Lua entry, %s: %s\n",
            "use the outer table and pass options inside of it",
            "{ modules = {}, constraints = {} }");

        LogMessage("== trace.set failed\n");

        delete trace_config;
        return 0;
    }

    TraceParser trace_parser(*trace_config);
    const Parameter* params_tree = get_params();

    bool parse_err = false;
    bool constraints_set = false;

    // Outer table traversal
    lua_pushnil(L);

    while ( lua_next(L, 1) )
    {
        const char* root_element_key = luaL_checkstring(L, -2);
        const Parameter* root_parameter = Parameter::find(params_tree, root_element_key);

        if ( !root_parameter )
        {
            LogMessage(".. invalid parameter: %s\n", root_element_key);
            parse_err = true;
            lua_pop(L, 1);
            continue;
        }

        if ( !strcmp(root_element_key, "ntuple") )
        {
            parse_err |= !set_ntuple(L, trace_parser, root_parameter);
            lua_pop(L, 1);
            continue;
        }

        if ( !strcmp(root_element_key, "timestamp") )
        {
            parse_err |= !set_timestamp(L, trace_parser, root_parameter);
            lua_pop(L, 1);
            continue;
        }

        if ( !strcmp(root_element_key, "output") )
        {
            parse_err |= !set_output(L, trace_parser, root_parameter);
            lua_pop(L, 1);
            continue;
        }

        if ( !lua_istable(L, -1) )
        {
            LogMessage(".. invalid table: %s\n", root_element_key);
            parse_err = true;
            lua_pop(L, 1);
            continue;
        }

        else if ( !strcmp(root_element_key, "modules") )
        {
            parse_err |= !set_modules(L, trace_parser, root_parameter);
            lua_pop(L, 1);
            continue;
        }
        else if ( !strcmp(root_element_key, "constraints") )
        {
            parse_err |= !set_constraints(L, trace_parser, root_parameter);
            lua_pop(L, 1);
            constraints_set = true;
            continue;
        }
        lua_pop(L, 1);
    }

    if ( parse_err )
    {
        delete trace_config;
        LogMessage("== trace.set failed\n");
    }
    else
    {
        if ( constraints_set )
            trace_parser.finalize_constraints();

        TraceLoggerManager::instantiate_default_loggers(&trace_parser.get_trace_config());
        trace_parser.get_trace_config().initialized = true;

        ControlConn* ctrlcon = ControlConn::query_from_lua(L);
        main_broadcast_command(new TraceSwap(&trace_parser.get_trace_config(), ctrlcon), ctrlcon);
    }
    return 0;
}

int TraceSwapParams::clear(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    // Create an empty overlay TraceConfig
    // It will be set in a SnortConfig during TraceSwap execution and owned by it after
    main_broadcast_command(new TraceSwap(new TraceConfig, ctrlcon), ctrlcon);
    return 0;
}

