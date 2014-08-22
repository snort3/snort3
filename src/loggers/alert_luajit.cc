/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// alert_luajit.cc author Russ Combs <rucombs@cisco.com>

#include <lua.hpp>

#include "main/snort_types.h"
#include "events/event.h"
#include "helpers/chunk.h"
#include "managers/event_manager.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "managers/script_manager.h"
#include "hash/sfhashfcn.h"
#include "parser/parser.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "time/profiler.h"

static THREAD_LOCAL ProfileStats luaLogPerfStats;

//-------------------------------------------------------------------------
// ffi stuff
//-------------------------------------------------------------------------

struct SnortEvent
{
    unsigned gid;
    unsigned sid;
    unsigned rev;

    uint32_t event_id;
    uint32_t event_ref;

    const char* msg;
    const char* svc;
    const char* os;
};

extern "C" {
// ensure Lua can link with this
const SnortEvent* get_event();
}

static THREAD_LOCAL Event* event;
static THREAD_LOCAL SnortEvent lua_event;

SO_PUBLIC const SnortEvent* get_event()
{
    assert(event);

    lua_event.gid = event->sig_info->generator;
    lua_event.sid = event->sig_info->id;
    lua_event.rev = event->sig_info->rev;

    lua_event.event_id = event->event_id;
    lua_event.event_ref = event->event_reference;

    lua_event.msg = event->sig_info->message;
    lua_event.svc = event->sig_info->num_services ? event->sig_info->services[1].service : "n/a";
    lua_event.os = event->sig_info->os ? event->sig_info->os : "n/a";

    return &lua_event;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter luajit_params[] =
{
    { "args", Parameter::PT_STRING, nullptr, nullptr,
      "luajit logger arguments" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class LuaLogModule : public Module
{
public:
    LuaLogModule(const char* name) : Module(name, luajit_params)
    { };

    bool begin(const char*, int, SnortConfig*)
    {
        args.clear();
        return true;
    };

    bool set(const char*, Value& v, SnortConfig*)
    {
        args = v.get_string();
        return true;
    };

    ProfileStats* get_profile() const
    { return &luaLogPerfStats; };

public:
    std::string args;
};

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class LuaJitLogger : public Logger
{
public:
    LuaJitLogger(const char* name, std::string& chunk, class LuaLogModule*);
    ~LuaJitLogger();

    void alert(Packet*, const char*, Event*);

    static const struct LogApi* get_api();

private:
    std::string config;
    struct lua_State** lua;
};

LuaJitLogger::LuaJitLogger(const char* name, std::string& chunk, LuaLogModule* mod)
{
    // create an args table with any rule options
    config = "args = { ";
    config += mod->args;
    config += "}";

    unsigned max = get_instance_max();

    lua = new lua_State*[max];

    // FIXIT-L might make more sense to have one instance
    // with one lua state in each thread instead of one
    // instance with one lua state per thread
    // (same for LuaJitOption)
    for ( unsigned i = 0; i < max; ++i )
        init_chunk(lua[i], chunk, name, config);
}

LuaJitLogger::~LuaJitLogger()
{
    unsigned max = get_instance_max();

    for ( unsigned i = 0; i < max; ++i )
        term_chunk(lua[i]);

    delete[] lua;
}

void LuaJitLogger::alert(Packet*, const char*, Event* e)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(luaLogPerfStats);

    event = e;

    lua_State* L = lua[get_instance_id()];
    lua_getglobal(L, "alert");

    if ( lua_pcall(L, 0, 1, 0) )
    {
        const char* err = lua_tostring(L, -1);
        ErrorMessage("%s\n", err);
        MODULE_PROFILE_END(luaLogPerfStats);
    }
    MODULE_PROFILE_END(luaLogPerfStats);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    const char* key = PluginManager::get_current_plugin();
    return new LuaLogModule(key);
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Logger* log_ctor(SnortConfig*, Module* m)
{
    const char* key = m->get_name();
    std::string* chunk = ScriptManager::get_chunk(key);

    if ( !chunk )
        return nullptr;

    LuaLogModule* mod = (LuaLogModule*)m;
    return new LuaJitLogger(key, *chunk, mod);
}

static void log_dtor(Logger* p)
{
    delete p;
}

static const LogApi log_lua_api =
{
    {
        PT_LOGGER,
        "tbd",
        LOGAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    log_ctor,
    log_dtor,
};

const LogApi* log_luajit = &log_lua_api;

