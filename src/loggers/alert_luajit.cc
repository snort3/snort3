//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// alert_luajit.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/ips_context.h"
#include "detection/signature.h"
#include "events/event.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "helpers/chunk.h"
#include "log/messages.h"
#include "lua/lua.h"
#include "main/thread_config.h"
#include "managers/lua_plugin_defs.h"
#include "managers/plugin_manager.h"
#include "managers/script_manager.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"

using namespace snort;

static THREAD_LOCAL ProfileStats luaLogPerfStats;

static THREAD_LOCAL const Event* event;
static THREAD_LOCAL SnortEvent lua_event;

static THREAD_LOCAL Packet* packet;
static THREAD_LOCAL SnortPacket lua_packet;

SO_PUBLIC const SnortEvent* get_event()
{
    assert(event);

    lua_event.gid = event->sig_info->gid;
    lua_event.sid = event->sig_info->sid;
    lua_event.rev = event->sig_info->rev;

    lua_event.event_id = event->event_id;
    lua_event.event_ref = event->event_reference;

    if ( event->sig_info->message )
        lua_event.msg = event->sig_info->message;
    else
        lua_event.msg = "";

    lua_event.svc = event->sig_info->num_services ? event->sig_info->services[1].service : "n/a";

    return &lua_event;
}

SO_PUBLIC const SnortPacket* get_packet()
{
    assert(packet);

    switch ( packet->type() )
    {
    case PktType::IP: lua_packet.type = "IP"; break;
    case PktType::TCP: lua_packet.type = "TCP"; break;
    case PktType::UDP: lua_packet.type = "UDP"; break;
    case PktType::ICMP: lua_packet.type = "ICMP"; break;
    default: lua_packet.type = "OTHER";
    }

    lua_packet.num = packet->context->packet_number;
    lua_packet.sp = packet->ptrs.sp;
    lua_packet.dp = packet->ptrs.dp;

    return &lua_packet;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "args", Parameter::PT_STRING, nullptr, nullptr,
      "luajit logger arguments" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event from custom Lua script"

class LuaLogModule : public Module
{
public:
    LuaLogModule(const char* name) : Module(name, s_help, s_params)
    { }

    bool begin(const char*, int, SnortConfig*) override
    {
        args.clear();
        return true;
    }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        args = v.get_string();
        return true;
    }

    ProfileStats* get_profile() const override
    { return &luaLogPerfStats; }

    Usage get_usage() const override
    { return CONTEXT; }

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

    void alert(Packet*, const char*, const Event&) override;

    static const struct LogApi* get_api();

private:
    std::string config;
    std::vector<Lua::State> states;
};

LuaJitLogger::LuaJitLogger(const char* name, std::string& chunk, LuaLogModule* mod)
{
    // create an args table with any rule options
    config = "args = { ";
    config += mod->args;
    config += "}";

    unsigned max = ThreadConfig::get_instance_max();

    // FIXIT-L might make more sense to have one instance with one lua state in
    // each thread instead of one instance with one lua state per thread (same
    // for LuaJitOption)
    for ( unsigned i = 0; i < max; i++ )
    {
        states.emplace_back(true);
        init_chunk(states[i], chunk, name, config);
    }
}


void LuaJitLogger::alert(Packet* p, const char*, const Event& e)
{
    Profile profile(luaLogPerfStats);

    packet = p;
    event = &e;

    lua_State* L = states[get_instance_id()];

    Lua::ManageStack ms(L, 1);

    lua_getglobal(L, "alert");
    if ( lua_pcall(L, 0, 1, 0) )
    {
        const char* err = lua_tostring(L, -1);
        ErrorMessage("%s\n", err);
    }
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
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "luajit",
        "Lua JIT script for logging events",
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    log_ctor,
    log_dtor,
};

const LogApi* log_luajit = &log_lua_api;

