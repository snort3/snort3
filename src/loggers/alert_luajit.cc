//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "protocols/eth.h"
#include "protocols/ipv6.h"
#include "detection/ips_context.h"
#include "events/event.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "log/messages.h"
#include "lua/lua.h"
#include "main/thread_config.h"
#include "managers/lua_plugin_defs.h"
#include "managers/plugin_manager.h"
#include "managers/script_manager.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "utils/chunk.h"

using namespace snort;

static THREAD_LOCAL ProfileStats luaLogPerfStats;

static THREAD_LOCAL const Event* event;
static THREAD_LOCAL SnortEvent lua_event;

static THREAD_LOCAL Packet* packet;
static THREAD_LOCAL SnortPacket lua_packet;

SO_PUBLIC const SnortEvent* get_event()
{
    assert(event);
    event->get_sig_ids(lua_event.gid, lua_event.sid, lua_event.rev);

    lua_event.event_id = event->get_event_id();
    lua_event.event_ref = event->get_event_reference();

    lua_event.msg = event->get_msg();
    if ( !lua_event.msg ) lua_event.msg = "";

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
    lua_packet.dst_addr = "";

    if ( !(packet->proto_bits & PROTO_BIT__ETH) ) {
        lua_packet.ether_dst = lua_packet.ether_src = "";
        return &lua_packet;
    }

    static THREAD_LOCAL char eth_src[eth::ETH_ADDR_STR_LEN], eth_dst[eth::ETH_ADDR_STR_LEN];

    const eth::EtherHdr* eh = layer::get_eth_layer( packet );

    if(eh && eh->ether_src) {
        snprintf(eth_src, eth::ETH_ADDR_STR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_src[0],
            eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
            eh->ether_src[4], eh->ether_src[5]);

        lua_packet.ether_src = (const char*)eth_src;
    } else {
        lua_packet.ether_src = "";
    }

    if(eh && eh->ether_dst) {
        snprintf(eth_dst, eth::ETH_ADDR_STR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_dst[0],
            eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
            eh->ether_dst[4], eh->ether_dst[5]);

        lua_packet.ether_dst = (const char*)eth_dst;
    } else {
        lua_packet.ether_dst = "";
    }

    if ( packet->has_ip() or packet->is_data() ) {
        static THREAD_LOCAL char ip[ip::IP6_MAX_STR_LEN];
        packet->ptrs.ip_api.get_dst()->ntop(ip, ip::IP6_MAX_STR_LEN);
        lua_packet.dst_addr = ip;
    }

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
    { return GLOBAL; }

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
    : config("args = { " + mod->args + "}")
{
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
    // cppcheck-suppress unreadVariable
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

static Logger* log_ctor(Module* m)
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

