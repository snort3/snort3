//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

// host_cache_module.cc author Steve Chew <stechew@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_cache_module.h"

#include <fstream>
#include <lua.hpp>
#include <sys/stat.h>

#include "control/control.h"
#include "log/messages.h"
#include "managers/module_manager.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

THREAD_LOCAL const Trace* host_cache_trace = nullptr;

//-------------------------------------------------------------------------
// commands
//-------------------------------------------------------------------------
static int host_cache_dump(lua_State* L)
{
    HostCacheModule* mod = (HostCacheModule*) ModuleManager::get_module(HOST_CACHE_NAME);
    if ( mod )
        mod->log_host_cache( luaL_optstring(L, 1, nullptr), true );
    return 0;
}

static int host_cache_get_stats(lua_State* L)
{
    HostCacheModule* mod = (HostCacheModule*) ModuleManager::get_module(HOST_CACHE_NAME);

    if ( mod )
    {
        ControlConn* ctrlcon = ControlConn::query_from_lua(L);
        string outstr = mod->get_host_cache_stats();
        ctrlcon->respond("%s", outstr.c_str());
    }
    return 0;
}

static int host_cache_delete_host(lua_State* L)
{
    HostCacheModule* mod = (HostCacheModule*) ModuleManager::get_module(HOST_CACHE_NAME);
    if ( mod )
    {
        const char* ips = luaL_optstring(L, 1, nullptr);
        if (ips == nullptr)
        {
            debug_logf(host_cache_trace, nullptr,  "Usage: host_cache.delete_host(ip)\n");
            return 0;
        }

        SfIp ip;
        if (ip.set(ips) != SFIP_SUCCESS)
        {
            debug_logf(host_cache_trace, nullptr,  "Bad ip %s\n", ips);
            return 0;
        }

        auto ht = host_cache.find(ip);
        if ( ht )
            ht->set_visibility(false);
        else
        {
            debug_logf(host_cache_trace, nullptr,  "%s not found in host cache\n", ips);
            return 0;
        }
        debug_logf(host_cache_trace, nullptr,  "host_cache_delete_host done\n");
    }
    return 0;
}

static int host_cache_delete_network_proto(lua_State* L)
{
    HostCacheModule* mod = (HostCacheModule*) ModuleManager::get_module(HOST_CACHE_NAME);
    if ( mod )
    {
        const char* ips = luaL_optstring(L, 1, nullptr);
        int proto = luaL_optint(L, 2, -1);

        if (ips == nullptr || proto == -1)
        {
            debug_logf(host_cache_trace, nullptr,  "Usage: host_cache.delete_network_proto(ip, proto)\n");
            return 0;
        }

        SfIp ip;
        if (ip.set(ips) != SFIP_SUCCESS)
        {
            debug_logf(host_cache_trace, nullptr,  "Bad ip %s\n", ips);
            return 0;
        }

        auto ht = host_cache.find(ip);
        if ( ht )
        {
            if ( !ht->set_network_proto_visibility(proto, false) )
            {
                debug_logf(host_cache_trace, nullptr,  "%d not found for host %s\n", proto, ips);
                return 0;
            }
        }
        else
        {
            debug_logf(host_cache_trace, nullptr,  "%s not found in host cache\n", ips);
            return 0;
        }
        debug_logf(host_cache_trace, nullptr,  "host_cache_delete_network_proto done\n");
    }
    return 0;
}

static int host_cache_delete_transport_proto(lua_State* L)
{
    HostCacheModule* mod = (HostCacheModule*) ModuleManager::get_module(HOST_CACHE_NAME);
    if ( mod )
    {
        const char* ips = luaL_optstring(L, 1, nullptr);
        int proto = luaL_optint(L, 2, -1);
        if ( ips == nullptr || proto == -1 )
        {
            debug_logf(host_cache_trace, nullptr,  "Usage: host_cache.delete_transport_proto(ip, proto)\n");
            return 0;
        }

        SfIp ip;
        if ( ip.set(ips) != SFIP_SUCCESS )
        {
            debug_logf(host_cache_trace, nullptr,  "Bad ip %s\n", ips);
            return 0;
        }

        auto ht = host_cache.find(ip);
        if ( ht )
        {
            if ( !ht->set_xproto_visibility(proto, false) )
            {
                debug_logf(host_cache_trace, nullptr,  "%d not found for host %s\n", proto, ips);
                return 0;
            }
        }
        else
        {
            debug_logf(host_cache_trace, nullptr,  "%s not found in host cache\n", ips);
            return 0;
        }
        debug_logf(host_cache_trace, nullptr,  "host_cache_delete_transport_proto done\n");
    }
    return 0;
}

static int host_cache_delete_service(lua_State* L)
{
    HostCacheModule* mod = (HostCacheModule*) ModuleManager::get_module(HOST_CACHE_NAME);
    if ( mod )
    {
        const char* ips = luaL_optstring(L, 1, nullptr);
        int port = luaL_optint(L, 2, -1);
        int proto = luaL_optint(L, 3, -1);

        if ( ips == nullptr || port == -1 || proto == -1 )
        {
            debug_logf(host_cache_trace, nullptr,  "Usage: host_cache.delete_service(ip, port, proto).\n");
            return 0;
        }

        if ( !(0 <= proto and proto < 256) )
        {
            debug_logf(host_cache_trace, nullptr,  "Protocol must be between 0 and 255.\n");
            return 0;
        }

        SfIp ip;
        if ( ip.set(ips) != SFIP_SUCCESS )
        {
            debug_logf(host_cache_trace, nullptr,  "Bad ip %s\n", ips);
            return 0;
        }

        auto ht = host_cache.find(ip);
        if ( ht )
        {
            if ( !ht->set_service_visibility(port, (IpProtocol)proto, false) )
            {
                debug_logf(host_cache_trace, nullptr,  "%d or %d not found for host %s\n", port, proto, ips);
                return 0;
            }
        }
        else
        {
            debug_logf(host_cache_trace, nullptr,  "%s not found in host cache\n", ips);
            return 0;
        }
        debug_logf(host_cache_trace, nullptr,  "host_cache_delete_service done\n");
    }
    return 0;
}

static int host_cache_delete_client(lua_State* L)
{
    HostCacheModule* mod = (HostCacheModule*) ModuleManager::get_module(HOST_CACHE_NAME);
    if ( mod )
    {
        const char* ips = luaL_optstring(L, 1, nullptr);
        int id = luaL_optint(L, 2, -1);
        int service = luaL_optint(L, 3, -1);
        const char* version = luaL_optstring(L, 4, nullptr);

        if (ips == nullptr || id == -1 || service == -1)
        {
            debug_logf(host_cache_trace, nullptr,  "Usage: host_cache.delete_client(ip, id, service, <version>).\n");
            return 0;
        }

        SfIp ip;
        if (ip.set(ips) != SFIP_SUCCESS)
        {
            debug_logf(host_cache_trace, nullptr,  "Bad ip %s\n", ips);
            return 0;
        }

        auto ht = host_cache.find(ip);
        if (ht)
        {
            HostClient hc(id, version, service);
            if ( !ht->set_client_visibility(hc, false) )
            {
                debug_logf(host_cache_trace, nullptr,  "Client not found for host %s\n", ips);
                return 0;
            }
        }
        else
        {
            debug_logf(host_cache_trace, nullptr,  "%s not found in host cache\n", ips);
            return 0;
        }
        debug_logf(host_cache_trace, nullptr,  "host_cache_delete_client done\n");
    }
    return 0;
}

static const Parameter host_cache_cmd_params[] =
{
    { "file_name", Parameter::PT_STRING, nullptr, nullptr, "file name to dump host cache" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter host_cache_stats_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter host_cache_delete_host_params[] =
{
    { "host_ip", Parameter::PT_STRING, nullptr, nullptr, "ip address to delete" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter host_cache_delete_network_proto_params[] =
{
    { "host_ip", Parameter::PT_STRING, nullptr, nullptr, "ip of host" },
    { "proto", Parameter::PT_INT, nullptr, nullptr, "network protocol to delete" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter host_cache_delete_transport_proto_params[] =
{
    { "host_ip", Parameter::PT_STRING, nullptr, nullptr, "ip of host" },
    { "proto", Parameter::PT_INT, nullptr, nullptr, "transport protocol to delete" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter host_cache_delete_service_params[] =
{
    { "host_ip", Parameter::PT_STRING, nullptr, nullptr, "ip of host" },
    { "port", Parameter::PT_INT, nullptr, nullptr, "service port" },
    { "proto", Parameter::PT_INT, nullptr, nullptr, "service protocol" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter host_cache_delete_client_params[] =
{
    { "host_ip", Parameter::PT_STRING, nullptr, nullptr, "ip of host" },
    { "id", Parameter::PT_INT, nullptr, nullptr, "application id" },
    { "service", Parameter::PT_INT, nullptr, nullptr, "service id" },
    { "version", Parameter::PT_STRING, nullptr, nullptr, "client version" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Command host_cache_cmds[] =
{
    { "dump", host_cache_dump, host_cache_cmd_params, "dump host cache"},
    { "delete_host", host_cache_delete_host, host_cache_delete_host_params, "delete host from host cache"},
    { "delete_network_proto", host_cache_delete_network_proto,
      host_cache_delete_network_proto_params, "delete network protocol from host"},
    { "delete_transport_proto", host_cache_delete_transport_proto,
      host_cache_delete_transport_proto_params, "delete transport protocol from host"},
    { "delete_service", host_cache_delete_service,
      host_cache_delete_service_params, "delete service from host"},
    { "delete_client", host_cache_delete_client,
      host_cache_delete_client_params, "delete client from host"},
    { "get_stats", host_cache_get_stats, host_cache_stats_params, "get current host cache usage and pegs"},
    { nullptr, nullptr, nullptr, nullptr }
};

const Command* HostCacheModule::get_commands() const
{
    return host_cache_cmds;
}

//-------------------------------------------------------------------------
// options
//-------------------------------------------------------------------------

static const Parameter host_cache_params[] =
{
    { "dump_file", Parameter::PT_STRING, nullptr, nullptr,
      "file name to dump host cache on shutdown; won't dump by default" },

    { "memcap", Parameter::PT_INT, "512:maxSZ", "8388608",
      "maximum host cache size in bytes" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

bool HostCacheModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("dump_file") )
    {
        dump_file = v.get_string();
    }
    else if ( v.is("memcap") )
        memcap = v.get_size();

    return true;
}

bool HostCacheModule::end(const char* fqn, int, SnortConfig* sc)
{
    if ( memcap and !strcmp(fqn, HOST_CACHE_NAME) )
    {
        if ( Snort::is_reloading() )
            sc->register_reload_handler(new HostCacheReloadTuner(memcap));
        else
        {   
            host_cache.set_max_size(memcap);
            ControlConn::log_command("host_cache.delete_host",false);
        }
    }

    return true;
}

//-------------------------------------------------------------------------
// methods
//-------------------------------------------------------------------------

HostCacheModule::HostCacheModule() :
    Module(HOST_CACHE_NAME, HOST_CACHE_HELP, host_cache_params) { }

HostCacheModule::~HostCacheModule()
{
    if ( !dump_file.empty() )
        log_host_cache(dump_file.c_str());
}

void HostCacheModule::log_host_cache(const char* file_name, bool verbose)
{
    if ( !file_name )
    {
        if ( verbose )
            LogMessage("File name is needed!\n");
        return;
    }

    // Prevent damaging any existing file, intentionally or not
    struct stat file_stat;
    if ( stat(file_name, &file_stat) == 0 )
    {
        if ( verbose )
            LogMessage("File %s already exists!\n", file_name);
        return;
    }

    ofstream out_stream(file_name);
    if ( !out_stream )
    {
        if ( verbose )
            LogMessage("Couldn't open %s to write!\n", file_name);
        return;
    }

    string str;
    SfIpString ip_str;
    const auto&& lru_data = host_cache.get_all_data();
    // The current size may not exactly correspond to the number of trackers seen here
    // as packet threads may continue to update cache, except when dumping upon exit or pause
    out_stream << "Current host cache size: " << host_cache.mem_size() << " bytes, "
        << lru_data.size() << " trackers" << endl << endl;
    for ( const auto& elem : lru_data )
    {
        if ( elem.second->is_visible() == true )
        {
            str = "IP: ";
            str += elem.first.ntop(ip_str);
            elem.second->stringify(str);
            out_stream << str << endl << endl;
        }
    }
    out_stream.close();

    if ( verbose )
        LogMessage("Dumped host cache to %s\n", file_name);
}


string HostCacheModule::get_host_cache_stats()
{
    string str;

    const auto&& lru_data = host_cache.get_all_data();
    str = "Current host cache size: " + to_string(host_cache.mem_size()) + " bytes, "
        + to_string(lru_data.size()) + " trackers, memcap: " + to_string(host_cache.max_size)
        + " bytes\n";

    host_cache.lock();

    host_cache.stats.bytes_in_use = host_cache.current_size;
    host_cache.stats.items_in_use = host_cache.list.size();

    PegCount* counts = (PegCount*) host_cache.get_counts();
    const PegInfo* pegs = host_cache.get_pegs();

    for ( int i = 0; pegs[i].type != CountType::END; i++ )
    {
        if ( counts[i] )
        {
            str += pegs[i].name;
            str += ": " + to_string(counts[i]) + "\n" ;
        }

    }

    host_cache.unlock();

    return str;
}

const PegInfo* HostCacheModule::get_pegs() const
{ return host_cache.get_pegs(); }

PegCount* HostCacheModule::get_counts() const
{ return (PegCount*)host_cache.get_counts(); }

void HostCacheModule::sum_stats(bool dump_stats)
{
    host_cache.lock();
    // These could be set in prep_counts but we set them here
    // to save an extra cache lock.
    host_cache.stats.bytes_in_use = host_cache.current_size;
    host_cache.stats.items_in_use = host_cache.list.size();

    Module::sum_stats(dump_stats);
    host_cache.unlock();
}

void HostCacheModule::set_trace(const Trace* trace) const
{ host_cache_trace = trace; }

const TraceOption* HostCacheModule::get_trace_options() const
{
#ifndef DEBUG_MSGS
    return nullptr;
#else
    static const TraceOption host_cache_trace_options(nullptr, 0, nullptr);

    return &host_cache_trace_options;
#endif
}
