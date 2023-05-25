//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// network_module.cc author Ron Dempster <rdempste@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_module.h"

#include <lua.hpp>

#include "main/policy.h"
#include "main/shell.h"
#include "main/snort_config.h"
#include "parser/config_file.h"

using namespace snort;

static const Parameter network_params[] =
{
    { "checksum_drop", Parameter::PT_MULTI,
      "all | ip | noip | tcp | notcp | udp | noudp | icmp | noicmp | none", "none",
      "drop if checksum is bad" },

    { "checksum_eval", Parameter::PT_MULTI,
      "all | ip | noip | tcp | notcp | udp | noudp | icmp | noicmp | none", "all",
      "checksums to verify" },

    { "id", Parameter::PT_INT, "0:max32", "0",
      "correlate unified2 events with configuration" },

    { "min_ttl", Parameter::PT_INT, "1:255", "1",
      "alert / normalize packets with lower TTL / hop limit "
      "(you must enable rules and / or normalization also)" },

    { "new_ttl", Parameter::PT_INT, "1:255", "1",
      "use this value for responses and when normalizing" },

    { "layers", Parameter::PT_INT, "3:255", "40",
      "the maximum number of protocols that Snort can correctly decode" },

    { "max_ip6_extensions", Parameter::PT_INT, "0:255", "0",
      "the maximum number of IP6 options Snort will process for a given IPv6 layer "
      "before raising 116:456 (0 = unlimited)" },

    { "max_ip_layers", Parameter::PT_INT, "0:255", "0",
      "the maximum number of IP layers Snort will process for a given packet "
      "before raising 116:293 (0 = unlimited)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define network_help  "configure basic network parameters"

static int network_set_policy(lua_State* L)
{
    int user_id = luaL_optint(L, 1, 0);
    Shell::set_network_policy_user_id(L, user_id);
    return 0;
}

const Parameter network_set_policy_params[] =
{
    {"id", Parameter::PT_INT, "0:max32", 0, "user network policy id"},
    {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}
};

const Command network_cmds[] =
{
    {"set_policy", network_set_policy, network_set_policy_params,
        "set the network policy for commands given the user policy id"},
    {nullptr, nullptr, nullptr, nullptr}
};

NetworkModule::NetworkModule() : snort::Module("network", network_help, network_params)
{ }

const Command* NetworkModule::get_commands() const
{ return network_cmds; }

bool NetworkModule::set(const char*, Value& v, SnortConfig* sc)
{
    NetworkPolicy* p = get_network_policy();

    if ( v.is("checksum_drop") )
        ConfigChecksumDrop(v.get_string());

    else if ( v.is("checksum_eval") )
        ConfigChecksumMode(v.get_string());

    else if ( v.is("id") )
        p->user_policy_id = v.get_uint32();

    else if ( v.is("min_ttl") )
        p->min_ttl = v.get_uint8();

    else if ( v.is("new_ttl") )
        p->new_ttl = v.get_uint8();

    else if (v.is("layers"))
        sc->num_layers = v.get_uint8();

    else if (v.is("max_ip6_extensions"))
        sc->max_ip6_extensions = v.get_uint8();

    else if (v.is("max_ip_layers"))
        sc->max_ip_layers = v.get_uint8();

    return true;
}

