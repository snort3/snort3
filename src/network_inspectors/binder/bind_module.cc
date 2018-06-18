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

// bind_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bind_module.h"

#include "log/messages.h"
#include "main/shell.h"
#include "main/snort_config.h"
#include "parser/parse_ip.h"
#include "protocols/packet.h"

using namespace snort;
using namespace std;

#define FILE_KEY ".file"
#define INSPECTION_KEY ".inspection"
#define IPS_KEY ".ips"
#define NETWORK_KEY ".network"

THREAD_LOCAL BindStats bstats;

static const PegInfo bind_pegs[] =
{
    { CountType::SUM, "packets", "initial bindings" },
    { CountType::SUM, "resets", "reset bindings" },
    { CountType::SUM, "blocks", "block bindings" },
    { CountType::SUM, "allows", "allow bindings" },
    { CountType::SUM, "inspects", "inspect bindings" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// binder module
//-------------------------------------------------------------------------

#define INT32_MAX_STR "2147483647"
static const Parameter binder_when_params[] =
{
    // FIXIT-L when.policy_id should be an arbitrary string auto converted
    // into index for binder matching and lookups

    { "ips_policy_id", Parameter::PT_INT, "0:", "0",
      "unique ID for selection of this config by external logic" },

    { "ifaces", Parameter::PT_BIT_LIST, "255", nullptr,
      "list of interface indices" },

    { "vlans", Parameter::PT_BIT_LIST, "4095", nullptr,
      "list of VLAN IDs" },

    { "nets", Parameter::PT_ADDR_LIST, nullptr, nullptr,
      "list of networks" },

    { "src_nets", Parameter::PT_ADDR_LIST, nullptr, nullptr,
      "list of source networks" },

    { "dst_nets", Parameter::PT_ADDR_LIST, nullptr, nullptr,
      "list of destination networks" },

    { "proto", Parameter::PT_ENUM, "any | ip | icmp | tcp | udp | user | file", nullptr,
      "protocol" },

    { "ports", Parameter::PT_BIT_LIST, "65535", nullptr,
      "list of ports" },

    { "src_ports", Parameter::PT_BIT_LIST, "65535", nullptr,
      "list of source ports" },

    { "dst_ports", Parameter::PT_BIT_LIST, "65535", nullptr,
      "list of destination ports" },

    { "src_zone", Parameter::PT_INT, "0:" INT32_MAX_STR, nullptr,
      "source zone" },

    { "dst_zone", Parameter::PT_INT, "0:" INT32_MAX_STR, nullptr,
      "destination zone" },

    { "role", Parameter::PT_ENUM, "client | server | any", "any",
      "use the given configuration on one or any end of a session" },

    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "override default configuration" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter binder_use_params[] =
{
    { "action", Parameter::PT_ENUM, "reset | block | allow | inspect", "inspect",
      "what to do with matching traffic" },

    { "file", Parameter::PT_STRING, nullptr, nullptr,
      "use configuration in given file" },

    { "inspection_policy", Parameter::PT_STRING, nullptr, nullptr,
      "use inspection policy from given file" },

    { "ips_policy", Parameter::PT_STRING, nullptr, nullptr,
      "use ips policy from given file" },

    { "network_policy", Parameter::PT_STRING, nullptr, nullptr,
      "use network policy from given file" },

    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "override automatic service identification" },

    { "type", Parameter::PT_STRING, nullptr, nullptr,
      "select module for binding" },

    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "symbol name (defaults to type)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "when", Parameter::PT_TABLE, binder_when_params, nullptr,
      "match criteria" },

    { "use", Parameter::PT_TABLE, binder_use_params, nullptr,
      "target configuration" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

BinderModule::BinderModule() : Module(BIND_NAME, BIND_HELP, s_params, true)
{ work = nullptr; }

BinderModule::~BinderModule()
{
    if ( work )
        delete work;
}

ProfileStats* BinderModule::get_profile() const
{ return &bindPerfStats; }

void BinderModule::add_file(const char* name, const char* type)
{
    work->use.name = name;
    work->use.type = type;
    use_name_count++;
    use_type_count++;
}

static void set_ip_var(sfip_var_t*& var, const char* val)
{
    if ( var )
        sfvar_free(var);
    var = sfip_var_from_string(val, "binder");
}

bool BinderModule::set(const char* fqn, Value& v, SnortConfig*)
{
    if ( !work )
        return false;

    // both
    else if ( !strcmp(fqn, "binder.when.service") )
        work->when.svc = v.get_string();

    else if ( !strcmp(fqn, "binder.use.service") )
        work->use.svc = v.get_string();

    // when
    else if ( v.is("ifaces") )
        v.get_bits(work->when.ifaces);

    else if ( v.is("nets") )
    {
        set_ip_var(work->when.src_nets, v.get_string());
        unsplit_nets = true;
    }
    else if ( v.is("src_nets") )
    {
        set_ip_var(work->when.src_nets, v.get_string());
        work->when.split_nets = true;
    }
    else if ( v.is("dst_nets") )
    {
        set_ip_var(work->when.dst_nets, v.get_string());
        work->when.split_nets = true;
    }
    else if ( v.is("ips_policy_id") )
        work->when.ips_id = v.get_long();

    else if ( v.is("proto") )
    {
        const unsigned mask[] =
        {
            PROTO_BIT__ANY_TYPE, PROTO_BIT__IP, PROTO_BIT__ICMP,
            PROTO_BIT__TCP, PROTO_BIT__UDP, PROTO_BIT__PDU, PROTO_BIT__FILE
        };
        work->when.protos = mask[v.get_long()];
    }
    else if ( v.is("ports") )
    {
        v.get_bits(work->when.src_ports);
        unsplit_ports = true;
    }
    else if ( v.is("src_ports") )
    {
        v.get_bits(work->when.src_ports);
        work->when.split_ports = true;
    }
    else if ( v.is("dst_ports") )
    {
        v.get_bits(work->when.dst_ports);
        work->when.split_ports = true;
    }

    else if ( v.is("src_zone") )
        work->when.src_zone = v.get_long();

    else if ( v.is("dst_zone") )
        work->when.dst_zone = v.get_long();

    else if ( v.is("role") )
        work->when.role = (BindWhen::Role)v.get_long();

    else if ( v.is("vlans") )
        v.get_bits(work->when.vlans);

    // use
    else if ( v.is("action") )
        work->use.action = (BindUse::Action)(v.get_long());

    else if ( v.is("file") )
        add_file(v.get_string(), FILE_KEY);

    else if ( v.is("inspection_policy") )
        add_file(v.get_string(), INSPECTION_KEY);

    else if ( v.is("ips_policy") )
        add_file(v.get_string(), IPS_KEY);

    else if ( v.is("network_policy") )
        add_file(v.get_string(), NETWORK_KEY);

    else if ( v.is("name") )
    {
        work->use.name = v.get_string();
        use_name_count++;
    }
    else if ( v.is("type") )
    {
        work->use.type = v.get_string();
        use_type_count++;
    }
    else
        return false;

    return true;
}

bool BinderModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, BIND_NAME) )
    {
        work = new Binding;
        unsplit_nets = false;
        unsplit_ports = false;
        use_name_count = 0;
        use_type_count = 0;
    }

    return true;
}

static void file_name_type_error()
{ ParseError("you can't set binder.use file, detection_policy, or inspection_policy with type or name"); }

static void split_nets_warning()
{ ParseWarning(WARN_CONF, "src_nets and dst_nets override nets"); }

static void split_ports_warning()
{ ParseWarning(WARN_CONF, "src_ports and dst_ports override ports"); }

bool BinderModule::end(const char* fqn, int idx, SnortConfig* sc)
{
    if ( idx && !strcmp(fqn, BIND_NAME) )
    {
        if ( !work )
        {
            ParseError("invalid %s[%d]", fqn, idx);
            return true;
        }

        if ( unsplit_nets && work->when.split_nets )
            split_nets_warning();

        if ( unsplit_ports && work->when.split_ports )
            split_ports_warning();

        if ( use_type_count > 1 || use_name_count > 1 )
            file_name_type_error();

        if ( work->use.type == FILE_KEY )
        {
            Shell* sh = new Shell(work->use.name.c_str());
            auto policies = sc->policy_map->add_shell(sh);
            work->use.inspection_index = policies->inspection->policy_id + 1;
            work->use.ips_index = policies->ips->policy_id + 1;
            work->use.network_index = policies->network->policy_id + 1;
        }
        else if ( work->use.type == INSPECTION_KEY )
        {
            Shell* sh = new Shell(work->use.name.c_str());
            work->use.inspection_index = sc->policy_map->add_inspection_shell(sh) + 1;
        }
        else if ( work->use.type == IPS_KEY )
        {
            Shell* sh = new Shell(work->use.name.c_str());
            work->use.ips_index = sc->policy_map->add_ips_shell(sh) + 1;
        }
        else if ( work->use.type == NETWORK_KEY )
        {
            Shell* sh = new Shell(work->use.name.c_str());
            work->use.network_index = sc->policy_map->add_network_shell(sh) + 1;
        }

        if ( work->use.name.empty() )
            work->use.name = work->use.type;

        bindings.push_back(work);
        work = nullptr;
    }
    return true;
}

void BinderModule::add(const char* svc, const char* type)
{
    Binding* b = new Binding;
    b->when.svc = svc;
    b->use.type = type;
    b->use.name = type;
    bindings.push_back(b);
}

void BinderModule::add(unsigned proto, const char* type)
{
    Binding* b = new Binding;
    b->when.protos = proto;
    b->use.type = type;
    b->use.name = type;
    bindings.push_back(b);
}

vector<Binding*>& BinderModule::get_data()
{
    return bindings;  // move semantics
}

const PegInfo* BinderModule::get_pegs() const
{ return bind_pegs; }

PegCount* BinderModule::get_counts() const
{ return (PegCount*)&bstats; }

