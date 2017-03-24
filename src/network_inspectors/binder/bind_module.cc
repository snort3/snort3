//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

using namespace std;

#define FILE_KEY ".file"

THREAD_LOCAL BindStats bstats;

static const PegInfo bind_pegs[] =
{
    { "packets", "initial bindings" },
    { "resets", "reset bindings" },
    { "blocks", "block bindings" },
    { "allows", "allow bindings" },
    { "inspects", "inspect bindings" },
    { nullptr, nullptr }
};

//-------------------------------------------------------------------------
// binder module
//-------------------------------------------------------------------------

static const Parameter binder_when_params[] =
{
    // FIXIT-L when.policy_id should be an arbitrary string auto converted
    // into index for binder matching and lookups
    { "policy_id", Parameter::PT_INT, "0:", "0",
      "unique ID for selection of this config by external logic" },

    { "ifaces", Parameter::PT_BIT_LIST, "255", nullptr,
      "list of interface indices" },

    { "vlans", Parameter::PT_BIT_LIST, "4095", nullptr,
      "list of VLAN IDs" },

    { "nets", Parameter::PT_ADDR_LIST, nullptr, nullptr,
      "list of networks" },

    { "proto", Parameter::PT_ENUM, "any | ip | icmp | tcp | udp | user | file", nullptr,
      "protocol" },

    { "ports", Parameter::PT_BIT_LIST, "65535", nullptr,
      "list of ports" },

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
        work->when.nets = sfip_var_from_string(v.get_string());

    else if ( v.is("policy_id") )
        work->when.id = v.get_long();

    else if ( v.is("proto") )
    {
        const PktType mask[] =
        {
            PktType::ANY, PktType::IP, PktType::ICMP, PktType::TCP, PktType::UDP,
            PktType::PDU, PktType::FILE
        };
        work->when.protos = (unsigned)mask[v.get_long()];
    }
    else if ( v.is("ports") )
        v.get_bits(work->when.ports);

    else if ( v.is("role") )
        work->when.role = (BindWhen::Role)v.get_long();

    else if ( v.is("vlans") )
        v.get_bits(work->when.vlans);

    // use
    else if ( v.is("action") )
        work->use.action = (BindUse::Action)(v.get_long());

    else if ( v.is("file") )
    {
        if ( !work->use.name.empty() || !work->use.type.empty() )
            ParseError("you can't set binder.use.file with type or name");

        work->use.name = v.get_string();
        work->use.type = FILE_KEY;
    }
    else if ( v.is("name") )
    {
        if ( !work->use.name.empty() )
            ParseError("you can't set binder.use.file with type or name");

        work->use.name = v.get_string();
    }
    else if ( v.is("type") )
    {
        if ( !work->use.type.empty() )
            ParseError("you can't set binder.use.file with type or name");

        work->use.type = v.get_string();
    }
    else
        return false;

    return true;
}

bool BinderModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, BIND_NAME) )
        work = new Binding;

    return true;
}

bool BinderModule::end(const char* fqn, int idx, SnortConfig* sc)
{
    if ( idx && !strcmp(fqn, BIND_NAME) )
    {
        if ( !work )
        {
            ParseError("invalid %s[%d]", fqn, idx);
            return true;
        }

        if ( work->use.type == FILE_KEY )
        {
            Shell* sh = new Shell(work->use.name.c_str());
            work->use.index = sc->policy_map->add_shell(sh) + 1;
        }
        if ( !work->use.name.size() )
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

