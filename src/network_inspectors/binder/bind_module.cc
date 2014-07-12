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

// bind_module.cc author Russ Combs <rucombs@cisco.com>

#include "bind_module.h"

#include <assert.h>
#include <string.h>

#include <string>
using namespace std;

#include "binder.h"

//-------------------------------------------------------------------------
// binder module
//-------------------------------------------------------------------------

static const Parameter binder_when_params[] =
{
    { "policy_id", Parameter::PT_STRING, nullptr, nullptr,
      "unique ID for selection of this config by external logic" },

    { "vlans", Parameter::PT_BIT_LIST, "4095", nullptr,
      "list of VLAN IDs" },

    { "nets", Parameter::PT_ADDR_LIST, nullptr, nullptr,
      "list of networks" },

    { "proto", Parameter::PT_ENUM, "any | ip | icmp | tcp | udp", nullptr,
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
    { "action", Parameter::PT_ENUM, "inspect | allow | block", "inspect",
      "what to do with matching traffic" },

    { "file", Parameter::PT_STRING, nullptr, nullptr,
      "use configuration in given file" },

    { "policy_id", Parameter::PT_STRING, nullptr, nullptr,
      "use configuration in given policy" },

    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "override automatic service identification" },

    { "type", Parameter::PT_STRING, nullptr, nullptr,
      "select module for binding" },

    { "name", Parameter::PT_STRING, nullptr, "defaults to type",
      "symbol name" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter binder_params[] =
{
    { "when", Parameter::PT_TABLE, binder_when_params, nullptr,
      "match criteria" },

    { "use", Parameter::PT_TABLE, binder_use_params, nullptr,
      "target configuration" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

BinderModule::BinderModule() : Module("binder", binder_params)
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
    // both
    if ( !strcmp(fqn, "binder.when.policy_id") )
        work->when_id = v.get_string();

    else if ( !strcmp(fqn, "binder.use.policy_id") )
        work->use_id = v.get_string();

    else if ( !strcmp(fqn, "binder.when.service") )
        work->when_svc = v.get_string();

    else if ( !strcmp(fqn, "binder.use.service") )
        work->use_svc = v.get_string();

    // when
    else if ( v.is("nets") )
        work->nets = v.get_string();

    else if ( v.is("proto") )
        work->proto = (BindProto)v.get_long();

    else if ( v.is("ports") )
        v.get_bits(work->ports);

    else if ( v.is("role") )
        work->role = (BindRole)v.get_long();

    else if ( v.is("vlans") )
        v.get_bits(work->vlans);

    // use
    else if ( v.is("action") )
        work->action = (BindAction)v.get_long();

    else if ( v.is("file") )
        work->file = v.get_string();

    else if ( v.is("name") )
        work->name = v.get_string();

    else if ( v.is("type") )
        work->type = v.get_string();

    else
        return false;

    return true;
}

bool BinderModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "binder") )
        work = new Binding;

    return true;
}

bool BinderModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "binder") )
    {
        bindings.push_back(work);
        work = nullptr;
    }
    return true;
}

vector<Binding*> BinderModule::get_data()
{
    return bindings;  // move semantics
}

