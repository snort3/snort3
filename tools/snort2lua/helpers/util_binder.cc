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
// pps_binder.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "helpers/util_binder.h"
#include "data/dt_table_api.h"

Binder::Binder(TableApi& t) :   table_api(t),
    printed(false),
    when_policy_id(-1)
{ }

Binder::~Binder()
{
    if (!printed)
        add_to_configuration();
}

void Binder::add_to_configuration()
{
    printed = true;
    table_api.open_top_level_table("binder");
    table_api.open_table();

    table_api.open_table("when");

    if (when_policy_id >= 0)
        table_api.add_option("policy_id", when_policy_id);

    if (!when_service.empty())
        table_api.add_option("service", when_service);

    if (!when_proto.empty())
        table_api.add_option("proto", when_proto);

    if (!when_role.empty())
        table_api.add_option("role", when_role);

    for (auto p : ports)
        table_api.add_list("ports", p);

    for (auto s : vlans)
        table_api.add_list("vlans", s);

    for (auto n : nets)
        table_api.add_list("nets", n);

    table_api.close_table(); // "when"

    table_api.open_table("use");

    if (!use_policy_id.empty())
        table_api.add_option("policy_id", use_policy_id);

    if (!use_action.empty())
        table_api.add_option("action", use_action);

    if (!use_file.empty())
        table_api.add_option("file", use_file);

    if (!use_service.empty())
        table_api.add_option("service", use_service);

    if (!use_type.empty())
        table_api.add_option("type", use_type);

    if (!use_name.empty())
        table_api.add_option("name", use_name);

    table_api.close_table();  // "use"

    table_api.close_table();  // anonymous table
    table_api.close_table();  // "binder"
}

void Binder::set_when_policy_id(int id)
{ when_policy_id = id; }

void Binder::set_when_service(std::string service)
{ when_service = std::string(service); }

void Binder::set_when_role(std::string role)
{ when_role = std::string(role); }

void Binder::set_when_proto(std::string proto)
{ when_proto = std::string(proto); }

void Binder::add_when_vlan(std::string vlan)
{ vlans.push_back(std::string(vlan)); }

void Binder::add_when_net(std::string net)
{ nets.push_back(std::string(net)); }

void Binder::add_when_port(std::string port)
{ ports.push_back(std::string(port)); }

void Binder::clear_ports()
{ ports.clear(); }

void Binder::set_use_type(std::string module_name)
{ use_type = std::string(module_name); }

void Binder::set_use_name(std::string struct_name)
{ use_name = std::string(struct_name); }

void Binder::set_use_file(std::string file_name)
{ use_file = std::string(file_name); }

void Binder::set_use_service(std::string service_name)
{ use_service = std::string(service_name); }

void Binder::set_use_action(std::string action)
{ use_action = std::string(action); }

void Binder::set_use_policy_id(std::string id)
{ use_policy_id = std::string(id); }

