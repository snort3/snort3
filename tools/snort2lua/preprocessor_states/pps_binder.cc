/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// pps_binder.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "preprocessor_states/pps_binder.h"
#include "data/dt_data.h"

Binder::~Binder()
{
    if (!added_to_bindings)
        add_to_configuration();

}

void Binder::add_to_configuration()
{
    added_to_bindings = true;
    ld->open_top_level_table("binder");
    ld->open_table();

    ld->open_table("when");

    if (!when_policy_id.empty())
        ld->add_option_to_table("policy_id", when_policy_id);

    if (!when_service.empty())
        ld->add_option_to_table("service", when_service);

    if (!when_proto.empty())
        ld->add_option_to_table("proto", when_proto);

    for (auto p : ports)
        ld->add_list_to_table("ports", p);

    for (auto s : vlans)
        ld->add_list_to_table("vlans", s);

    for (auto n : nets)
        ld->add_list_to_table("nets", n);

    ld->close_table(); // "when"


    ld->open_table("use");

    if (!use_policy_id.empty())
        ld->add_option_to_table("policy_id", use_policy_id);

    if (!use_action.empty())
        ld->add_option_to_table("action", use_action);

    if (!use_file.empty())
        ld->add_option_to_table("file", use_file);

    if (!use_service.empty())
        ld->add_option_to_table("service", use_service);

    if (!use_type.empty())
        ld->add_option_to_table("type", use_type);

    if (!use_name.empty())
        ld->add_option_to_table("name", use_name);

    ld->close_table();  // "use"

    ld->close_table();  // anonymous table
    ld->close_table();  // "binder"
}


void Binder::set_when_policy_id(std::string id)
{  when_policy_id = std::string(id);  }

void Binder::set_when_service(std::string service)
{  when_service = std::string(service);  }

void Binder::set_when_role(std::string role)
{  when_role = std::string(role);  }

void Binder::set_when_proto(std::string proto)
{  when_proto = std::string(proto);  }

void Binder::add_when_vlan(std::string vlan)
{  vlans.push_back(std::string(vlan));  }

void Binder::add_when_net(std::string net)
{  nets.push_back(std::string(net));  }

void Binder::add_when_port(uint16_t port)
{  ports.push_back(std::to_string(port));  }

void Binder::add_when_port(std::string port)
{  ports.push_back(std::string(port));  }





void Binder::set_use_type(std::string module_name)
{  use_type = std::string(module_name);  }

void Binder::set_use_name(std::string struct_name)
{  use_name = std::string(struct_name);  }

void Binder::set_use_file(std::string file_name)
{  use_file = std::string(file_name);  }

void Binder::set_use_service(std::string service_name)
{  use_service = std::string(service_name);  }

void Binder::set_use_action(std::string action)
{  use_action = std::string(action);  }

void Binder::set_use_policy_id(std::string id)
{  use_policy_id = std::string(id);  }

