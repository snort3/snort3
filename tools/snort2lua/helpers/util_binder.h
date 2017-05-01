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
// util_binder.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef HELPERS_PPS_BINDER_H
#define HELPERS_PPS_BINDER_H

#include <string>
#include <vector>

class TableApi;

// The Binders destructor will add the Objects configuration to the
//   table_api.
class Binder
{
public:
    Binder(TableApi&);
    ~Binder();

    //  By calling add_to_configuration(), you are adding this Binder Object
    //  "as is" to the table_api.  Additionally, after calling
    //  add_to_configuration(), the destructor will NOT add the object to the
    //  table_api unless 'print_binding(true)' is called.
    void add_to_configuration();
    void print_binding(bool should_print)
    { printed = !should_print; }

    void set_when_policy_id(int id);
    void set_when_service(std::string service);
    void set_when_role(std::string role);
    void set_when_proto(std::string proto);
    void add_when_vlan(std::string vlan);
    void add_when_net(std::string net);
    void add_when_port(std::string port);
    void clear_ports();

    void set_use_type(std::string module_name);
    void set_use_name(std::string struct_name);
    void set_use_file(std::string file_name);
    void set_use_service(std::string service_name);
    void set_use_action(std::string action);
    void set_use_policy_id(std::string id);

private:
    TableApi& table_api;
    bool printed; // ensures that the binding is added once,
                  // by either the destructor or user

    int when_policy_id;
    std::string when_service;
    std::string when_role;
    std::string when_proto;
    std::vector<std::string> vlans;
    std::vector<std::string> nets;
    std::vector<std::string> ports;

    std::string use_policy_id;
    std::string use_type;
    std::string use_name;
    std::string use_file;
    std::string use_service;
    std::string use_action;
};

typedef void (Binder::* binder_func)(std::string);

#endif

