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
// pps_binder.h author Josh Rosenbaum <jrosenba@cisco.com>

#include <cctype>
#include <string>
#include <vector>

#ifndef PPS_BINDER_H
#define PPS_BINDER_H

class LuaData;

// If the user never adds add_to_configuration,
//  the destructor will call the method
class Binder
{
public:
    Binder(LuaData* ld) :   ld(ld), printed(false){};
    ~Binder();

    void add_to_configuration();
    void print_binding(bool should_print)
    { printed = !should_print; }

    void set_when_policy_id(std::string id);
    void set_when_service(std::string service);
    void set_when_role(std::string role);
    void set_when_proto(std::string proto);
    void add_when_vlan(std::string vlan);
    void add_when_net(std::string net);
    void add_when_port(std::string port);


    void set_use_type(std::string module_name);
    void set_use_name(std::string struct_name);
    void set_use_file(std::string file_name);
    void set_use_service(std::string service_name);
    void set_use_action(std::string action);
    void set_use_policy_id(std::string id);



private:
    LuaData* ld;
    bool printed; // ensures that the binding is added once,
                  // by either the destructor or user

    std::string when_policy_id;
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


#endif
