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

#include <algorithm>

#include "helpers/util_binder.h"
#include "data/dt_table_api.h"

using namespace std;

Binder::Binder(TableApi& t) :   table_api(t),
    printed(false),
    when_policy_id(-1)
{ }

Binder::~Binder()
{
    if ( !printed )
        add_to_configuration();
}

void Binder::add_to_configuration()
{
    printed = true;
    table_api.open_top_level_table("binder");
    table_api.open_table(true);

    table_api.open_table("when", true);

    if ( has_policy_id() )
        table_api.add_option("policy_id", when_policy_id);

    for ( auto s : vlans )
        table_api.add_list("vlans", s);

    if ( has_service() )
        table_api.add_option("service", when_service);

    for ( auto n : nets )
        table_api.add_list("nets", n);

    for ( auto p : ports )
        table_api.add_list("ports", p);

    if ( has_proto() )
        table_api.add_option("proto", when_proto);

    if ( has_role() )
        table_api.add_option("role", when_role);

    table_api.close_table(); // "when"

    table_api.open_table("use", true);

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

/*  This operator is provided for STL compatible sorting. A Binder is considered
    less than another Binder if it should be printed first in the binder table,
    thus giving it higher priority. This is determined by checking for presence
    of when options and assigning them priority. If multiple options exist,
    the highest-priority non-match is used to determine order.
    
    Example of ordering:
    policy_id vlan net
    policy_id vlan
    policy_id net
    policy_id
    vlan net
    vlan
    net

*/
bool operator<(const shared_ptr<Binder> left, const shared_ptr<Binder> right)
{
    #define TRISTATE(v) \
    { \
        if ( (v) < 0 ) return true; \
        if ( (v) > 0 ) return false; \
    }

    #define FIRST_IF_LT(left, right) \
    { \
        if ( (left) < (right) ) return true; \
        if ( (left) > (right) ) return false; \
    }

    #define FIRST_IF_GT(left, right) \
    { \
        if ( (left) < (right) ) return false; \
        if ( (left) > (right) ) return true; \
    }

    //By priorities of options
    FIRST_IF_GT(left->has_policy_id(), right->has_policy_id())
    FIRST_IF_GT(left->has_vlans(), right->has_vlans())
    FIRST_IF_GT(left->has_service(), right->has_service())
    FIRST_IF_GT(left->has_nets(), right->has_nets())
    FIRST_IF_GT(left->has_ports(), right->has_ports())
    FIRST_IF_GT(left->has_proto(), right->has_proto())
    FIRST_IF_GT(left->has_role(), right->has_role())

    //By values of options. Fewer specs = more specific.
    if ( left->has_vlans() && right->has_vlans() )
        FIRST_IF_LT(left->vlans.size(), right->vlans.size())

    if ( left->has_nets() && right->has_nets() )
        FIRST_IF_LT(left->nets.size(), right->nets.size())

    if ( left->has_ports() && right->has_ports() )
        FIRST_IF_LT(left->ports.size(), right->ports.size())

    //Sorted by value for readability if all else is equal
    if ( left->has_policy_id() && right->has_policy_id() )
        FIRST_IF_LT(left->when_policy_id, right->when_policy_id)

    if ( left->has_service() && right->has_service() )
        TRISTATE(left->when_service.compare(right->when_service))

    if ( left->has_proto() && right->has_proto() )
        TRISTATE(left->when_proto.compare(right->when_proto))

    if ( left->has_role() && right->has_role() )
        TRISTATE(left->when_role.compare(right->when_role))

    return false; //if here, l == r
}

#ifdef REG_TEST
#include <iostream>

void print_binder_priorities()
{
    static unsigned const num_combos = 2 * 2 * 2 * 2 * 2 * 2 * 2;
    vector<shared_ptr<Binder>> binders;
    TableApi t;

    for ( unsigned i = 0; i < num_combos; i++ )
    {
        binders.push_back(shared_ptr<Binder>(new Binder(t)));
        binders.back()->print_binding(false);
        
        if ( i & (1 << 0) )
            binders.back()->set_when_policy_id(1);
        
        if ( i & (1 << 1) )
            binders.back()->add_when_vlan("a");
        
        if ( i & (1 << 2) )
            binders.back()->set_when_service("a");       

        if ( i & (1 << 3) )
            binders.back()->add_when_net("a");
        
        if ( i & (1 << 4) )
            binders.back()->add_when_port("a");

        if ( i & (1 << 5) )
            binders.back()->set_when_proto("a");

        if ( i & (1 << 6) )
            binders.back()->set_when_role("a");
    }

    sort(binders.begin(), binders.end());

    for ( auto& b : binders )
    {
        if ( b->has_policy_id() )
            cout << "policy_id ";

        if ( b->has_vlans() )
            cout << "vlan ";

        if ( b->has_service() )
            cout << "service ";

        if ( b->has_nets() )
            cout << "net ";

        if ( b->has_ports() )
            cout << "port ";

        if ( b->has_proto() )
            cout << "proto ";

        if ( b->has_role() )
            cout << "role ";

        cout << endl;
    }
}
#endif
