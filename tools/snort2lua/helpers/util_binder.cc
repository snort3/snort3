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
// util_binder.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "util_binder.h"

#include <algorithm>
#include <cassert>

#include "data/dt_table_api.h"

using namespace std;

Binder::Binder(TableApi& t) : table_api(t)
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

    //FIXIT-M this needs to be split out into ips, network, and inspection
    if ( has_ips_policy_id() )
        table_api.add_option("ips_policy_id", when_ips_policy_id);

    for ( const auto& s : vlans )
        table_api.add_list("vlans", s);

    if ( has_service() )
        table_api.add_option("service", when_service);

    for ( const auto& n : src_nets )
        table_api.add_list("src_nets", n);

    for ( const auto& n : dst_nets )
        table_api.add_list("dst_nets", n);

    for ( const auto& n : nets )
        table_api.add_list("nets", n);

    for ( const auto& p : src_ports )
        table_api.add_list("src_ports", p);

    for ( const auto& p : dst_ports )
        table_api.add_list("dst_ports", p);

    for ( const auto& p : ports )
        table_api.add_list("ports", p);

    if ( has_src_zone() )
        table_api.add_option("src_zone", std::stoi(when_src_zone));

    if ( has_dst_zone() )
        table_api.add_option("dst_zone", std::stoi(when_dst_zone));

    if ( has_proto() )
        table_api.add_option("proto", when_proto);

    if ( has_role() )
        table_api.add_option("role", when_role);

    table_api.close_table(); // "when"

    table_api.open_table("use", true);

    if (!use_action.empty())
        table_api.add_option("action", use_action);

    if (!use_file.empty())
    {
        std::string opt_name;

        switch ( use_file_type )
        {
            case IT_FILE:
                opt_name = "file";
                break;

            case IT_INSPECTION:
                opt_name = "inspection_policy";
                break;

            case IT_IPS:
                opt_name = "ips_policy";
                break;

            case IT_NETWORK:
                opt_name = "network_policy";
                break;
            
            default:
                // This should always be set explicitly if a file name exists.
                assert(false);
        }
        table_api.add_option(opt_name, use_file);
    }

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

void Binder::set_priority(unsigned p)
{ priority = p; }

unsigned Binder::get_priority()
{ return priority; }

void Binder::set_when_ips_policy_id(int id)
{ when_ips_policy_id = id; }

void Binder::set_when_service(const std::string& service)
{ when_service = service; }

void Binder::set_when_role(const std::string& role)
{ when_role = role; }

void Binder::set_when_proto(const std::string& proto)
{ when_proto = proto; }

void Binder::add_when_vlan(const std::string& vlan)
{ vlans.push_back(vlan); }

void Binder::add_when_src_net(const std::string& net)
{ src_nets.push_back(net); }

void Binder::add_when_dst_net(const std::string& net)
{ dst_nets.push_back(net); }

void Binder::add_when_net(const std::string& net)
{ nets.push_back(net); }

void Binder::add_when_src_port(const std::string& port)
{ src_ports.push_back(port); }

void Binder::add_when_dst_port(const std::string& port)
{ dst_ports.push_back(port); }

void Binder::add_when_port(const std::string& port)
{ ports.push_back(port); }

void Binder::set_when_src_zone(const std::string& zone)
{ when_src_zone = zone; }

void Binder::set_when_dst_zone(const std::string& zone)
{ when_dst_zone = zone; }

void Binder::clear_ports()
{ ports.clear(); }

void Binder::set_use_type(const std::string& module_name)
{ use_type = module_name; }

void Binder::set_use_name(const std::string& struct_name)
{ use_name = struct_name; }

void Binder::set_use_file(const std::string& file_name, IncludeType type)
{
    use_file = file_name;
    use_file_type = type;
}

void Binder::set_use_service(const std::string& service_name)
{ use_service = service_name; }

void Binder::set_use_action(const std::string& action)
{ use_action = action; }

/*  This operator is provided for STL compatible sorting. A Binder is considered
    less than another Binder if it should be printed first in the binder table,
    thus giving it higher priority. This is determined by checking for presence
    of when options and assigning them priority. If multiple options exist,
    the highest-priority non-match is used to determine order.

    Example of ordering:
    ips_policy_id vlan net
    ips_policy_id vlan
    ips_policy_id net
    ips_policy_id
    vlan net
    vlan
    net

*/
bool operator<(const shared_ptr<Binder>& left, const shared_ptr<Binder>& right)
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

    // By predetermined order
    FIRST_IF_LT(left->get_priority(), right->get_priority());

    // By priorities of options
    FIRST_IF_GT(left->has_ips_policy_id(), right->has_ips_policy_id())
    
    auto left_zone_specs = left->has_src_zone() + left->has_dst_zone();
    auto right_zone_specs = right->has_src_zone() + right->has_dst_zone();
    FIRST_IF_GT(left_zone_specs, right_zone_specs);

    FIRST_IF_GT(left->has_vlans(), right->has_vlans())
    FIRST_IF_GT(left->has_service(), right->has_service())

    auto left_net_specs = left->has_src_nets() + left->has_dst_nets();
    auto right_net_specs = right->has_src_nets() + right->has_dst_nets();
    FIRST_IF_GT(left_net_specs, right_net_specs);

    FIRST_IF_GT(left->has_nets(), right->has_nets())

    auto left_port_specs = left->has_src_ports() + left->has_dst_ports();
    auto right_port_specs = right->has_src_ports() + right->has_dst_ports();
    FIRST_IF_GT(left_port_specs, right_port_specs);

    FIRST_IF_GT(left->has_ports(), right->has_ports())
    FIRST_IF_GT(left->has_proto(), right->has_proto())
    FIRST_IF_GT(left->has_role(), right->has_role())

    // By values of options. Fewer specs = more specific.
    if ( left->has_vlans() && right->has_vlans() )
        FIRST_IF_LT(left->vlans.size(), right->vlans.size())

    // src/dst nets and ports are not compared. This was done to allow stable sort to
    // preserve the order of nap rules
    if ( left->has_nets() && right->has_nets() )
        FIRST_IF_LT(left->nets.size(), right->nets.size())

    if ( left->has_ports() && right->has_ports() )
        FIRST_IF_LT(left->ports.size(), right->ports.size())

    // Sorted by value for readability if all else is equal
    if ( left->has_ips_policy_id() && right->has_ips_policy_id() )
        FIRST_IF_LT(left->when_ips_policy_id, right->when_ips_policy_id)

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
#include <memory>

void print_binder_priorities()
{
    static unsigned const num_combos = 2 << 12; 
    vector<shared_ptr<Binder>> binders;
    TableApi t;

    for ( unsigned i = 0; i < num_combos; i++ )
    {
        binders.push_back(std::make_shared<Binder>(t));
        binders.back()->print_binding(false);

        if ( i & (1 << 0) )
            binders.back()->set_when_ips_policy_id(1);

        if ( i & (1 << 1) )
            binders.back()->set_when_src_zone("0");

        if ( i & (1 << 2) )
            binders.back()->set_when_dst_zone("0");

        if ( i & (1 << 3) )
            binders.back()->add_when_vlan("a");

        if ( i & (1 << 4) )
            binders.back()->set_when_service("a");

        if ( i & (1 << 5) )
            binders.back()->add_when_src_net("a");

        if ( i & (1 << 6) )
            binders.back()->add_when_dst_net("a");

        if ( i & (1 << 7) )
            binders.back()->add_when_net("a");

        if ( i & (1 << 8) )
            binders.back()->add_when_src_port("a");

        if ( i & (1 << 9) )
            binders.back()->add_when_dst_port("a");

        if ( i & (1 << 10) )
            binders.back()->add_when_port("a");

        if ( i & (1 << 11) )
            binders.back()->set_when_proto("a");

        if ( i & (1 << 12) )
            binders.back()->set_when_role("a");
    }

    stable_sort(binders.begin(), binders.end());

    for ( auto& b : binders )
    {
        if ( b->has_ips_policy_id() )
            cout << "ips_policy_id ";

        if ( b->has_vlans() )
            cout << "vlan ";

        if ( b->has_src_zone() )
            cout << "src_zone ";

        if ( b->has_dst_zone() )
            cout << "dst_zone ";

        if ( b->has_service() )
            cout << "service ";

        if ( b->has_src_nets() )
            cout << "src_net ";

        if ( b->has_dst_nets() )
            cout << "dst_net ";

        if ( b->has_nets() )
            cout << "net ";

        if ( b->has_src_ports() )
            cout << "src_port ";

        if ( b->has_dst_ports() )
            cout << "dst_port ";

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
