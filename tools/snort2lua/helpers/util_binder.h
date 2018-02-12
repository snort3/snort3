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
// util_binder.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef HELPERS_PPS_BINDER_H
#define HELPERS_PPS_BINDER_H

#include <climits>
#include <memory>
#include <string>
#include <vector>

class TableApi;

// The Binders destructor will add the Objects configuration to the
//   table_api.
class Converter;
class Binder
{
public:
    enum IncludeType
    { IT_NONE, IT_FILE, IT_INSPECTION, IT_IPS, IT_NETWORK };

    typedef std::pair<std::string, IncludeType> IncludeTypePair;

    //Only use Converter to instantiate Binders through make_binder()
    //This ensures only one binder tables is created per policy
    friend class Converter;

    //Binding order matters. This allows STL compatible sorting.
    friend bool operator<(const std::shared_ptr<Binder>&, const std::shared_ptr<Binder>&);

    Binder(TableApi&);
    ~Binder();

    void print_binding(bool should_print)
    { printed = !should_print; }

    static const unsigned PRIORITY_LAST = UINT_MAX;

    void set_priority(unsigned);
    unsigned get_priority();

    void set_when_ips_policy_id(int);
    void set_when_service(const std::string&);
    void set_when_role(const std::string&);
    void set_when_proto(const std::string&);
    void add_when_vlan(const std::string&);
    void add_when_net(const std::string&);
    void add_when_src_net(const std::string&);
    void add_when_dst_net(const std::string&);
    void add_when_port(const std::string&);
    void add_when_src_port(const std::string&);
    void add_when_dst_port(const std::string&);
    void set_when_src_zone(const std::string&);
    void set_when_dst_zone(const std::string&);
    void clear_ports();

    int get_when_ips_policy_id() const
    { return when_ips_policy_id; }

    bool has_ips_policy_id() const
    { return when_ips_policy_id >= 0; }

    bool has_service() const
    { return !when_service.empty(); }

    bool has_proto() const
    { return !when_proto.empty(); }

    bool has_role() const
    { return !when_role.empty() && when_role != "any"; }

    bool has_vlans() const
    { return !vlans.empty(); }

    bool has_src_nets() const
    { return !src_nets.empty(); }

    bool has_dst_nets() const
    { return !dst_nets.empty(); }

    bool has_nets() const
    { return !nets.empty(); }

    bool has_src_ports() const
    { return !src_ports.empty(); }

    bool has_dst_ports() const
    { return !dst_ports.empty(); }

    bool has_ports() const
    { return !ports.empty(); }

    bool has_src_zone() const
    { return !when_src_zone.empty(); }

    bool has_dst_zone() const
    { return !when_dst_zone.empty(); }

    void set_use_type(const std::string& module_name);
    void set_use_name(const std::string& struct_name);
    void set_use_file(const std::string& file_name, IncludeType = IT_FILE);
    void set_use_service(const std::string& service_name);
    void set_use_action(const std::string& action);

    std::string get_use_type() const
    { return use_type; }

    std::string get_use_name() const
    { return use_name; }

    IncludeTypePair get_use_file() const
    { return IncludeTypePair(use_file, use_file_type); }

    std::string get_use_service() const
    { return use_service; }

    std::string get_use_action() const
    { return use_action; }

private:
    TableApi& table_api;
    bool printed = false; // ensures that the binding is added once,
                          // by either the destructor or user

    unsigned priority = PRIORITY_LAST;
    
    int when_ips_policy_id = -1;
    std::string when_service;
    std::string when_role;
    std::string when_proto;
    std::vector<std::string> vlans;
    std::vector<std::string> nets;
    std::vector<std::string> src_nets;
    std::vector<std::string> dst_nets;
    std::vector<std::string> ports;
    std::vector<std::string> src_ports;
    std::vector<std::string> dst_ports;
    std::string when_src_zone;
    std::string when_dst_zone;

    std::string use_type;
    std::string use_name;
    std::string use_file;
    IncludeType use_file_type = IT_NONE;
    std::string use_service;
    std::string use_action;

    void add_to_configuration();
};


typedef void (Binder::* binder_func)(const std::string&);

#ifdef REG_TEST
void print_binder_priorities();
#endif

#endif

