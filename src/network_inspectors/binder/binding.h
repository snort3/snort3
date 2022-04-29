//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
// binding.h author Russ Combs <rucombs@cisco.com>

#ifndef BINDING_H
#define BINDING_H

#include <string>

#include "framework/bits.h"
#include "main/policy.h"
#include "sfip/sf_ipvar.h"

namespace snort
{
class Flow;
class Inspector;
struct SnortConfig;
}

struct BindWhen
{
    enum Role
    { BR_CLIENT, BR_SERVER, BR_EITHER, BR_MAX };

    PolicyId ips_id;
    unsigned ips_id_user;
    unsigned protos;
    Role role;
    std::string svc;

    sfip_var_t* src_nets;
    sfip_var_t* dst_nets;

    VlanBitSet vlans;

    PortBitSet src_ports;
    PortBitSet dst_ports;

    std::unordered_set<int32_t> src_intfs;
    std::unordered_set<int32_t> dst_intfs;

    std::unordered_set<int16_t> src_groups;
    std::unordered_set<int16_t> dst_groups;

    std::unordered_set<uint32_t> addr_spaces;

    std::unordered_set<uint32_t> tenants;

    enum Criteria
    {
        BWC_IPS_ID =        0x0001,
        BWC_PROTO =         0x0002,
        BWC_SVC =           0x0004,
        BWC_NETS =          0x0008,
        BWC_SPLIT_NETS =    0x0010,
        BWC_VLANS =         0x0020,
        BWC_PORTS =         0x0040,
        BWC_SPLIT_PORTS =   0x0080,
        BWC_INTFS =         0x0100,
        BWC_SPLIT_INTFS =   0x0200,
        BWC_GROUPS =        0x0400,
        BWC_SPLIT_GROUPS =  0x0800,
        BWC_ADDR_SPACES =   0x1000,
        BWC_TENANTS =       0x2000
    };
    uint16_t criteria_flags;

    void add_criteria(uint16_t flags)
    { criteria_flags |= flags; }
    bool has_criteria(uint16_t flags) const
    { return (criteria_flags & flags) == flags; }
};

struct BindUse
{
    enum Action
    { BA_RESET, BA_BLOCK, BA_ALLOW, BA_INSPECT, BA_MAX };

    enum What
    { BW_NONE, BW_PASSIVE, BW_CLIENT, BW_SERVER, BW_STREAM, BW_WIZARD, BW_GADGET, BW_MAX };

    std::string svc;
    std::string type;
    std::string name;

    Action action;
    unsigned inspection_index;
    unsigned ips_index;
    What what;
    snort::Inspector* inspector;
    bool global_type;
};

struct Binding
{
    BindWhen when;
    BindUse use;

    Binding();

    void clear();
    void configure(const snort::SnortConfig* sc);

    bool check_all(const snort::Flow&, const char* = nullptr) const;
    bool check_all(const snort::Packet*) const;
    bool check_ips_policy(const snort::Flow&) const;
    bool check_ips_policy() const;
    bool check_vlan(const snort::Flow&) const;
    bool check_vlan(const snort::Packet*) const;
    bool check_addr(const snort::Flow&) const;
    bool check_addr(const snort::Packet*) const;
    bool check_split_addr(const snort::Flow&) const;
    bool check_split_addr(const snort::Packet*) const;
    bool check_proto(const snort::Flow&) const;
    bool check_proto(const snort::Packet*) const;
    bool check_port(const snort::Flow&) const;
    bool check_port(const snort::Packet*) const;
    bool check_split_port(const snort::Flow&) const;
    bool check_split_port(const snort::Packet*) const;
    bool check_intf(const snort::Flow&) const;
    bool check_intf(const snort::Packet*) const;
    bool check_split_intf(const snort::Flow&) const;
    bool check_split_intf(const snort::Packet*) const;
    bool check_group(const snort::Flow&) const;
    bool check_group(const snort::Packet*) const;
    bool check_split_group(const snort::Flow&) const;
    bool check_split_group(const snort::Packet*) const;
    bool check_address_space(const snort::Flow&) const;
    bool check_address_space(const snort::Packet*) const;
    bool check_tenant(const snort::Flow&) const;
    bool check_tenant(const snort::Packet*) const;
    bool check_service(const snort::Flow&) const;
    bool check_service(const char* service) const;
    bool check_service() const;
};

#endif

