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
// binder.cc author Russ Combs <rucombs@cisco.com>

#ifndef BINDING_H
#define BINDING_H

#include <string>

#include "framework/bits.h"
#include "sfip/sf_ipvar.h"

namespace snort
{
class Flow;
struct Packet;
}

struct BindWhen
{
    enum Role
    { BR_CLIENT, BR_SERVER, BR_EITHER, BR_MAX };

    unsigned ips_id;
    unsigned protos;
    Role role;
    std::string svc;

    bool split_nets;
    sfip_var_t* src_nets;
    sfip_var_t* dst_nets;

    ByteBitSet ifaces;
    VlanBitSet vlans;

    bool split_ports;
    PortBitSet src_ports;
    PortBitSet dst_ports;

    int32_t src_zone;
    int32_t dst_zone;
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
    unsigned network_index;
    unsigned inspection_index;
    unsigned ips_index;
    What what;
    void* object;
};

struct Binding
{
    enum DirResult
    {
        // Did not match
        DR_NO_MATCH,

        // Matched but direction could not be determined
        DR_ANY_MATCH,

        // On flow: src_* matched client, dst_* matched server
        // On packet: src_* matched p->src_*, dst_* matched p->dst_*
        DR_FORWARD,

        // On flow: src_* matched server, dst_* matched client
        // On packet: src_* matched p->dst_*, dst_* matched p->src_*
        DR_REVERSE,
    };

    BindWhen when;
    BindUse use;

    Binding();
    ~Binding();

    bool check_all(const snort::Flow*, snort::Packet*) const;
    bool check_ips_policy(const snort::Flow*) const;
    bool check_iface(const snort::Packet*) const;
    bool check_vlan(const snort::Flow*) const;
    bool check_addr(const snort::Flow*) const;
    DirResult check_split_addr(const snort::Flow*, const snort::Packet*, const DirResult) const;
    bool check_proto(const snort::Flow*) const;
    bool check_port(const snort::Flow*) const;
    DirResult check_split_port(const snort::Flow*, const snort::Packet*, const DirResult) const;
    bool check_service(const snort::Flow*) const;
    DirResult check_zone(const snort::Packet*, const DirResult) const;
};

#endif

