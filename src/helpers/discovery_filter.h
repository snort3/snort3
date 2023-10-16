//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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

// discovery_filter.h author Masud Hasan <mashasan@cisco.com>

#ifndef DISCOVERY_FILTER_H
#define DISCOVERY_FILTER_H

#include <unordered_map>

#include "protocols/packet.h"
#include "sfip/sf_ipvar.h"
#include "sfip/sf_vartable.h"

enum FilterType { DF_APP, DF_HOST, DF_USER, DF_MAX };
enum FlowCheckDirection { DF_NONE, DF_CLIENT, DF_SERVER };

typedef int32_t IntfType; // matching daq header
#define DF_ANY_INTF INT32_MAX

// Holds configurations to filter traffic discovery based network address, port, and interface
class DiscoveryFilter
{
public:
    DiscoveryFilter(const std::string& conf_path);
    ~DiscoveryFilter();

    // If flag is provided (preferable), results are stored in flag to avoid future lookups
    bool is_app_monitored(const snort::Packet* p, uint8_t* flag = nullptr);
    bool is_host_monitored(const snort::Packet* p, uint8_t* flag = nullptr,
        const snort::SfIp* ip = nullptr, FlowCheckDirection flowdir = FlowCheckDirection::DF_NONE);
    bool is_user_monitored(const snort::Packet* p, uint8_t* flag = nullptr);

private:

    enum Direction { CLIENT, SERVER, NUM_DIRECTIONS };

    bool is_monitored(const snort::Packet* p, FilterType type, uint8_t& flag,
        uint8_t checked, uint8_t monitored, const snort::SfIp* ip = nullptr,
        FlowCheckDirection flowdir = FlowCheckDirection::DF_NONE);
    bool is_monitored(const snort::Packet* p, FilterType type, const snort::SfIp* ip = nullptr,
        FlowCheckDirection flowdir = FlowCheckDirection::DF_NONE);
    void add_ip(FilterType type, IntfType intf, std::string& ip);
    sfip_var_t* get_list(FilterType type, IntfType intf, bool exclude_empty = false);

    // add ip for port exclusion
    void add_ip(Direction dir, uint16_t proto, uint16_t port, const std::string& ip);
    sfip_var_t* get_port_list(Direction dir, uint32_t key);

    inline uint32_t proto_port_key(uint16_t proto, uint16_t port) const
    {
        return (proto << 16) | port;
    }

    bool is_port_excluded(const snort::Packet* p);

    std::unordered_map<IntfType, sfip_var_t*> intf_ip_list[DF_MAX];
    vartable_t* vartable = nullptr;

    // Internal cache for sfip_var_t indexed by protocol x port, for port
    // exclusion.
    std::unordered_map<uint32_t, sfip_var_t*> port_ip_list[NUM_DIRECTIONS];

#ifdef UNIT_TEST
    friend bool is_port_excluded_test(DiscoveryFilter& df, snort::Packet* p);
#endif
};

#endif
