//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

typedef int32_t ZoneType; // matching daq header
#define DF_ANY_ZONE INT32_MAX

// Holds configurations to filter traffic discovery based network address, port, and zone
class DiscoveryFilter
{
public:
    DiscoveryFilter(const std::string& conf_path);
    ~DiscoveryFilter();

    // If flag is provided (preferable), results are stored in flag to avoid future lookups
    bool is_app_monitored(const snort::Packet* p, uint8_t* flag = nullptr);
    bool is_host_monitored(const snort::Packet* p, uint8_t* flag = nullptr);
    bool is_user_monitored(const snort::Packet* p, uint8_t* flag = nullptr);

private:
    bool is_monitored(const snort::Packet* p, FilterType type, uint8_t& flag,
        uint8_t checked, uint8_t monitored);
    bool is_monitored(const snort::Packet* p, FilterType type);
    void add_ip(FilterType type, ZoneType zone, std::string& ip);
    sfip_var_t* get_list(FilterType type, ZoneType zone, bool exclude_empty = false);

    std::unordered_map<ZoneType, sfip_var_t*> zone_list[DF_MAX];
    vartable_t* vartable = nullptr;
};

#endif
