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

#include "protocols/packet.h"
#include "sfip/sf_ipvar.h"
#include "sfip/sf_vartable.h"

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
    bool is_monitored(const snort::Packet* p, const char* type, uint8_t& flag,
        uint8_t checked, uint8_t monitored);
    bool is_monitored(const snort::Packet* p, const char* type);
    void add_ip(const char* name, std::string ip);

    vartable_t* vartable = nullptr;
    sfip_var_t* varip = nullptr;
};

#endif
