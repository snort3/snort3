//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

#ifndef RNA_APP_DISCOVERY_H
#define RNA_APP_DISCOVERY_H

#include "rna_pnd.h"

class RnaAppDiscovery
{
public:
    static void process(AppidEvent* appid_event, DiscoveryFilter& filter,
        RnaConfig* conf, RnaLogger& logger);

    static void discover_service(const snort::Packet* p, IpProtocol proto, RnaTracker& rt,
        const struct in6_addr* src_ip, const uint8_t* src_mac, RnaConfig* conf,
        RnaLogger& logger, AppId service = APP_ID_NONE);

private:
    static void update_service_info(const snort::Packet* p, IpProtocol proto, const char* vendor,
        const char* version, RnaTracker& rt, const snort::SfIp* ip, const uint8_t* src_mac,
        RnaLogger& logger);
};

#endif
