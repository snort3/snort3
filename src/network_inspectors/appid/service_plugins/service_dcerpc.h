//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// service_dcerpc.h author Sourcefire Inc.

#ifndef SERVICE_DCERPC_H
#define SERVICE_DCERPC_H
#include "service_detector.h"

#define DCERPC_LE_FLAG  0x10

#pragma pack(1)

struct DCERPCHeader
{
    uint8_t version;
    uint8_t minor_version;
    uint8_t type;
    uint8_t flags;
    uint8_t drep[4];
    uint16_t frag_length;
    uint16_t auth_length;
    uint32_t id;
};

#pragma pack()

class AppIdSession;
class ServiceDiscovery;
class ServiceRPCData;

class DceRpcServiceDetector : public ServiceDetector
{
public:
    DceRpcServiceDetector(ServiceDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;

private:
    int udp_validate(AppIdDiscoveryArgs&);
    int tcp_validate(AppIdDiscoveryArgs&);
};
#endif

