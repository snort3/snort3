//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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
// netflow_event.h author Masud Hasan <mashasan@cisco.com>

#ifndef NETFLOW_EVENT_H
#define NETFLOW_EVENT_H

#include "framework/data_bus.h"
#include "service_inspectors/netflow/netflow_headers.h"

#define NETFLOW_EVENT "service_inspector.netflow"

namespace snort
{

class NetflowEvent : public DataEvent
{
public:
    NetflowEvent(const snort::Packet* p, const NetflowSessionRecord* rec,
        bool cre_host, bool cre_serv, uint32_t s_id)
        : pkt(p), record(rec), create_host(cre_host),
          create_service(cre_serv), serviceID(s_id) { }

    const Packet* get_packet() override
    { return pkt; }

    const NetflowSessionRecord* get_record()
    { return record; }

    bool get_create_host()
    { return create_host; }

    bool get_create_service()
    { return create_service; }

    uint32_t get_service_id()
    { return serviceID; }

private:
    const Packet* pkt;
    const NetflowSessionRecord* record;
    bool create_host;
    bool create_service;
    uint32_t serviceID = 0;
};

}

#endif
