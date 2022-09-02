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
// rna_events.h author Michael Matirko <mmatirko@cisco.com>

#ifndef RNA_EVENTS_H
#define RNA_EVENTS_H

#include "framework/data_bus.h"
#include "service_inspectors/netflow/netflow_record.h"

#define RNA_NEW_NETFLOW_CONN "network_inspector.rna.new_netflow_host"

namespace snort
{

class RNAEvent : public DataEvent
{
public:
    RNAEvent(const snort::Packet* p, const NetFlowSessionRecord* rec, const uint32_t service)
        : pkt(p), record(rec), service_id(service) { }

    const Packet* get_packet() const override
    { return pkt; }

    const NetFlowSessionRecord* get_record()
    { return record; }

    uint32_t get_service_id()
    { return service_id; }

private:
    const Packet* pkt;
    const NetFlowSessionRecord* record;
    const uint32_t service_id;
};

}

#endif
