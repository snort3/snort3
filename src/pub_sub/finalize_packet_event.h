//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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
// finalize_packet_event.h author Steve Chew <stechew@cisco.com>

#ifndef FINALIZE_PACKET_EVENT_H
#define FINALIZE_PACKET_EVENT_H

// An event to indicate that the packet is about to be finalized (sent
// back to the daq).

#include <daq_common.h>

#include "framework/data_bus.h"

#define FINALIZE_PACKET_EVENT "analyzer.finalize.packet"

namespace snort
{

class SO_PUBLIC FinalizePacketEvent : public snort::DataEvent
{
public:
    FinalizePacketEvent(const snort::Packet* p, DAQ_Verdict& v) :
        pkt(p), verdict(v)
    {
    }

    const snort::Packet* get_packet() override
    { return pkt; }

    DAQ_Verdict& get_verdict()
    { return verdict; }

private:
    const snort::Packet* pkt;
    DAQ_Verdict& verdict;
};

}

#endif
