//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// opportunistic_tls_event.h author Steven Baigal <sbaigal@cisco.com>

#ifndef OPPORTUNISTIC_TLS_EVENT_H
#define OPPORTUNISTIC_TLS_EVENT_H

#include <memory>
#include <string>

#include "pub_sub/intrinsic_event_ids.h"

// An opportunistic SSL/TLS session will start from next packet

namespace snort
{

class SO_PUBLIC OpportunisticTlsEvent : public snort::DataEvent
{
public:
    OpportunisticTlsEvent(const snort::Packet* p, const char* service) :
        pkt(p), next_service(service) { }

    const snort::Packet* get_packet() const override
    { return pkt; }

    const char* get_next_service()
    { return next_service; }

private:
    const snort::Packet* pkt;
    const char* next_service;
};

}

#endif
