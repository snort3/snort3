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
// assistant_gadget_events.h author Maya Dagon <mdagon@cisco.com>

#ifndef ASSISTANT_GADGET_EVENTS_H
#define ASSISTANT_GADGET_EVENTS_H

#include "framework/data_bus.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

// A flow is setting up assistant inspector.
// For example used by HTTP2 to set NHI as assistant inspector.

namespace snort
{
struct Packet;
}

class AssistantGadgetEvent : public snort::DataEvent
{
public:
    AssistantGadgetEvent(snort::Packet* packet, const char* _service) :
        p(packet), service(_service)
    { }

    snort::Packet* get_packet() const override
    { return p; }

    const char* get_service()
    { return service.c_str(); }

private:
    snort::Packet* p;
    std::string service;
};

#endif

