//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// dns_payload_event_handler.cc author Shibin K V <shikv@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dns_payload_event_handler.h"

#include "detection/detection_engine.h"
#include "pub_sub/dns_payload_event.h"

#include "dns.h"

using namespace snort;

void DnsPayloadEventHandler::handle(DataEvent& event, Flow* flow)
{
    Packet *p = DetectionEngine::get_current_wire_packet();
    if (!flow or !p )
        return;
    DnsPayloadEvent* dns_payload_event = (DnsPayloadEvent*)&event;
    int32_t payload_length = 0;
    const uint8_t* dns_payload = dns_payload_event->get_payload(payload_length);
    bool is_udp = dns_payload_event->is_dns_udp();

    if (!dns_payload or payload_length <= 0)
        return;

    const uint8_t* old_data = p->data;
    const uint32_t old_dsize = p->dsize;
    SnortProtocolId old_protocol_id = p->flow->ssn_state.snort_protocol_id;
    bool is_insert_set = p->packet_flags & PKT_STREAM_INSERT;

    {
        p->data = dns_payload;
        p->dsize = payload_length;
        p->flow->ssn_state.snort_protocol_id = inspector.get_service();
        p->context->snapshot_flow(p->flow);
        p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
        if (is_insert_set)
            p->packet_flags &= ~PKT_STREAM_INSERT;
        DetectionEngine::detect(p);
    }

    if (is_udp)
        static_cast<Dns&>(inspector).snort_dns(p, true, true);

    p->data = old_data;
    p->dsize = old_dsize;
    p->flow->ssn_state.snort_protocol_id = old_protocol_id;
    p->context->snapshot_flow(flow);
    if (is_insert_set)
        p->packet_flags |= PKT_STREAM_INSERT;

}
