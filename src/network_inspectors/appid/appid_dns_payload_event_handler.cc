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

// appid_dns_payload_event_handler.cc author Shibin K V <shikv@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_dns_payload_event_handler.h"

#include "flow/stream_flow.h"
#include "profiler/profiler_defs.h"
#include "pub_sub/dns_payload_event.h"

#include "appid_dns_session.h"
#include "appid_inspector.h"
#include "detector_plugins/detector_dns.h"

using namespace snort;

void AppIdDnsPayloadEventHandler::handle(DataEvent& event, Flow* flow)
{
    Packet *p = DetectionEngine::get_current_packet();
    if(!flow or !p)
        return;
    DnsPayloadEvent* dns_payload_event = (DnsPayloadEvent*)&event;
    int32_t payload_length = 0;
    const uint8_t* dns_payload = dns_payload_event->get_payload(payload_length);
    bool is_udp = dns_payload_event->is_dns_udp();
    AppIdSession* asd = appid_api.get_appid_session(*flow);
    if (!dns_payload or payload_length <= 0 or !dns_payload_event->is_last_piece() or !asd)
        return;
    AppidChangeBits change_bits;
    // Skip sessions using old odp context after reload detectors
    if (!pkt_thread_odp_ctxt or
        (pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version()))
        return;

    bool is_appid_cpu_profiling_running = (asd->get_odp_ctxt().is_appid_cpu_profiler_running());
    Stopwatch<SnortClock> per_appid_event_cpu_timer;

    if (is_appid_cpu_profiling_running)
        per_appid_event_cpu_timer.start();

    AppidSessionDirection dir = dns_payload_event->is_from_client() ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    AppIdDiscoveryArgs args(dns_payload, payload_length, dir, *asd, nullptr, change_bits);
    APPID_LOG(p, TRACE_DEBUG_LEVEL, "Processing DNS-%s payload event\n", is_udp ? "UDP" : "TCP");
    int rval;
    if (is_udp)
    {
        if (!dns_udp_detector)
            return;
        rval = static_cast<DnsUdpServiceDetector*>(dns_udp_detector)->validate_doh(args);
    }
    else
    {
        if (!dns_tcp_detector)
            return;
        rval = static_cast<DnsTcpServiceDetector*>(dns_tcp_detector)->validate_doq(args);
    }
    APPID_LOG(p, TRACE_DEBUG_LEVEL, "DNS-%s detector returned %d\n",
                is_udp ? "UDP" : "TCP", rval);

    if (rval == APPID_SUCCESS || rval == APPID_INPROCESS)
    {
        AppId service_id = asd->pick_service_app_id();
        if (service_id == APP_ID_HTTP2 || service_id == APP_ID_HTTP3)
        {
            if (flow->stream_intf)
            {
                int64_t stream_id = -1;
                flow->stream_intf->get_stream_id(flow, stream_id);
                if (stream_id != -1)
                {
                    AppIdHttpSession* hsession = asd->get_matching_http_session(stream_id);
                    if (hsession)
                        hsession->set_payload(APP_ID_DNS, change_bits, "body");
                }
                else
                {
                    // Stream ID not yet assigned, defer DNS payload processing
                    APPID_LOG(p, TRACE_DEBUG_LEVEL, "Stream ID not assigned yet for HTTP/2 or HTTP/3 flow\n");
                    return;
                }
            }
        }
        else
        {
            AppIdHttpSession* hsession = asd->get_http_session();
            if (hsession)
                hsession->set_payload(APP_ID_DNS, change_bits, "body");
            if (asd->get_payload_id() != APP_ID_DNS)
                asd->set_payload_appid_data(APP_ID_DNS, nullptr);
            asd->set_ss_application_ids_payload(APP_ID_DNS, change_bits);
        }
        AppIdDnsSession* dsession = asd->get_dns_session();
        if (!dsession)
            return;
        dsession->set_doh(true);
        asd->publish_appid_event(change_bits, *p);
        // TODO: add DNS hostname based appid detection
    }

    if (is_appid_cpu_profiling_running)
    {
        per_appid_event_cpu_timer.stop();
        asd->stats.processing_time += TO_USECS(per_appid_event_cpu_timer.get());
    }
}

