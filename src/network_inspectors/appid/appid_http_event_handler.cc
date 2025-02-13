//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

// appid_http_event_handler.cc author Steve Chew <stechew@cisco.com>

// Receive events from the HTTP inspector containing header information
// to be used to detect AppIds.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_http_event_handler.h"

#include <cassert>

#include "detection/detection_engine.h"
#include "flow/stream_flow.h"

#include "app_info_table.h"
#include "appid_cpu_profile_table.h"
#include "appid_debug.h"
#include "appid_discovery.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "appid_session.h"

using namespace snort;

void HttpEventHandler::handle(DataEvent& event, Flow* flow)
{
    if ( !pkt_thread_odp_ctxt )
        return;

    assert(flow);
    AppIdSession* asd = appid_api.get_appid_session(*flow);
    Packet* p = DetectionEngine::get_current_packet();
    assert(p);
    auto direction = event_type == REQUEST_EVENT ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    bool is_debug_active = false;

    const AppIdConfig& config = inspector.get_config();
    if ( !asd )
    {
        // The event is received before appid has seen any packet, e.g., data on SYN
        asd = AppIdSession::allocate_session( p, p->get_ip_proto_next(), direction,
            inspector, *pkt_thread_odp_ctxt );
        if ( appidDebug->is_enabled() )
        {
            appidDebug->activate(flow, asd, inspector.get_ctxt().config.log_all_sessions);
            is_debug_active = true;
        }
        APPID_LOG(p, TRACE_DEBUG_LEVEL, "New AppId session at HTTP event\n");
    }
    else if ( asd->get_odp_ctxt_version() != pkt_thread_odp_ctxt->get_version() )
        return; // Skip detection for sessions using old odp context after odp reload
    if (!asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
        return;

    if (asd->get_session_flags(APPID_SESSION_FIRST_PKT_CACHE_MATCHED) and !asd->get_odp_ctxt().need_reinspection)
        return;

    const uint8_t* header_start;
    int32_t header_length;
    HttpEvent* http_event = (HttpEvent*)&event;
    AppidChangeBits change_bits;

    if ((asd->get_tp_appid_ctxt() or ThirdPartyAppIdContext::get_tp_reload_in_progress()) and
        !http_event->get_is_httpx())
        return;

    bool is_appid_cpu_profiling_running = (asd->get_odp_ctxt().is_appid_cpu_profiler_running());
    Stopwatch<SnortClock> per_appid_event_cpu_timer;

    if (is_appid_cpu_profiling_running)
        per_appid_event_cpu_timer.start();
    
    if (appidDebug->is_enabled() and !is_debug_active)
        appidDebug->activate(flow, asd, config.log_all_sessions);

    APPID_LOG(p, TRACE_DEBUG_LEVEL, "Processing HTTP metadata from HTTP Inspector for stream %" PRId64 "\n",
        http_event->get_httpx_stream_id());

    asd->set_session_flags(APPID_SESSION_HTTP_SESSION);

    AppIdHttpSession* hsession;
    if (http_event->get_is_httpx())
    {
        if (direction == APP_ID_FROM_INITIATOR)
        {
            AppId http_app_id = flow->stream_intf->get_appid_from_stream(flow);
            if (http_app_id != APP_ID_HTTP3 and asd->get_prev_httpx_raw_packet() != asd->session_packet_count)
            {
                asd->delete_all_http_sessions();
                asd->set_prev_httpx_raw_packet(asd->session_packet_count);
            }
            hsession = asd->create_http_session(http_event->get_httpx_stream_id());
        }
        else
        {
            hsession = asd->get_matching_http_session(http_event->get_httpx_stream_id());
            if (!hsession)
                hsession = asd->create_http_session(http_event->get_httpx_stream_id());
        }
    }
    else
    {
        hsession = asd->get_http_session(0);

        if (!hsession)
            hsession = asd->create_http_session();
    }

    if (direction == APP_ID_FROM_INITIATOR)
    {
        header_start = http_event->get_authority(header_length);
        if (header_length > 0)
            hsession->set_field(REQ_HOST_FID, header_start, header_length, change_bits);

        header_start = http_event->get_uri(header_length);
        if (header_length > 0)
        {
            hsession->set_field(REQ_URI_FID, header_start, header_length, change_bits);
            hsession->update_url(change_bits);
        }

        header_start = http_event->get_user_agent(header_length);
        if (header_length > 0)
            hsession->set_field(REQ_AGENT_FID, header_start, header_length, change_bits);

        header_start = http_event->get_cookie(header_length);
        hsession->set_field(REQ_COOKIE_FID, header_start, header_length, change_bits);
        header_start = http_event->get_referer(header_length);
        hsession->set_field(REQ_REFERER_FID, header_start, header_length, change_bits);
        hsession->set_is_webdav(http_event->contains_webdav_method());

        // FIXIT-M: Should we get request body (may be expensive to copy)?
        //      It is not currently set in callback in 2.9.x, only via
        //      third-party.
    }
    else    // Response headers.
    {
        header_start = http_event->get_content_type(header_length);
        if (header_length > 0)
            hsession->set_field(RSP_CONTENT_TYPE_FID, header_start, header_length, change_bits);

        header_start = http_event->get_location(header_length);
        hsession->set_field(RSP_LOCATION_FID, header_start, header_length, change_bits);
        header_start = http_event->get_server(header_length);
        if (header_length > 0)
            hsession->set_field(MISC_SERVER_FID, header_start, header_length, change_bits);

        int32_t responseCodeNum = http_event->get_response_code();
        if (responseCodeNum > 0 and responseCodeNum < 700)
        {
            unsigned int ret;
            char tmpstr[32];
            ret = snprintf(tmpstr, sizeof(tmpstr), "%d", responseCodeNum);
            if ( ret < sizeof(tmpstr) )
                hsession->set_field(MISC_RESP_CODE_FID, (const uint8_t*)tmpstr, ret, change_bits);
        }

        // FIXIT-M: Get Location header data.
        // FIXIT-M: Should we get response body (may be expensive to copy)?
        //      It is not currently set in callback in 2.9.x, only via
        //      third-party.
    }

    header_start = http_event->get_x_working_with(header_length);
    if (header_length > 0)
        hsession->set_field(MISC_XWW_FID, header_start, header_length, change_bits);

    //  The Via header can be in both the request and response.
    header_start = http_event->get_via(header_length);
    if (header_length > 0)
        hsession->set_field(MISC_VIA_FID, header_start, header_length, change_bits);

    if (http_event->get_is_httpx())
    {
        AppId http_app_id = flow->stream_intf->get_appid_from_stream(flow);
        assert((http_app_id == APP_ID_HTTP2) or (http_app_id == APP_ID_HTTP3));
        asd->set_service_id(http_app_id, asd->get_odp_ctxt());
    }

    hsession->process_http_packet(direction, change_bits,
        asd->get_odp_ctxt().get_http_matchers());

    if (!http_event->get_is_httpx())
        asd->set_ss_application_ids(asd->pick_service_app_id(), asd->pick_ss_client_app_id(),
            asd->pick_ss_payload_app_id(), asd->pick_ss_misc_app_id(),
            asd->pick_ss_referred_payload_app_id(), change_bits);
    else
        asd->set_application_ids_service(asd->get_service_id(), change_bits);

    asd->publish_appid_event(change_bits, *p, http_event->get_is_httpx(),
        asd->get_api().get_hsessions_size() - 1);

    if (is_appid_cpu_profiling_running)
    {
        per_appid_event_cpu_timer.stop();
        asd->stats.processing_time += TO_USECS(per_appid_event_cpu_timer.get());
    }
}
