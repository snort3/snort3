//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "app_info_table.h"
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

    if ( !asd )
    {
        // The event is received before appid has seen any packet, e.g., data on SYN
        asd = AppIdSession::allocate_session( p, p->get_ip_proto_next(), direction,
            inspector, *pkt_thread_odp_ctxt );
        if ( appidDebug->is_enabled() )
        {
            appidDebug->activate(flow, asd, inspector.get_ctxt().config.log_all_sessions);
            if ( appidDebug->is_active() )
                LogMessage("AppIdDbg %s New AppId session at HTTP event\n",
                    appidDebug->get_debug_session());
        }
    }
    else if ( asd->get_odp_ctxt_version() != pkt_thread_odp_ctxt->get_version() )
        return; // Skip detection for sessions using old odp context after odp reload
    if (!asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
        return;

    const uint8_t* header_start;
    int32_t header_length;
    HttpEvent* http_event = (HttpEvent*)&event;
    AppidChangeBits change_bits;

    if ((asd->get_tp_appid_ctxt() or ThirdPartyAppIdContext::get_tp_reload_in_progress()) and
        !http_event->get_is_http2())
        return;

    if (appidDebug->is_active())
        LogMessage("AppIdDbg %s Processing HTTP metadata from HTTP Inspector for stream %u\n",
            appidDebug->get_debug_session(), http_event->get_http2_stream_id());

    asd->set_session_flags(APPID_SESSION_HTTP_SESSION);

    AppIdHttpSession* hsession;
    if (http_event->get_is_http2())
    {
        if (direction == APP_ID_FROM_INITIATOR)
        {
            if (asd->get_prev_http2_raw_packet() != asd->session_packet_count)
            {
                asd->delete_all_http_sessions();
                asd->set_prev_http2_raw_packet(asd->session_packet_count);
            }
            hsession = asd->create_http_session(http_event->get_http2_stream_id());
        }
        else
        {
            hsession = asd->get_matching_http_session(http_event->get_http2_stream_id());
            if (!hsession)
                hsession = asd->create_http_session(http_event->get_http2_stream_id());
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
        if (responseCodeNum > 0 && responseCodeNum < 700)
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

    if (http_event->get_is_http2())
    {
        asd->set_service_id(APP_ID_HTTP2, asd->get_odp_ctxt());
    }

    hsession->process_http_packet(direction, change_bits,
        asd->get_odp_ctxt().get_http_matchers());

    if (asd->get_service_id() != APP_ID_HTTP2)
        asd->set_ss_application_ids(asd->pick_service_app_id(), asd->pick_ss_client_app_id(),
            asd->pick_ss_payload_app_id(), asd->pick_ss_misc_app_id(),
            asd->pick_ss_referred_payload_app_id(), change_bits);
    else
        asd->set_application_ids_service(APP_ID_HTTP2, change_bits);

    asd->publish_appid_event(change_bits, *p, http_event->get_is_http2(),
        asd->get_api().get_hsessions_size() - 1);
}

