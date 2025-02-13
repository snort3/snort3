//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

// appid_httpx_req_body_event_handler.h
// author Kani<kamurthi@cisco.com>

#ifndef APPID_HTTPX_REQ_BODY_EVENT_HANDLER_H
#define APPID_HTTPX_REQ_BODY_EVENT_HANDLER_H

#include "pub_sub/http_request_body_event.h"

class AppIdHttpXReqBodyEventHandler : public snort::DataHandler
{
public:
    AppIdHttpXReqBodyEventHandler() : DataHandler(MOD_NAME){ }
    void handle(snort::DataEvent& event, snort::Flow* flow) override
    {
        if (!pkt_thread_odp_ctxt)
            return;
        assert(flow);
        snort::Packet* p = snort::DetectionEngine::get_current_packet();
        assert(p);
        AppIdSession* asd = snort::appid_api.get_appid_session(*flow);

        if (!asd or
            !asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
            return;
        // Skip sessions using old odp context after reload detectors
        if (pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version())
            return;
        snort::HttpRequestBodyEvent* http_req_body = (snort::HttpRequestBodyEvent*)&event;
        AppIdHttpSession* hsession = asd->get_matching_http_session(
            http_req_body->get_httpx_stream_id());

        if (!hsession)
            return;

        const uint8_t* header_start;
        int32_t header_length;
        int32_t offset;
        AppidChangeBits change_bits;
        header_start = http_req_body->get_request_body_data(header_length, offset);
        if (hsession->get_field(REQ_BODY_FID) and
            !asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
            hsession->set_chp_finished(false);

        hsession->set_req_body_field(REQ_BODY_FID, header_start, header_length, change_bits);
        hsession->process_http_packet(APP_ID_FROM_INITIATOR, change_bits,
            asd->get_odp_ctxt().get_http_matchers());
        asd->publish_appid_event(change_bits, *p, true, asd->get_api().get_hsessions_size() - 1);

        bool last_req_rcvd = http_req_body->is_last_request_body_piece();
        if (last_req_rcvd)
            hsession->set_rcvd_full_req_body(last_req_rcvd);
    }
};
#endif

