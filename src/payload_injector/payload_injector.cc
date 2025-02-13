//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

// payload_injector.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "payload_injector.h"

#include "detection/detection_engine.h"
#include "flow/session.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"
#include "utils/util.h"

#include "payload_injector_config.h"
#include "payload_injector_module.h"

using namespace snort;

// Should have an entry for each error in InjectionReturnStatus
static const std::map <InjectionReturnStatus, const char*> InjectionErrorToString =
{
    { ERR_INJECTOR_NOT_CONFIGURED, "Payload injector is not configured" },
    { ERR_STREAM_NOT_ESTABLISHED, "TCP stream not established" },
    { ERR_UNIDENTIFIED_PROTOCOL, "Unidentified protocol" },
    { ERR_HTTP2_STREAM_ID_0, "HTTP/2 - injection to stream 0" },
    { ERR_PAGE_TRANSLATION, "Error in translating HTTP block page to HTTP/2. "
      "Unsupported or bad format." },
    { ERR_HTTP2_MID_FRAME, "HTTP/2 - attempt to inject mid frame. Currently not supported." },
    { ERR_TRANSLATED_HDRS_SIZE,
      "HTTP/2 translated header size is bigger than expected. Update max size." },
    { ERR_HTTP2_EVEN_STREAM_ID, "HTTP/2 - injection to server initiated stream" },
    { ERR_PKT_FROM_SERVER, "Packet is from server" },
    { ERR_CONFLICTING_S2C_TRAFFIC, "Conflicting S2C HTTP traffic in progress" }
};

InjectionReturnStatus PayloadInjector::inject_http2_payload(Packet* p,
    const InjectionControl& control, EncodeFlags df)
{
    InjectionReturnStatus status;

    if (control.stream_id == 0)
        status = ERR_HTTP2_STREAM_ID_0;
    else if (control.stream_id % 2 == 0)
    {
        // Don't inject against server initiated streams
        status = ERR_HTTP2_EVEN_STREAM_ID;
    }
    else
    {
        // Check if mid frame
        Http2FlowData* const session_data =
            (Http2FlowData*)p->flow->get_flow_data(Http2FlowData::inspector_id);
        if (!session_data || session_data->is_mid_frame())
        {
            payload_injector_stats.http2_mid_frame++;
            // FIXIT-E mid-frame injection not supported
            status = ERR_HTTP2_MID_FRAME;
        }
        else if (p->flow->session and
            p->flow->session->are_client_segments_queued())
        {
            status = ERR_CONFLICTING_S2C_TRAFFIC;
        }
        else
        {
            uint8_t* http2_payload;
            uint32_t payload_len;
            const bool send_settings = (session_data->was_server_settings_received() == false);
            status = get_http2_payload(control, http2_payload, payload_len, send_settings);
            if (status == INJECTION_SUCCESS)
            {
                p->active->send_data(p, df, http2_payload, payload_len);
                snort_free(http2_payload);
                payload_injector_stats.http2_injects++;
                return INJECTION_SUCCESS;
            }
            else
                payload_injector_stats.http2_translate_err++;
        }
    }

    // If we got here, shouldn't inject the page
    p->active->send_data(p, df, nullptr, 0);
    return status;
}

InjectionReturnStatus PayloadInjector::inject_http_payload(Packet* p,
    const InjectionControl& control)
{
    InjectionReturnStatus status = INJECTION_SUCCESS;

    assert(p != nullptr);

    const PayloadInjectorConfig* conf = p->context->conf->payload_injector_config;
    if (conf)
    {
        if (p->packet_flags & PKT_FROM_SERVER)
            status =  ERR_PKT_FROM_SERVER;
        else
        {
            EncodeFlags df = ENC_FLAG_RST_SRVR; // Send RST to server.

            if (!p->flow)
                status = ERR_UNIDENTIFIED_PROTOCOL;
            else if (p->flow->ssn_state.session_flags & SSNFLAG_ESTABLISHED)
            {
                // FIXIT-M should we be supporting injection when there is no gadget on the flow?
                if (!p->flow->gadget || strcmp(p->flow->gadget->get_name(), "http_inspect") == 0)
                {
                    if (p->flow->session and
                        p->flow->session->are_client_segments_queued())
                    {
                        status = ERR_CONFLICTING_S2C_TRAFFIC;
                        p->active->send_data(p, df, nullptr, 0);    // To send reset
                    }
                    else
                    {
                        payload_injector_stats.http_injects++;
                        p->active->send_data(p, df, control.http_page, control.http_page_len);
                    }
                }
                else if (strcmp(p->flow->gadget->get_name(),"http2_inspect") == 0)
                    status = inject_http2_payload(p, control, df);
                else
                    status = ERR_UNIDENTIFIED_PROTOCOL;
            }
            else
                status = ERR_STREAM_NOT_ESTABLISHED;
        }
    }
    else
        status = ERR_INJECTOR_NOT_CONFIGURED;

    p->active->block_session(p, true);

    DetectionEngine::disable_all(p);

    return status;
}

const char* PayloadInjector::get_err_string(InjectionReturnStatus status)
{
    auto iter = InjectionErrorToString.find(status);
    assert (iter != InjectionErrorToString.end());
    return iter->second;
}
