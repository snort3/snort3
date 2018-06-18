//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "app_info_table.h"
#include "appid_debug.h"
#include "appid_http_session.h"
#include "appid_session.h"
#include "utils/util.h"

using namespace snort;

void HttpEventHandler::handle(DataEvent& event, Flow* flow)
{
    AppidSessionDirection direction;
    const uint8_t* header_start;
    int32_t header_length;
    HttpEvent* http_event = (HttpEvent*)&event;

    assert(flow);
    AppIdSession* asd = appid_api.get_appid_session(*flow);
    if (!asd)
        return;

    if (appidDebug->is_active())
        LogMessage("AppIdDbg %s Processing HTTP metadata from HTTP Inspector\n",
            appidDebug->get_debug_session());

    direction = event_type == REQUEST_EVENT ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

    AppIdHttpSession* hsession = asd->get_http_session();

    if (direction == APP_ID_FROM_INITIATOR)
    {
        header_start = http_event->get_host(header_length);
        if (header_length > 0)
        {
            hsession->set_field(REQ_HOST_FID, header_start, header_length);
            asd->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;

            header_start = http_event->get_uri(header_length);
            if (header_length > 0)
            {
                hsession->set_field(REQ_URI_FID, header_start, header_length);
                hsession->update_url();
            }
        }

        header_start = http_event->get_user_agent(header_length);
        if (header_length > 0)
        {
            hsession->set_field(REQ_AGENT_FID, header_start, header_length);
            asd->scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
        }

        header_start = http_event->get_cookie(header_length);
        hsession->set_field(REQ_COOKIE_FID, header_start, header_length);
        header_start = http_event->get_referer(header_length);
        hsession->set_field(REQ_REFERER_FID, header_start, header_length);
        header_start = http_event->get_x_working_with(header_length);
        hsession->set_field(MISC_XWW_FID, header_start, header_length);
        hsession->set_is_webdav(http_event->contains_webdav_method());

        // FIXIT-M: Should we get request body (may be expensive to copy)?
        //      It is not currently set in callback in 2.9.x, only via
        //      third-party.
    }
    else    // Response headers.
    {
        header_start = http_event->get_content_type(header_length);
        hsession->set_field(RSP_CONTENT_TYPE_FID, header_start, header_length);
        header_start = http_event->get_location(header_length);
        hsession->set_field(RSP_LOCATION_FID, header_start, header_length);
        header_start = http_event->get_server(header_length);
        hsession->set_field(MISC_SERVER_FID, header_start, header_length);

        int32_t responseCodeNum = http_event->get_response_code();
        if (responseCodeNum > 0 && responseCodeNum < 700)
        {
            unsigned int ret;
            char tmpstr[32];
            ret = snprintf(tmpstr, sizeof(tmpstr), "%d", responseCodeNum);
            if ( ret < sizeof(tmpstr) )
                hsession->set_field(MISC_RESP_CODE_FID, (const uint8_t*)tmpstr, ret);
        }

        // FIXIT-M: Get Location header data.
        // FIXIT-M: Should we get response body (may be expensive to copy)?
        //      It is not currently set in callback in 2.9.x, only via
        //      third-party.
    }

    //  The Via header can be in both the request and response.
    header_start = http_event->get_via(header_length);
    if (header_length > 0)
    {
        hsession->set_field(MISC_VIA_FID, header_start, header_length);
        asd->scan_flags |= SCAN_HTTP_VIA_FLAG;
    }

    hsession->process_http_packet(direction);
    if (asd->service.get_id() == APP_ID_HTTP)
    {
        asd->set_application_ids(asd->pick_service_app_id(), asd->pick_client_app_id(),
            asd->pick_payload_app_id(), asd->pick_misc_app_id());
    }
}

