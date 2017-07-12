//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

#include <assert.h>

#include "appid_http_session.h"
#include "appid_module.h"
#include "appid_session.h"
#include "utils/util.h"

static void replace_header_data(char** data, uint16_t& datalen, const uint8_t* header_start,
    int32_t header_length)
{
    if (header_length <= 0)
        return;

    assert(data);
    if (*data)
        snort_free(*data);

    *data = (char*)snort_alloc(header_length + 1);
    memcpy(*data, header_start, header_length);
    *(*data + header_length) = '\0';
    datalen = header_length;
}

void HttpEventHandler::handle(DataEvent& event, Flow* flow)
{
    int direction;
    uint16_t tmplen;
    const uint8_t* header_start;
    int32_t header_length;
    HttpEvent* http_event = (HttpEvent*)&event;

    assert(flow);
    AppIdSession* session = appid_api.get_appid_session(flow);
    if (!session)
        return;

    direction = event_type == REQUEST_EVENT ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

    if (!session->hsession)
        session->hsession = new AppIdHttpSession(session);

    if (direction == APP_ID_FROM_INITIATOR)
    {
        header_start = http_event->get_host(header_length);
        if (header_length > 0)
        {
            replace_header_data(&session->hsession->host,
                session->hsession->host_buflen, header_start, header_length);
            session->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;

            header_start = http_event->get_uri(header_length);
            if (header_length > 0)
            {
                replace_header_data(&session->hsession->uri,
                    session->hsession->uri_buflen, header_start,
                    header_length);

                if (session->hsession->url)
                    snort_free(session->hsession->url);
                tmplen = sizeof(HTTP_PREFIX) + session->hsession->host_buflen +
                    session->hsession->uri_buflen + 1;
                session->hsession->url = (char*)snort_calloc(tmplen);
                strcpy(session->hsession->url, HTTP_PREFIX);
                strncat(session->hsession->url, session->hsession->host,
                    session->hsession->host_buflen);
                strncat(session->hsession->url, session->hsession->uri,
                    session->hsession->uri_buflen);
            }
        }

        header_start = http_event->get_user_agent(header_length);
        if (header_length > 0)
        {
            replace_header_data(&session->hsession->useragent,
                session->hsession->useragent_buflen, header_start, header_length);
            session->scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
        }

        header_start = http_event->get_cookie(header_length);
        replace_header_data(&session->hsession->cookie,
            session->hsession->cookie_buflen, header_start, header_length);

        header_start = http_event->get_referer(header_length);
        replace_header_data(&session->hsession->referer,
            session->hsession->referer_buflen, header_start, header_length);

        header_start = http_event->get_x_working_with(header_length);
        replace_header_data(&session->hsession->x_working_with, tmplen,
            header_start, header_length);

        session->hsession->is_webdav = http_event->contains_webdav_method();

        // FIXIT-M: Should we get request body (may be expensive to copy)?
        //      It is not currently set in callback in 2.9.x, only via
        //      third-party.
    }
    else    // Response headers.
    {
        header_start = http_event->get_content_type(header_length);
        replace_header_data(&session->hsession->content_type,
            session->hsession->content_type_buflen, header_start,
            header_length);

        header_start = http_event->get_location(header_length);
        replace_header_data(&session->hsession->location,
            session->hsession->location_buflen, header_start, header_length);

        header_start = http_event->get_server(header_length);
        replace_header_data(&session->hsession->server, tmplen, header_start,
            header_length);

        int32_t responseCodeNum = http_event->get_response_code();
        if (responseCodeNum > 0 && responseCodeNum < 700)
        {
            unsigned int ret;
            char tmpstr[32];
            ret = snprintf(tmpstr, sizeof(tmpstr), "%d", responseCodeNum);
            if (ret < sizeof(tmpstr))
            {
                snort_free(session->hsession->response_code);
                session->hsession->response_code = snort_strdup(tmpstr);
                session->hsession->response_code_buflen = strlen(tmpstr);
            }
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
        replace_header_data(&session->hsession->via, tmplen, header_start,
            header_length);
        session->scan_flags |= SCAN_HTTP_VIA_FLAG;
    }

    session->hsession->process_http_packet(direction);
    session->set_session_flags(APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_HTTP_SESSION);
    if (direction == APP_ID_FROM_INITIATOR)
        appid_stats.http_flows++;
    session->set_application_ids(session->pick_service_app_id(),
        session->pick_client_app_id(), session->pick_payload_app_id(),
        session->pick_misc_app_id());
}

