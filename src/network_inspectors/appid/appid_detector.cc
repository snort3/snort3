//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// client_detector.cc author davis mcpherson

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_detector.h"

#include "appid_config.h"
#include "appid_http_session.h"
#include "app_info_table.h"
#include "lua_detector_api.h"
#include "protocols/packet.h"

AppIdDetector::AppIdDetector()
{
}

AppIdDetector::~AppIdDetector()
{
}

int AppIdDetector::initialize()
{
    if ( tcp_patterns.size() )
        for (auto& pat : tcp_patterns)
            handler->register_tcp_pattern(this, pat.pattern, pat.length, pat.index, pat.nocase);

    if ( udp_patterns.size() )
        for (auto& pat : udp_patterns)
            handler->register_udp_pattern(this, pat.pattern, pat.length, pat.index, pat.nocase);

    if (appid_registry.size())
        for (auto& id : appid_registry)
            register_appid(id.appId, id.additionalInfo);

    if (service_ports.size())
        for (auto& port: service_ports)
            handler->add_service_port(this, port);

    do_custom_init();
    return APPID_SUCCESS;
}

void* AppIdDetector::data_get(AppIdSession* asd)
{
    return asd->get_flow_data(flow_data_index);
}

int AppIdDetector::data_add(AppIdSession* asd, void* data, AppIdFreeFCN fcn)
{
    return asd->add_flow_data(data, flow_data_index, fcn);
}

void AppIdDetector::add_info(AppIdSession* asd, const char* info)
{
    if (asd->hsession && !asd->hsession->url)
        asd->hsession->url = snort_strdup(info);
}

void AppIdDetector::add_user(AppIdSession* asd, const char* username, AppId appId, bool success)
{
    if (asd->username)
        snort_free(asd->username);
    asd->username = snort_strdup(username);
    asd->username_service = appId;
    if (success)
        asd->set_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
    else
        asd->clear_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
}

void AppIdDetector::add_payload(AppIdSession* asd, AppId payload_id)
{
    asd->payload_app_id = payload_id;
}

void AppIdDetector::add_app(AppIdSession* asd, AppId service_id, AppId id, const char* version)
{
    if (version)
    {
        if (asd->client_version)
        {
            if (strcmp(version, asd->client_version))
            {
                snort_free(asd->client_version);
                asd->client_version = snort_strdup(version);
            }
        }
        else
            asd->client_version = snort_strdup(version);
    }

    asd->set_client_detected();
    asd->client_service_app_id = service_id;
    asd->client_app_id = id;
}

