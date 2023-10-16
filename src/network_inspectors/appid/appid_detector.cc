//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// appid_detector.cc author davis mcpherson

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_detector.h"

#include "protocols/packet.h"

#include "app_info_table.h"
#include "appid_config.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "lua_detector_api.h"

using namespace snort;

int AppIdDetector::initialize(AppIdInspector& inspector)
{
    if ( !tcp_patterns.empty() )
        for (auto& pat : tcp_patterns)
            handler->register_tcp_pattern(this, pat.pattern, pat.length, pat.index, pat.nocase);

    if ( !udp_patterns.empty() )
        for (auto& pat : udp_patterns)
            handler->register_udp_pattern(this, pat.pattern, pat.length, pat.index, pat.nocase);

    if (!appid_registry.empty())
    {
        AppIdContext& ctxt = inspector.get_ctxt();
        for (auto& id : appid_registry)
            register_appid(id.appId, id.additionalInfo, ctxt.get_odp_ctxt());
      }

    if (!service_ports.empty())
        for (auto& port: service_ports)
            handler->add_service_port(this, port);

    do_custom_init();
    return APPID_SUCCESS;
}

void AppIdDetector::reload()
{
    do_custom_reload();
}

void* AppIdDetector::data_get(AppIdSession& asd)
{
    return asd.get_flow_data(flow_data_index);
}

int AppIdDetector::data_add(AppIdSession& asd, void* data, AppIdFreeFCN fcn)
{
    return asd.add_flow_data(data, flow_data_index, fcn);
}

void AppIdDetector::add_user(AppIdSession& asd, const char* username, AppId appId, bool success,
    AppidChangeBits& change_bits)
{
    asd.set_client_user(appId, username, change_bits);
    if ( success )
        asd.set_user_logged_in();
    else
        asd.clear_user_logged_in();
}

void AppIdDetector::add_payload(AppIdSession& asd, AppId payload_id)
{
    asd.set_payload_id(payload_id);
}

void AppIdDetector::add_app(const Packet& p, AppIdSession& asd, AppidSessionDirection dir, AppId service_id,
    AppId client_id, const char* version, AppidChangeBits& change_bits)
{
    if ( version )
        asd.set_client_version(version, change_bits);

    asd.set_client_detected();
    asd.client_inferred_service_id = service_id;
    asd.set_client_id(p, dir, client_id, change_bits);
}

const char* AppIdDetector::get_code_string(APPID_STATUS_CODE code) const
{
    switch (code)
    {
    case APPID_SUCCESS:
        return "success";
    case APPID_INPROCESS:
        return "in-process";
    case APPID_NEED_REASSEMBLY:
        return "need-reassembly";
    case APPID_NOT_COMPATIBLE:
        return "not-compatible";
    case APPID_INVALID_CLIENT:
        return "invalid-client";
    case APPID_REVERSED:
        return "appid-reversed";
    case APPID_NOMATCH:
        return "no-match";
    case APPID_ENULL:
        return "error-null";
    case APPID_EINVALID:
        return "error-invalid";
    case APPID_ENOMEM:
        return "error-memory";
    }
    return "unknown-code";
}

