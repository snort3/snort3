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

// client_detector.cc author davis mcpherson

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_detector.h"

#include "log/messages.h"
#include "protocols/packet.h"
#include "sfip/sf_ip.h"

#include "app_info_table.h"
#include "appid_config.h"
#include "appid_session.h"
#include "lua_detector_api.h"

using namespace snort;

static THREAD_LOCAL unsigned service_module_index = 0;

ServiceDetector::ServiceDetector()
{
    flow_data_index = service_module_index++ | APPID_SESSION_DATA_SERVICE_MODSTATE_BIT;
    client = false;
}

void ServiceDetector::register_appid(AppId appId, unsigned extractsInfo, OdpContext& odp_ctxt)
{
    AppInfoTableEntry* pEntry = odp_ctxt.get_app_info_mgr().get_app_info_entry(appId);
    if (!pEntry)
    {
        if ( odp_ctxt.get_app_info_mgr().configured() )
        {
            ParseWarning(WARN_RULES,
                "appid: no entry for %d in appMapping.data; no rule support for this ID.",
                appId);
        }
        return;
    }
    extractsInfo &= (APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_SERVICE_UDP_REVERSED);
    if (!extractsInfo)
        return;
    pEntry->service_detector = this;
    pEntry->flags |= extractsInfo;
}

int ServiceDetector::service_inprocess(AppIdSession& asd, const Packet* pkt, AppidSessionDirection dir)
{
    if (dir == APP_ID_FROM_INITIATOR ||
        asd.get_session_flags(APPID_SESSION_IGNORE_HOST | APPID_SESSION_UDP_REVERSED))
        return APPID_SUCCESS;

    if (!asd.is_service_ip_set())
    {
        uint16_t port = asd.get_service_port();
        asd.set_server_info(*(pkt->ptrs.ip_api.get_src()),
            port ? port : pkt->ptrs.sp, pkt->get_ingress_group());
    }
    return APPID_SUCCESS;
}

int ServiceDetector::update_service_data(AppIdSession& asd, const Packet* pkt,
    AppidSessionDirection dir, AppId appId, const char* vendor, const char* version,
    AppidChangeBits& change_bits, AppIdServiceSubtype* subtype)
{
    uint16_t port = 0;
    const SfIp* ip = nullptr;
    int16_t group;

    asd.service_detector = this;
    asd.set_service_vendor(vendor, change_bits);
    asd.set_service_version(version, change_bits);
    if (subtype)
        asd.add_service_subtype(*subtype, change_bits);
    asd.set_service_detected();
    asd.set_service_id(appId, asd.get_odp_ctxt());

    if (asd.get_session_flags(APPID_SESSION_IGNORE_HOST))
        return APPID_SUCCESS;

    if (!asd.get_session_flags(APPID_SESSION_UDP_REVERSED))
    {
        if (dir == APP_ID_FROM_INITIATOR)
        {
            ip = pkt->ptrs.ip_api.get_dst();
            port = pkt->ptrs.dp;
            group = pkt->get_egress_group();
        }
        else
        {
            ip = pkt->ptrs.ip_api.get_src();
            port = pkt->ptrs.sp;
            group = pkt->get_ingress_group();
        }
        if (asd.get_service_port())
            port = asd.get_service_port();
    }
    else
    {
        if (dir == APP_ID_FROM_INITIATOR)
        {
            ip = pkt->ptrs.ip_api.get_src();
            port = pkt->ptrs.sp;
            group = pkt->get_ingress_group();
        }
        else
        {
            ip = pkt->ptrs.ip_api.get_dst();
            port = pkt->ptrs.dp;
            group = pkt->get_egress_group();
        }
    }

    asd.set_server_info(*ip, port, group);

    ServiceDiscoveryState* sds = AppIdServiceState::add(ip, asd.protocol, port,
        group, asd.asid, asd.is_decrypted());
    sds->set_service_id_valid(this);

    return APPID_SUCCESS;
}

int ServiceDetector::add_service_consume_subtype(AppIdSession& asd, const Packet* pkt,
    AppidSessionDirection dir, AppId appId, const char* vendor, const char* version,
    AppIdServiceSubtype* subtype, AppidChangeBits& change_bits)
{
    return update_service_data(asd, pkt, dir, appId, vendor, version, change_bits, subtype);
}

int ServiceDetector::add_service(AppidChangeBits& change_bits, AppIdSession& asd,
    const Packet* pkt, AppidSessionDirection dir, AppId appId, const char* vendor,
    const char* version, AppIdServiceSubtype* subtype)
{
    AppIdServiceSubtype* new_subtype = nullptr;

    for (; subtype; subtype = subtype->next)
    {
        AppIdServiceSubtype* tmp_subtype = new AppIdServiceSubtype(*subtype);

        tmp_subtype->next = new_subtype;
        new_subtype = tmp_subtype;
    }
    return update_service_data(asd, pkt, dir, appId, vendor, version, change_bits, new_subtype);
}

int ServiceDetector::incompatible_data(AppIdSession& asd, const Packet* pkt, AppidSessionDirection dir)
{
    return static_cast<ServiceDiscovery*>(handler)->incompatible_data(asd, pkt, dir, this);
}

int ServiceDetector::fail_service(AppIdSession& asd, const Packet* pkt, AppidSessionDirection dir)
{
    return static_cast<ServiceDiscovery*>(handler)->fail_service(asd, pkt, dir, this);
}
