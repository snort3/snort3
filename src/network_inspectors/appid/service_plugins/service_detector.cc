//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

void ServiceDetector::register_appid(AppId appId, unsigned extractsInfo)
{
    AppInfoTableEntry* pEntry = AppInfoManager::get_instance().get_app_info_entry(appId);
    if (!pEntry)
    {
        if ( AppInfoManager::get_instance().configured() )
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

    if (!asd.service_ip.is_set())
    {
        asd.service_ip = *(pkt->ptrs.ip_api.get_src());
        if (!asd.service_port)
            asd.service_port = pkt->ptrs.sp;
    }

    return APPID_SUCCESS;
}

int ServiceDetector::update_service_data(AppIdSession& asd, const Packet* pkt, AppidSessionDirection dir, AppId appId,
    const char* vendor, const char* version)
{
    uint16_t port = 0;
    const SfIp* ip = nullptr;

    asd.service_detector = this;
    asd.service.set_vendor(vendor);
    asd.service.set_version(version);
    asd.set_service_detected();
    asd.service.set_id(appId);

    if (asd.get_session_flags(APPID_SESSION_IGNORE_HOST))
        return APPID_SUCCESS;

    if (!asd.get_session_flags(APPID_SESSION_UDP_REVERSED))
    {
        if (dir == APP_ID_FROM_INITIATOR)
        {
            ip = pkt->ptrs.ip_api.get_dst();
            port = pkt->ptrs.dp;
        }
        else
        {
            ip = pkt->ptrs.ip_api.get_src();
            port = pkt->ptrs.sp;
        }
        if (asd.service_port)
            port = asd.service_port;
    }
    else
    {
        if (dir == APP_ID_FROM_INITIATOR)
        {
            ip = pkt->ptrs.ip_api.get_src();
            port = pkt->ptrs.sp;
        }
        else
        {
            ip = pkt->ptrs.ip_api.get_dst();
            port = pkt->ptrs.dp;
        }
    }

    asd.service_ip = *ip;
    asd.service_port = port;
    ServiceDiscoveryState* sds = AppIdServiceState::add(ip, asd.protocol, port, asd.is_decrypted());
    sds->set_service_id_valid(this);

    return APPID_SUCCESS;
}

int ServiceDetector::add_service_consume_subtype(AppIdSession& asd, const Packet* pkt,
    AppidSessionDirection dir, AppId appId, const char* vendor, const char* version,
    AppIdServiceSubtype* subtype)
{
    asd.subtype = subtype;
    return update_service_data(asd, pkt, dir, appId, vendor, version);
}

int ServiceDetector::add_service(AppIdSession& asd, const Packet* pkt, AppidSessionDirection dir,
    AppId appId, const char* vendor, const char* version, const AppIdServiceSubtype* subtype)
{
    AppIdServiceSubtype* new_subtype = nullptr;

    for (; subtype; subtype = subtype->next)
    {
        AppIdServiceSubtype* tmp_subtype = (AppIdServiceSubtype*)snort_calloc(
            sizeof(AppIdServiceSubtype));
        if (subtype->service)
            tmp_subtype->service = snort_strdup(subtype->service);

        if (subtype->vendor)
            tmp_subtype->vendor = snort_strdup(subtype->vendor);

        if (subtype->version)
            tmp_subtype->version = snort_strdup(subtype->version);

        tmp_subtype->next = new_subtype;
        new_subtype = tmp_subtype;
    }
    asd.subtype = new_subtype;
    return update_service_data(asd, pkt, dir, appId, vendor, version);
}

int ServiceDetector::incompatible_data(AppIdSession& asd, const Packet* pkt, AppidSessionDirection dir)
{
    return static_cast<ServiceDiscovery*>(handler)->incompatible_data(asd, pkt, dir, this);
}

int ServiceDetector::fail_service(AppIdSession& asd, const Packet* pkt, AppidSessionDirection dir)
{
    return static_cast<ServiceDiscovery*>(handler)->fail_service(asd, pkt, dir, this);
}

void ServiceDetector::initialize_expected_session(AppIdSession& parent, AppIdSession& expected,
    uint64_t flags, AppidSessionDirection dir)
{
    if (dir == APP_ID_FROM_INITIATOR)
    {
        expected.set_session_flags(flags |
            parent.get_session_flags(
            APPID_SESSION_INITIATOR_CHECKED |
            APPID_SESSION_INITIATOR_MONITORED |
            APPID_SESSION_RESPONDER_CHECKED |
            APPID_SESSION_RESPONDER_MONITORED));
    }
    else if (dir == APP_ID_FROM_RESPONDER)
    {
        if (parent.get_session_flags(APPID_SESSION_INITIATOR_CHECKED))
            flags |= APPID_SESSION_RESPONDER_CHECKED;

        if (parent.get_session_flags(APPID_SESSION_INITIATOR_MONITORED))
            flags |= APPID_SESSION_RESPONDER_MONITORED;

        if (parent.get_session_flags(APPID_SESSION_RESPONDER_CHECKED))
            flags |= APPID_SESSION_INITIATOR_CHECKED;

        if (parent.get_session_flags(APPID_SESSION_RESPONDER_MONITORED))
            flags |= APPID_SESSION_INITIATOR_MONITORED;
    }

    expected.set_session_flags(flags |
        parent.get_session_flags(
        APPID_SESSION_SPECIAL_MONITORED |
        APPID_SESSION_DISCOVER_APP |
        APPID_SESSION_DISCOVER_USER));

    expected.service_disco_state = APPID_DISCO_STATE_FINISHED;
    expected.client_disco_state = APPID_DISCO_STATE_FINISHED;
}
