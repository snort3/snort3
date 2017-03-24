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

#include "service_detector.h"

#include "appid_config.h"
#include "app_info_table.h"
#include "appid_session.h"
#include "lua_detector_api.h"

#include "protocols/packet.h"
#include "main/snort_debug.h"
#include "log/messages.h"
#include "sfip/sf_ip.h"

static THREAD_LOCAL unsigned service_module_index = 0;

ServiceDetector::ServiceDetector()
{
    flow_data_index = service_module_index++ | APPID_SESSION_DATA_SERVICE_MODSTATE_BIT;
}

int ServiceDetector::validate(AppIdDiscoveryArgs&)
{
    return APPID_SUCCESS;
}

void ServiceDetector::register_appid(AppId appId, unsigned extractsInfo)
{
    AppInfoTableEntry* pEntry = AppInfoManager::get_instance().get_app_info_entry(appId);
    if (!pEntry)
    {
        ParseWarning(WARN_RULES,
            "AppId: ID to Name mapping entry missing for AppId: %d. No rule support for this ID.",
            appId);
        return;
    }
    extractsInfo &= (APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_SERVICE_UDP_REVERSED);
    if (!extractsInfo)
    {
        DebugFormat(DEBUG_APPID, "Ignoring direct service without info for AppId %d", appId);
        return;
    }
    pEntry->service_detector = this;
    pEntry->flags |= extractsInfo;
}

int ServiceDetector::service_inprocess(AppIdSession* asd, const Packet* pkt, int dir)
{
    if (dir == APP_ID_FROM_INITIATOR ||
        asd->get_session_flags(APPID_SESSION_IGNORE_HOST | APPID_SESSION_UDP_REVERSED))
        return APPID_SUCCESS;

    const SfIp* ip = pkt->ptrs.ip_api.get_src();
    uint16_t port = asd->service_port ? asd->service_port : pkt->ptrs.sp;
    ServiceDiscoveryState* id_state = AppIdServiceState::get(ip, asd->protocol, port,
        get_service_detect_level(asd));
    if ( !id_state )
    {
        id_state = AppIdServiceState::add(ip, asd->protocol, port, get_service_detect_level(asd));
        id_state->state = SERVICE_ID_NEW;
        id_state->service = this;
        asd->service_ip = *ip;
        asd->service_port = port;
    }
    else
    {
        if (!asd->service_ip.is_set())
        {
            asd->service_ip = *(pkt->ptrs.ip_api.get_src());
            if (!asd->service_port)
                asd->service_port = pkt->ptrs.sp;
        }
    }

    APPID_LOG_IP_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,asd->service_ip,
        "Inprocess: %s:%u:%u %p %d\n", ipstr,
        (unsigned)asd->protocol, (unsigned)asd->service_port, (void*)id_state,
        (int)id_state->state);

    APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
        "Service for protocol %u on port %u is in process (%u->%u), %s\n",
        (unsigned)asd->protocol, (unsigned)asd->service_port, (unsigned)pkt->ptrs.sp,
        (unsigned)pkt->ptrs.dp,
        svc_element->name ? svc_element->name : "UNKNOWN");

    return APPID_SUCCESS;
}

int ServiceDetector::add_service(AppIdSession* asd, const Packet* pkt, int dir, AppId appId,
    const char* vendor, const char* version)
{
    ServiceDiscoveryState* id_state = nullptr;
    uint16_t port = 0;
    const SfIp* ip = nullptr;

    asd->service_detector = this;

    if (vendor)
    {
        if (asd->serviceVendor)
            snort_free(asd->serviceVendor);
        asd->serviceVendor = snort_strdup(vendor);
    }
    if (version)
    {
        if (asd->serviceVersion)
            snort_free(asd->serviceVersion);
        asd->serviceVersion = snort_strdup(version);
    }
    asd->set_session_flags(APPID_SESSION_SERVICE_DETECTED);
    asd->serviceAppId = appId;

    if (asd->get_session_flags(APPID_SESSION_IGNORE_HOST))
        return APPID_SUCCESS;

    if (!asd->get_session_flags(APPID_SESSION_UDP_REVERSED))
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
        if (asd->service_port)
            port = asd->service_port;
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

    // If UDP reversed, ensure we have the correct host tracker entry.
    if (asd->get_session_flags(APPID_SESSION_UDP_REVERSED))
        id_state = AppIdServiceState::get(ip, asd->protocol, port, get_service_detect_level(asd));

    if ( !id_state )
    {
        id_state = AppIdServiceState::add(ip, asd->protocol, port, get_service_detect_level(asd));
        asd->service_ip = *ip;
        asd->service_port = port;
    }
    else
    {
        if (!asd->service_ip.is_set())
        {
            asd->service_ip = *ip;
            asd->service_port = port;
        }

        APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
            "Service %d for protocol %u on port %u (%u->%u) is valid\n",
            (int)appId, (unsigned)asd->protocol, (unsigned)asd->service_port,
            (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp);
    }
    id_state->reset_time = 0;
    if (id_state->state != SERVICE_ID_VALID)
    {
        id_state->state = SERVICE_ID_VALID;
        id_state->valid_count = 0;
        id_state->detract_count = 0;
        id_state->last_detract.clear();
        id_state->invalid_client_count = 0;
        id_state->last_invalid_client.clear();
    }
    id_state->service = this;

    APPID_LOG_IP_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp, asd->service_ip,
        "Valid: %s:%u:%u %p %d\n",
        ipstr, (unsigned)asd->protocol, (unsigned)asd->service_port,
        (void*)id_state, (int)id_state->state);

    if (!id_state->valid_count)
    {
        id_state->valid_count++;
        id_state->invalid_client_count = 0;
        id_state->last_invalid_client.clear();
        id_state->detract_count = 0;
        id_state->last_detract.clear();
    }
    else if (id_state->valid_count < STATE_ID_MAX_VALID_COUNT)
        id_state->valid_count++;

    /* Done looking for this session. */
    id_state->searching = false;

    APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
        "Service %d for protocol %u on port %u (%u->%u) is valid\n",
        (int)appId, (unsigned)asd->protocol, (unsigned)asd->service_port,
        (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp);
    return APPID_SUCCESS;
}

int ServiceDetector::add_service_consume_subtype(AppIdSession* asd, const Packet* pkt, int dir,
    AppId appId, const char* vendor, const char* version, RNAServiceSubtype* subtype)
{
    asd->subtype = subtype;
    if (!current_ref_count)
    {
        APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
            "Service %d for protocol %u on port %u (%u->%u) is valid, but skipped\n",
            (int)appId, (unsigned)asd->protocol, (unsigned)asd->service_port,
            (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp);
        return APPID_SUCCESS;
    }
    return add_service(asd, pkt, dir, appId, vendor, version);
}

int ServiceDetector::add_service(AppIdSession* asd, const Packet* pkt, int dir, AppId appId,
    const char* vendor, const char* version, const RNAServiceSubtype* subtype)
{
    RNAServiceSubtype* new_subtype = nullptr;

    if (!current_ref_count)
    {
        APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
            "Service %d for protocol %u on port %u (%u->%u) is valid, but skipped\n",
            (int)appId, (unsigned)asd->protocol, (unsigned)asd->service_port,
            (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp);
        return APPID_SUCCESS;
    }

    for (; subtype; subtype = subtype->next)
    {
        RNAServiceSubtype* tmp_subtype = (RNAServiceSubtype*)snort_calloc(
            sizeof(RNAServiceSubtype));
        if (subtype->service)
            tmp_subtype->service = snort_strdup(subtype->service);

        if (subtype->vendor)
            tmp_subtype->vendor = snort_strdup(subtype->vendor);

        if (subtype->version)
            tmp_subtype->version = snort_strdup(subtype->version);

        tmp_subtype->next = new_subtype;
        new_subtype = tmp_subtype;
    }
    asd->subtype = new_subtype;
    return add_service(asd, pkt, dir, appId, vendor, version);
}

int ServiceDetector::incompatible_data(AppIdSession* asd, const Packet* pkt, int dir)
{
    return static_cast<ServiceDiscovery*>(handler)->incompatible_data(asd, pkt, dir, this);
}

int ServiceDetector::fail_service(AppIdSession* asd, const Packet* pkt, int dir)
{
    return static_cast<ServiceDiscovery*>(handler)->fail_service(asd, pkt, dir, this);
}

void ServiceDetector::PopulateExpectedFlow(AppIdSession* parent,
    AppIdSession* expected, uint64_t flags)
{
    expected->set_session_flags(flags |
        parent->get_session_flags(APPID_SESSION_RESPONDER_MONITORED |
        APPID_SESSION_INITIATOR_MONITORED |
        APPID_SESSION_SPECIAL_MONITORED |
        APPID_SESSION_RESPONDER_CHECKED |
        APPID_SESSION_INITIATOR_CHECKED |
        APPID_SESSION_DISCOVER_APP |
        APPID_SESSION_DISCOVER_USER));
    expected->rna_service_state = RNA_STATE_FINISHED;
    expected->rna_client_state = RNA_STATE_FINISHED;
}

