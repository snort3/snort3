//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// fw_appid.cc author Sourcefire Inc.

#include "fw_appid.h"

#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/tcp.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#include "appid_stats.h"
#include "appid_module.h"
#include "app_forecast.h"
#include "app_info_table.h"
#include "appid_api.h"
#include "host_port_app_cache.h"
#include "lua_detector_module.h"
#include "client_plugins/client_app_base.h"
#include "detector_plugins/detector_dns.h"
#include "service_plugins/service_base.h"
#include "service_plugins/service_ssl.h"
#include "service_plugins/service_util.h"
#include "appid_utils/common_util.h"
#include "appid_utils/ip_funcs.h"
#include "appid_utils/network_set.h"
#include "time/packet_time.h"
#include "sfip/sf_ip.h"
#include "stream/stream_api.h"

#define HTTP_PATTERN_MAX_LEN    1024
#define PORT_MAX 65535

void dump_appid_stats()
{
    LogMessage("Application Identification Preprocessor:\n");
    LogMessage("   Total packets received : %lu\n", appid_stats.packets);
    LogMessage("  Total packets processed : %lu\n", appid_stats.processed_packets);
    if (thirdparty_appid_module)
        thirdparty_appid_module->print_stats();
    LogMessage("    Total packets ignored : %lu\n", appid_stats.ignored_packets);
    AppIdServiceStateDumpStats();
    RNAPndDumpLuaStats();
}

void reset_appid_stats(int, void*)
{
    if (thirdparty_appid_module)
        thirdparty_appid_module->reset_stats();
}

void fwAppIdFini(AppIdConfig* pConfig)
{
    AppIdSession::release_free_list_flow_data();
    appInfoTableFini(pConfig);
}

unsigned isIPv4HostMonitored(uint32_t ip4, int32_t zone)
{
    NetworkSet* net_list;
    unsigned flags;
    AppIdConfig* pConfig = pAppidActiveConfig;

    if (zone >= 0 && zone < MAX_ZONES && pConfig->net_list_by_zone[zone])
        net_list = pConfig->net_list_by_zone[zone];
    else
        net_list = pConfig->net_list;

    NetworkSet_ContainsEx(net_list, ip4, &flags);
    return flags;
}

void AppIdAddUser(AppIdSession* session, const char* username, AppId appId, int success)
{
    if (session->username)
        snort_free(session->username);
    session->username = snort_strdup(username);
    session->username_service = appId;
    if (success)
        session->setAppIdFlag(APPID_SESSION_LOGIN_SUCCEEDED);
    else
        session->clearAppIdFlag(APPID_SESSION_LOGIN_SUCCEEDED);
}

void AppIdAddDnsQueryInfo(AppIdSession* session, uint16_t id, const uint8_t* host, uint8_t host_len,
        uint16_t host_offset, uint16_t record_type)
{
    if ( session->dsession )
    {
        if ( ( session->dsession->state != 0 ) && ( session->dsession->id != id ) )
            AppIdResetDnsInfo(session);
    }
    else
        session->dsession = (dnsSession*)snort_calloc(sizeof(dnsSession));

    if (session->dsession->state & DNS_GOT_QUERY)
        return;
    session->dsession->state |= DNS_GOT_QUERY;

    session->dsession->id          = id;
    session->dsession->record_type = record_type;

    if (!session->dsession->host)
    {
        if ((host != nullptr) && (host_len > 0) && (host_offset > 0))
        {
            session->dsession->host_len    = host_len;
            session->dsession->host_offset = host_offset;
            session->dsession->host        = dns_parse_host(host, host_len);
        }
    }
}

void AppIdAddDnsResponseInfo(AppIdSession* session, uint16_t id, const uint8_t* host,
        uint8_t host_len, uint16_t host_offset, uint8_t response_type, uint32_t ttl)
{
    if ( session->dsession )
    {
        if ( ( session->dsession->state != 0 ) && ( session->dsession->id != id ) )
            AppIdResetDnsInfo(session);
    }
    else
        session->dsession = (dnsSession*)snort_calloc(sizeof(*session->dsession));

    if (session->dsession->state & DNS_GOT_RESPONSE)
        return;
    session->dsession->state |= DNS_GOT_RESPONSE;

    session->dsession->id            = id;
    session->dsession->response_type = response_type;
    session->dsession->ttl           = ttl;

    if (!session->dsession->host)
    {
        if ((host != nullptr) && (host_len > 0) && (host_offset > 0))
        {
            session->dsession->host_len    = host_len;
            session->dsession->host_offset = host_offset;
            session->dsession->host        = dns_parse_host(host, host_len);
        }
    }
}

void AppIdResetDnsInfo(AppIdSession* session)
{
    if (session->dsession)
    {
        snort_free(session->dsession->host);
        memset(session->dsession, 0, sizeof(*(session->dsession)));
    }
}

void AppIdAddPayload(AppIdSession* session, AppId payload_id)
{
    if (pAppidActiveConfig->mod_config->instance_id)
        checkSandboxDetection(payload_id);
    session->payload_app_id = payload_id;
}


void checkSandboxDetection(AppId appId)
{
    AppInfoTableEntry* entry;
    AppIdConfig* pConfig = pAppidActiveConfig;

    if (pAppidActiveConfig->mod_config->instance_id && pConfig)
    {
        entry = appInfoEntryGet(appId, pConfig);
        if ( entry && ( entry->flags & APPINFO_FLAG_ACTIVE ) )
            fprintf(SF_DEBUG_FILE, "Detected AppId %d\n", entry->appId);
    }
}
