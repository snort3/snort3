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

// fw_appid.h author Sourcefire Inc.

#ifndef FW_APPID_H
#define FW_APPID_H

#include "client_plugins/client_app_api.h"
#include "appid_utils/common_util.h"

#include "appid.h"
#include "appid_api.h"
#include "appid_config.h"
#include "appid_session.h"
#include "application_ids.h"
#include "app_info_table.h"
#include "service_plugins/service_api.h"
#include "thirdparty_appid_utils.h"

#define MIN_SFTP_PACKET_COUNT   30
#define MAX_SFTP_PACKET_COUNT   55

extern uint8_t appIdPriorityArray[SF_APPID_MAX + 1];

AppIdSession* getAppIdData(void* lwssn);

void fwAppIdFini(AppIdConfig*);
void AppIdAddUser(AppIdSession*, const char* username, AppId, int success);
void AppIdAddDnsQueryInfo(AppIdSession*, uint16_t id, const uint8_t* host, uint8_t host_len,
        uint16_t host_offset, uint16_t record_type);
void AppIdAddDnsResponseInfo(AppIdSession*, uint16_t id, const uint8_t* host, uint8_t host_len,
        uint16_t host_offset, uint8_t response_type, uint32_t ttl);
void AppIdResetDnsInfo(AppIdSession*);
void AppIdAddPayload(AppIdSession*, AppId);
void dump_appid_stats();

extern unsigned dhcp_fp_table_size;

unsigned isIPv4HostMonitored(uint32_t ip4, int32_t zone);
void checkSandboxDetection(AppId appId);


inline void initializePriorityArray()
{
    for ( int i=0; i < SF_APPID_MAX; ++i )
        appIdPriorityArray[i] = 2;
}

inline void setAppPriority(AppId app_id, uint8_t bit_val)
{
    if ( app_id < SF_APPID_MAX && bit_val <= APPID_MAX_PRIORITY )
        appIdPriorityArray[app_id] = bit_val;
}

inline int getAppPriority(AppId app_id)
{
    if (app_id > APP_ID_NONE && app_id < SF_APPID_MAX)
        return appIdPriorityArray[app_id];

    return -1;
}

inline int ThirdPartyAppIDFoundProto(AppId proto, AppId* proto_list)
{
    unsigned int proto_cnt = 0;
    while (proto_list[proto_cnt] != APP_ID_NONE)
        if (proto_list[proto_cnt++] == proto)
            return 1;       // found

    return 0;            // not found
}

inline int TPIsAppIdDone(void* tpSession)
{
    if (thirdparty_appid_module)
    {
        unsigned state;

        if (tpSession)
            state = thirdparty_appid_module->session_state_get(tpSession);
        else
            state = TP_STATE_INIT;
        return (state  == TP_STATE_CLASSIFIED || state == TP_STATE_TERMINATED || state ==
               TP_STATE_HA);
    }
    return true;
}

inline int TPIsAppIdAvailable(void* tpSession)
{
    if (thirdparty_appid_module)
    {
        unsigned state;

        if (tpSession)
            state = thirdparty_appid_module->session_state_get(tpSession);
        else
            state = TP_STATE_INIT;
        return (state == TP_STATE_CLASSIFIED || state == TP_STATE_TERMINATED || state ==
               TP_STATE_MONITORING);
    }
    return true;
}

inline int testSSLAppIdForReinspect(AppId app_id)
{
    if (app_id <= SF_APPID_MAX &&
            (app_id == APP_ID_SSL ||
                    appInfoEntryFlagGet(app_id, APPINFO_FLAG_SSL_INSPECT, pAppidActiveConfig)))
        return 1;
    else
        return 0;
}

#endif
