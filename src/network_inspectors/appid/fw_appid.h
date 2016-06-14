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
#include "util/common_util.h"

#include "appid.h"
#include "appid_api.h"
#include "appid_config.h"
#include "appid_flow_data.h"
#include "application_ids.h"
#include "app_info_table.h"
#include "service_plugins/service_api.h"
#include "thirdparty_appid_utils.h"

#define PP_APP_ID   1

#define MIN_SFTP_PACKET_COUNT   30
#define MAX_SFTP_PACKET_COUNT   55

struct HttpParsedHeaders;
struct Packet;
class AppIdConfig;

extern uint8_t appIdPriorityArray[SF_APPID_MAX+1];

enum ServiceEventType {};

AppIdData* getAppIdData(void* lwssn);

void fwAppIdInit();
void fwAppIdFini(AppIdConfig*);
void fwAppIdSearch(Packet*);
void httpHeaderCallback(Packet*, HttpParsedHeaders* const);
void SipSessionSnortCallback(void* ssnptr, ServiceEventType, void* eventData);

void readRnaAppMappingTable(const char* path, AppIdConfig*);
AppId appGetAppFromServiceId(uint32_t serviceId, AppIdConfig*);
AppId appGetAppFromClientId(uint32_t clientId, AppIdConfig*);
AppId appGetAppFromPayloadId(uint32_t payloadId, AppIdConfig*);
void appSharedDataDelete(AppIdData*);
void AppIdAddUser(AppIdData*, const char* username, AppId, int success);
void AppIdAddDnsQueryInfo(
    AppIdData*,
    uint16_t id,
    const uint8_t* host, uint8_t host_len, uint16_t host_offset,
    uint16_t record_type
);

void AppIdAddDnsResponseInfo(
    AppIdData*,
    uint16_t id,
    const uint8_t* host, uint8_t host_len, uint16_t host_offset,
    uint8_t response_type, uint32_t ttl
);

void AppIdResetDnsInfo(AppIdData*);

void AppIdAddPayload(AppIdData*, AppId);
AppIdData* appSharedDataAlloc(IpProtocol proto, const sfip_t*);
AppId getOpenAppId(void* ssnptr);

void appSetServiceValidator(
    RNAServiceValidationFCN, AppId, unsigned extractsInfo, AppIdConfig*);

void appSetLuaServiceValidator(
    RNAServiceValidationFCN, AppId, unsigned extractsInfo, Detector* dat);

void appSetClientValidator(
    RNAClientAppFCN, AppId, unsigned extractsInfo, AppIdConfig*);

void appSetLuaClientValidator(
    RNAClientAppFCN, AppId, unsigned extractsInfo, Detector* data);

int sslAppGroupIdLookup(
    void* ssnptr,
    const char* serverName,
    const char* commonName,
    AppId* serviceAppId,
    AppId* ClientAppId,
    AppId* payloadAppId
);

AppId getAppId(void* ssnptr);

#ifdef FW_TRACKER_DEBUG
void logAppIdInfo(SFSnortPacket* p, char* message, AppId id);
#endif
int AppIdDebug(
    uint16_t type,
    const uint8_t* data,
    uint32_t length,
    void** new_context,
    char* statusBuf,
    int statusBuf_len
);

extern char app_id_debug_session[FW_DEBUG_SESSION_ID_SIZE];
extern bool app_id_debug_session_flag;

extern ProfileStats httpPerfStats;
extern ProfileStats clientMatchPerfStats;
extern ProfileStats serviceMatchPerfStats;
extern ProfileStats luaDetectorsPerfStats;
extern ProfileStats tpPerfStats;
extern ProfileStats tpLibPerfStats;

extern unsigned dhcp_fp_table_size;
extern unsigned long app_id_raw_packet_count;
extern unsigned long app_id_processed_packet_count;
extern unsigned long app_id_ignored_packet_count;
extern int app_id_debug;
extern unsigned isIPv4HostMonitored(uint32_t ip4, int32_t zone);
extern void checkSandboxDetection(AppId appId);

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

inline AppId isAppDetectionDone(AppIdData* flow)
{ return getAppIdFlag(flow, APPID_SESSION_SERVICE_DETECTED); }

inline AppId pickServiceAppId(AppIdData* flow)
{
    AppId rval;

    if (!flow || flow->common.fsf_type.flow_type != APPID_SESSION_TYPE_NORMAL)
        return APP_ID_NONE;

    if (getAppIdFlag(flow, APPID_SESSION_SERVICE_DETECTED))
    {
        bool deferred = appInfoEntryFlagGet(flow->serviceAppId, APPINFO_FLAG_DEFER, pAppidActiveConfig)
                || appInfoEntryFlagGet(flow->tpAppId, APPINFO_FLAG_DEFER, pAppidActiveConfig);

        if (flow->serviceAppId > APP_ID_NONE && !deferred)
            return flow->serviceAppId;
        if (TPIsAppIdAvailable(flow->tpsession))
        {
            if (flow->tpAppId > APP_ID_NONE)
                return flow->tpAppId;
            else if (deferred)
                return flow->serviceAppId;
            else
                rval = APP_ID_UNKNOWN_UI;
        }
        else
            rval = flow->tpAppId;
    }
    else if (flow->tpAppId > APP_ID_NONE)
        return flow->tpAppId;
    else
        rval = APP_ID_NONE;

    if (flow->ClientServiceAppId > APP_ID_NONE)
        return flow->ClientServiceAppId;

    if (flow->portServiceAppId > APP_ID_NONE)
        return flow->portServiceAppId;

    return rval;
}

inline AppId pickOnlyServiceAppId(AppIdData* flow)
{
    if (!flow || flow->common.fsf_type.flow_type != APPID_SESSION_TYPE_NORMAL)
        return APP_ID_NONE;

    bool deferred = appInfoEntryFlagGet(flow->serviceAppId, APPINFO_FLAG_DEFER,  pAppidActiveConfig)
            || appInfoEntryFlagGet(flow->tpAppId, APPINFO_FLAG_DEFER, pAppidActiveConfig);

    if (flow->serviceAppId > APP_ID_NONE && !deferred)
        return flow->serviceAppId;

    if (TPIsAppIdAvailable(flow->tpsession) && flow->tpAppId > APP_ID_NONE)
        return flow->tpAppId;
    else if (deferred)
        return flow->serviceAppId;

    if (flow->serviceAppId < APP_ID_NONE)
        return APP_ID_UNKNOWN_UI;

    return APP_ID_NONE;
}

inline AppId pickMiscAppId(AppIdData* flow)
{
    if (!flow || flow->common.fsf_type.flow_type != APPID_SESSION_TYPE_NORMAL)
        return APP_ID_NONE;
    if (flow->miscAppId > APP_ID_NONE)
        return flow->miscAppId;
    return APP_ID_NONE;
}

inline AppId pickClientAppId(AppIdData* flow)
{
    if (!flow || flow->common.fsf_type.flow_type != APPID_SESSION_TYPE_NORMAL)
        return APP_ID_NONE;
    if (flow->ClientAppId > APP_ID_NONE)
        return flow->ClientAppId;
    return APP_ID_NONE;
}

inline AppId pickPayloadId(AppIdData* flow)
{
    if (!flow || flow->common.fsf_type.flow_type != APPID_SESSION_TYPE_NORMAL)
        return APP_ID_NONE;

    // if we have a deferred payload, just use it.
    // we are not worried about the APP_ID_UNKNOWN case here
    if (appInfoEntryFlagGet(flow->tpPayloadAppId, APPINFO_FLAG_DEFER_PAYLOAD, pAppidActiveConfig))
        return flow->tpPayloadAppId;
    else if (flow->payloadAppId > APP_ID_NONE)
        return flow->payloadAppId;
    else if (flow->tpPayloadAppId > APP_ID_NONE)
        return flow->tpPayloadAppId;

    return APP_ID_NONE;
}

inline AppId pickReferredPayloadId(AppIdData* flow)
{
    if (!flow || flow->common.fsf_type.flow_type != APPID_SESSION_TYPE_NORMAL)
        return APP_ID_NONE;
    if (flow->referredPayloadAppId > APP_ID_NONE)
        return flow->referredPayloadAppId;
    return APP_ID_NONE;
}

inline AppId fwPickServiceAppId(AppIdData* session)
{
    AppId appId;
    appId = pickServiceAppId(session);
    if (appId == APP_ID_NONE)
        appId = session->encrypted.serviceAppId;
    return appId;
}

inline AppId fwPickMiscAppId(AppIdData* session)
{
    AppId appId;
    appId = pickMiscAppId(session);
    if (appId == APP_ID_NONE)
        appId = session->encrypted.miscAppId;
    return appId;
}

inline AppId fwPickClientAppId(AppIdData* session)
{
    AppId appId;
    appId = pickClientAppId(session);
    return appId;
}

inline AppId fwPickPayloadAppId(AppIdData* session)
{
    AppId appId;
    appId = pickPayloadId(session);
    if (appId == APP_ID_NONE)
        appId = session->encrypted.payloadAppId;
    return appId;
}

inline AppId fwPickReferredPayloadAppId(AppIdData* session)
{
    AppId appId;
    appId = pickReferredPayloadId(session);
    if (appId == APP_ID_NONE)
        appId = session->encrypted.referredAppId;
    return appId;
}

inline AppIdData* appSharedGetData(const Packet* p)
{
    if ( p && p->flow )
        return (AppIdData*)p->flow->get_application_data(AppIdData::flow_id);

    return nullptr;
}

inline unsigned int isFwSessionSslDecrypted(AppIdData* session)
{
    return getAppIdFlag(session, APPID_SESSION_DECRYPTED);
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
