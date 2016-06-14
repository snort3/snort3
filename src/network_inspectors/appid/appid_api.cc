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

// appid_api.cc author Sourcefire Inc.

#include "appid_api.h"

#include "appid.h"
#include "service_plugins/service_base.h"
#include "app_info_table.h"
#include "fw_appid.h"

#include "utils/util.h"

#define SSL_WHITELIST_PKT_LIMIT 20

AppId getServiceAppId(AppIdData* appIdData)
{
    if (appIdData)
        return pickServiceAppId(appIdData);

    return APP_ID_NONE;
}

AppId getOnlyServiceAppId(AppIdData* appIdData)
{
    if (appIdData)
        return pickOnlyServiceAppId(appIdData);

    return APP_ID_NONE;
}

AppId getMiscAppId(AppIdData* appIdData)
{
    if (appIdData)
        return pickMiscAppId(appIdData);

    return APP_ID_NONE;
}

AppId getClientAppId(AppIdData* appIdData)
{
    if (appIdData)
        return pickClientAppId(appIdData);

    return APP_ID_NONE;
}

AppId getPayloadAppId(AppIdData* appIdData)
{
    if (appIdData)
        return pickPayloadId(appIdData);

    return APP_ID_NONE;
}

AppId getReferredAppId(AppIdData* appIdData)
{
    if (appIdData)
        return pickReferredPayloadId(appIdData);

    return APP_ID_NONE;
}

AppId getFwServiceAppId(AppIdData* appIdData)
{
    if (appIdData)
        return fwPickServiceAppId(appIdData);

    return APP_ID_NONE;
}

AppId getFwMiscAppId(AppIdData* appIdData)
{
    if (appIdData)
        return fwPickMiscAppId(appIdData);

    return APP_ID_NONE;
}

AppId getFwClientAppId(AppIdData* appIdData)
{
    if (appIdData)
        return fwPickClientAppId(appIdData);

    return APP_ID_NONE;
}

AppId getFwPayloadAppId(AppIdData* appIdData)
{
    if (appIdData)
        return fwPickPayloadAppId(appIdData);

    return APP_ID_NONE;
}

AppId getFwReferredAppId(AppIdData* appIdData)
{
    if (appIdData)
        return fwPickReferredPayloadAppId(appIdData);

    return APP_ID_NONE;
}

bool isSessionSslDecrypted(AppIdData* appIdData)
{
    if (appIdData)
        return isFwSessionSslDecrypted(appIdData);

    return false;
}

AppIdData* getAppIdData(void* lwssn)
{
    AppIdData* appIdData = (AppIdData*)(((Flow*)lwssn)->get_application_data(AppIdData::flow_id));

    return (appIdData && appIdData->common.fsf_type.flow_type == APPID_SESSION_TYPE_NORMAL) ?
           appIdData : nullptr;
}

bool IsAppIdInspectingSession(AppIdData* appIdSession)
{
    if (appIdSession && appIdSession->common.fsf_type.flow_type == APPID_SESSION_TYPE_NORMAL)
    {
        if (appIdSession->rnaServiceState != RNA_STATE_FINISHED ||
            !TPIsAppIdDone(appIdSession->tpsession) ||
            getAppIdFlag(appIdSession, APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE) ||
            (getAppIdFlag(appIdSession, APPID_SESSION_ENCRYPTED) &&
            (getAppIdFlag(appIdSession, APPID_SESSION_DECRYPTED) ||
            appIdSession->session_packet_count < SSL_WHITELIST_PKT_LIMIT)))
        {
            return true;
        }
        if (appIdSession->rnaClientState != RNA_STATE_FINISHED &&
            (!getAppIdFlag(appIdSession, APPID_SESSION_CLIENT_DETECTED) ||
            (appIdSession->rnaServiceState != RNA_STATE_STATEFUL && getAppIdFlag(appIdSession,
            APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))))
        {
            return true;
        }
        if (appIdSession->tpAppId == APP_ID_SSH && appIdSession->payloadAppId != APP_ID_SFTP &&
            appIdSession->session_packet_count < MAX_SFTP_PACKET_COUNT)
        {
            return true;
        }
    }
    return false;
}

char* getUserName(AppIdData* appIdData, AppId* service, bool* isLoginSuccessful)
{
    char* userName = nullptr;
    if (appIdData)
    {
        userName = appIdData->username;
        *service = appIdData->usernameService;
        *isLoginSuccessful = getAppIdFlag(appIdData, APPID_SESSION_LOGIN_SUCCEEDED) ? true : false;
        appIdData->username = nullptr; //transfer ownership to caller.
        return userName;
    }
    return nullptr;
}

bool isAppIdAvailable(AppIdData* appIdData)
{
    if (appIdData)
    {
        if (getAppIdFlag(appIdData, APPID_SESSION_NO_TPI))
            return true;
        return TPIsAppIdAvailable(appIdData->tpsession);
    }
    return false;
}

char* getClientVersion(AppIdData* appIdData)
{
    return appIdData ? appIdData->clientVersion : nullptr;
}

uint64_t getAppIdSessionAttribute(AppIdData* appIdData, uint64_t flags)
{
    return appIdData ? getAppIdFlag(appIdData, flags) : 0;
}

APPID_FLOW_TYPE getFlowType(AppIdData* appIdData)
{
    return appIdData ? appIdData->common.fsf_type.flow_type : APPID_FLOW_TYPE_IGNORE;
}

void getServiceInfo(AppIdData* appIdData, char** serviceVendor, char** serviceVersion,
    RNAServiceSubtype** serviceSubtype)
{
    if (appIdData)
    {
        *serviceVendor = appIdData->serviceVendor;
        *serviceVersion = appIdData->serviceVersion;
        *serviceSubtype = appIdData->subtype;
    }
    else
    {
        *serviceVendor = nullptr;
        *serviceVersion = nullptr;
        *serviceSubtype = nullptr;
    }
}

short getServicePort(AppIdData* appIdData)
{
    if (appIdData)
        return appIdData->service_port;
    return 0;
}

char* getHttpUserAgent(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->useragent;
    return nullptr;
}

char* getHttpHost(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->host;
    return nullptr;
}

char* getHttpUrl(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->url;
    return nullptr;
}

char* getHttpReferer(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->referer;
    return nullptr;
}

char* getHttpNewUrl(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->new_field[REQ_URI_FID];
    return nullptr;
}

char* getHttpUri(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->uri;
    return nullptr;
}

char* getHttpResponseCode(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->response_code;
    return nullptr;
}

char* getHttpCookie(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->cookie;
    return nullptr;
}

char* getHttpNewCookie(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->new_field[REQ_COOKIE_FID];
    return nullptr;
}

char* getHttpNewField(AppIdData* appIdData, HTTP_FIELD_ID fieldId)
{
    if (appIdData && appIdData->hsession && fieldId >= 0 && fieldId <= HTTP_FIELD_MAX)
        return appIdData->hsession->new_field[fieldId];
    return nullptr;
}

void freeHttpNewField(AppIdData* appIdData, HTTP_FIELD_ID fieldId)
{
    if (appIdData && appIdData->hsession && fieldId >= 0 && fieldId <= HTTP_FIELD_MAX &&
        nullptr != appIdData->hsession->new_field[fieldId])
    {
        snort_free(appIdData->hsession->new_field[fieldId]);
        appIdData->hsession->new_field[fieldId] = nullptr;
    }
}

char* getHttpContentType(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->content_type;
    return nullptr;
}

char* getHttpLocation(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->location;
    return nullptr;
}

char* getHttpBody(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->body;
    return nullptr;
}

char* getHttpReqBody(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->req_body;
    return nullptr;
}

uint16_t getHttpUriOffset(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->uriOffset;
    return 0;
}

uint16_t getHttpUriEndOffset(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->uriEndOffset;
    return 0;
}

uint16_t getHttpCookieOffset(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->cookieOffset;
    return 0;
}

uint16_t getHttpCookieEndOffset(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->cookieEndOffset;
    return 0;
}

SEARCH_SUPPORT_TYPE getHttpSearch(AppIdData* appIdData)
{
    if (appIdData)
        return (appIdData->search_support_type != SEARCH_SUPPORT_TYPE_UNKNOWN) ?
               appIdData->search_support_type : NOT_A_SEARCH_ENGINE;
    return NOT_A_SEARCH_ENGINE;
}

// FIXIT used to be sfaddr_t
sfip_t* getHttpXffAddr(AppIdData* appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->xffAddr;
    return nullptr;
}

char* getTlsHost(AppIdData* appIdData)
{
    if (appIdData && appIdData->tsession)
        return appIdData->tsession->tls_host;
    return nullptr;
}

AppId getPorServiceAppId(AppIdData* appIdData)
{
    if (appIdData)
        return appIdData->portServiceAppId;
    return APP_ID_NONE;
}

// FIXIT used to be sfaddr_t
sfip_t* getServiceIp(AppIdData* appIdData)
{
    if (appIdData)
        return &appIdData->service_ip;
    return nullptr;
}

// FIXIT used to be sfaddr_t
sfip_t* getInitiatorIp(AppIdData* appIdData)
{
    return appIdData ? &appIdData->common.initiator_ip : nullptr;
}

DhcpFPData* getDhcpFpData(AppIdData* appIdData)
{
    if (appIdData && getAppIdFlag(appIdData, APPID_SESSION_HAS_DHCP_FP))
        return static_cast<DhcpFPData*>(
            AppIdFlowdataRemove(appIdData, APPID_SESSION_DATA_DHCP_FP_DATA));

    return nullptr;
}

void freeDhcpFpData(AppIdData* appIdData, DhcpFPData* data)
{
    if (appIdData)
    {
        clearAppIdFlag(appIdData, APPID_SESSION_HAS_DHCP_FP);
        AppIdFreeDhcpData(data);
    }
}

DHCPInfo* getDhcpInfo(AppIdData* appIdData)
{
    if (appIdData && getAppIdFlag(appIdData, APPID_SESSION_HAS_DHCP_INFO))
        return static_cast<DHCPInfo*>(
            AppIdFlowdataRemove(appIdData, APPID_SESSION_DATA_DHCP_INFO));

    return nullptr;
}

void freeDhcpInfo(AppIdData* appIdData, DHCPInfo* data)
{
    if (appIdData)
    {
        clearAppIdFlag(appIdData, APPID_SESSION_HAS_DHCP_INFO);
        AppIdFreeDhcpInfo(data);
    }
}

FpSMBData* getSmbFpData(AppIdData* appIdData)
{
    if (appIdData && getAppIdFlag(appIdData, APPID_SESSION_HAS_SMB_INFO))
        return static_cast<FpSMBData*>(
            AppIdFlowdataRemove(appIdData, APPID_SESSION_DATA_SMB_DATA));

    return nullptr;
}

void freeSmbFpData(AppIdData* appIdData, FpSMBData* data)
{
    if (appIdData)
    {
        clearAppIdFlag(appIdData, APPID_SESSION_HAS_SMB_INFO);
        AppIdFreeSMBData(data);
    }
}

char* getNetbiosName(AppIdData* appIdData)
{
    if (appIdData)
    {
        char* netbiosName = appIdData->netbios_name;
        appIdData->netbios_name = nullptr; //transfer ownership to caller.
        return netbiosName;
    }
    return nullptr;
}

#define APPID_HA_FLAGS_APP (1<<0)
#define APPID_HA_FLAGS_TP_DONE (1<<1)
#define APPID_HA_FLAGS_SVC_DONE (1<<2)
#define APPID_HA_FLAGS_HTTP (1<<3)

uint32_t produceHAState(void* lwssn, uint8_t* buf)
{
    AppIdSessionHA* appHA = (AppIdSessionHA*)buf;
    AppIdData* appIdData = (AppIdData*)(((Flow*)lwssn)->get_application_data(AppIdData::flow_id));

    // FIXIT - getFlowType should be a class member
    if (appIdData && getFlowType(appIdData) != APPID_FLOW_TYPE_NORMAL)
        appIdData = nullptr;
    if (appIdData)
    {
        appHA->flags = APPID_HA_FLAGS_APP;
        if (TPIsAppIdAvailable(appIdData->tpsession))
            appHA->flags |= APPID_HA_FLAGS_TP_DONE;
        if (getAppIdFlag(appIdData, APPID_SESSION_SERVICE_DETECTED))
            appHA->flags |= APPID_HA_FLAGS_SVC_DONE;
        if (getAppIdFlag(appIdData, APPID_SESSION_HTTP_SESSION))
            appHA->flags |= APPID_HA_FLAGS_HTTP;
        appHA->appId[0] = appIdData->tpAppId;
        appHA->appId[1] = appIdData->serviceAppId;
        appHA->appId[2] = appIdData->ClientServiceAppId;
        appHA->appId[3] = appIdData->portServiceAppId;
        appHA->appId[4] = appIdData->payloadAppId;
        appHA->appId[5] = appIdData->tpPayloadAppId;
        appHA->appId[6] = appIdData->ClientAppId;
        appHA->appId[7] = appIdData->miscAppId;
    }
    else
    {
        memset(appHA->appId, 0, sizeof(appHA->appId));
    }
    return sizeof(*appHA);
}

// FIXIT last arg used to be sfaddr_t
uint32_t consumeHAState(void* lwssn, const uint8_t* buf, uint8_t, IpProtocol proto,
    sfip_t* ip)
{
    AppIdSessionHA* appHA = (AppIdSessionHA*)buf;
    if (appHA->flags & APPID_HA_FLAGS_APP)
    {
        AppIdData* appIdData = (AppIdData*)(((Flow*)lwssn)->get_application_data(
            AppIdData::flow_id));

        if (!appIdData)
        {
            appIdData = appSharedDataAlloc(proto, ip);
            ((Flow*)lwssn)->set_application_data(appIdData);
            if (appIdData->serviceAppId == APP_ID_FTP_CONTROL)
            {
                setAppIdFlag(appIdData, APPID_SESSION_CLIENT_DETECTED |
                    APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_SERVICE_DETECTED);
                if (!AddFTPServiceState(appIdData))
                {
                    setAppIdFlag(appIdData, APPID_SESSION_CONTINUE);
                }
                appIdData->rnaServiceState = RNA_STATE_STATEFUL;
            }
            else
                appIdData->rnaServiceState = RNA_STATE_FINISHED;
            appIdData->rnaClientState = RNA_STATE_FINISHED;
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_state_set(appIdData->tpsession, TP_STATE_HA);
        }

        if (appHA->flags & APPID_HA_FLAGS_TP_DONE && thirdparty_appid_module)
        {
            thirdparty_appid_module->session_state_set(appIdData->tpsession, TP_STATE_TERMINATED);
            setAppIdFlag(appIdData, APPID_SESSION_NO_TPI);
        }
        if (appHA->flags & APPID_HA_FLAGS_SVC_DONE)
            setAppIdFlag(appIdData, APPID_SESSION_SERVICE_DETECTED);
        if (appHA->flags & APPID_HA_FLAGS_HTTP)
            setAppIdFlag(appIdData, APPID_SESSION_HTTP_SESSION);

        appIdData->tpAppId = appHA->appId[0];
        appIdData->serviceAppId = appHA->appId[1];
        appIdData->ClientServiceAppId = appHA->appId[2];
        appIdData->portServiceAppId = appHA->appId[3];
        appIdData->payloadAppId = appHA->appId[4];
        appIdData->tpPayloadAppId = appHA->appId[5];
        appIdData->ClientAppId = appHA->appId[6];
        appIdData->miscAppId = appHA->appId[7];
    }
    return sizeof(*appHA);
}

char* getDNSQuery(AppIdData* appIdData, uint8_t* query_len)
{
    if (appIdData && appIdData->dsession)
    {
        if (query_len)
        {
            if (appIdData->dsession->host)
                *query_len = appIdData->dsession->host_len;

            else
                *query_len = 0;
        }

        return appIdData->dsession->host;
    }
    if (query_len)
        *query_len = 0;
    return nullptr;
}

uint16_t getDNSQueryoffset(AppIdData* appIdData)
{
    if (appIdData && appIdData->dsession)
        return appIdData->dsession->host_offset;
    return 0;
}

uint16_t getDNSRecordType(AppIdData* appIdData)
{
    if (appIdData && appIdData->dsession)
        return appIdData->dsession->record_type;
    return 0;
}

uint8_t getDNSResponseType(AppIdData* appIdData)
{
    if (appIdData && appIdData->dsession)
        return appIdData->dsession->response_type;
    return 0;
}

uint32_t getDNSTTL(AppIdData* appIdData)
{
    if (appIdData && appIdData->dsession)
        return appIdData->dsession->ttl;
    return 0;
}

static AppIdApi appIdDispatchTable =
{
    appGetAppName,
    appGetAppId,

    getServiceAppId,
    getPorServiceAppId,
    getOnlyServiceAppId,
    getMiscAppId,
    getClientAppId,
    getPayloadAppId,
    getReferredAppId,
    getFwServiceAppId,
    getFwMiscAppId,
    getFwClientAppId,
    getFwPayloadAppId,
    getFwReferredAppId,

    isSessionSslDecrypted,
    IsAppIdInspectingSession,
    isAppIdAvailable,

    getUserName,
    getClientVersion,

    getAppIdSessionAttribute,

    getFlowType,
    getServiceInfo,
    getServicePort,
    getServiceIp,
    getInitiatorIp,

    getHttpUserAgent,
    getHttpHost,
    getHttpUrl,
    getHttpReferer,
    getHttpNewUrl,
    getHttpUri,
    getHttpResponseCode,
    getHttpCookie,
    getHttpNewCookie,
    getHttpContentType,
    getHttpLocation,
    getHttpBody,
    getHttpReqBody,
    getHttpUriOffset,
    getHttpUriEndOffset,
    getHttpCookieOffset,
    getHttpCookieEndOffset,
    getHttpSearch,
    getHttpXffAddr,

    getTlsHost,

    getDhcpFpData,
    freeDhcpFpData,
    getDhcpInfo,
    freeDhcpInfo,
    getSmbFpData,
    freeSmbFpData,
    getNetbiosName,
    produceHAState,
    consumeHAState,

    getAppIdData,

    getDNSQuery,
    getDNSQueryoffset,
    getDNSRecordType,
    getDNSResponseType,
    getDNSTTL,

    getHttpNewField,
    freeHttpNewField,
};

void appIdApiInit(struct AppIdApi* api)
{
    *api = appIdDispatchTable;
}

