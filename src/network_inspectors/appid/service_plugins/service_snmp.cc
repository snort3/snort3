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

// service_snmp.cc author Sourcefire Inc.

#include "service_snmp.h"

#include "log/messages.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#include "appid_api.h"
#include "app_info_table.h"
#include "service_base.h"
#include "application_ids.h"

#define SNMP_PORT   161

#define SNMP_VERSION_1  0
#define SNMP_VERSION_2c 1
#define SNMP_VERSION_2u 2
#define SNMP_VERSION_3  3

#define SNMP_VENDOR_STR     "SNMP"
#define SNMP_VERSION_STR_1  "v1"
#define SNMP_VERSION_STR_2c "v2c"
#define SNMP_VERSION_STR_2u "v2u"
#define SNMP_VERSION_STR_3  "v3"

enum SNMPState
{
    SNMP_STATE_CONNECTION,
    SNMP_STATE_RESPONSE,
    SNMP_STATE_REQUEST,
    SNMP_STATE_R_RESPONSE,
    SNMP_STATE_R_REQUEST,
    SNMP_STATE_ERROR
};

struct ServiceSNMPData
{
    SNMPState state;
};

enum SNMPPDUType
{
    SNMP_PDU_GET_REQUEST,
    SNMP_PDU_GET_NEXT_REQUEST,
    SNMP_PDU_GET_RESPONSE,
    SNMP_PDU_SET_REQUEST,
    SNMP_PDU_TRAP,
    SNMP_PDU_GET_BULK_REQUEST,
    SNMP_PDU_INFORM_REQUEST,
    SNMP_PDU_TRAPV2
};

#pragma pack(1)

struct ServiceSNMPHeader
{
    uint16_t opcode;
    union
    {
        uint16_t block;
        uint16_t errorcode;
    } d;
};

#pragma pack()

static int snmp_init(const IniServiceAPI* const init_api);
static int snmp_validate(ServiceValidationArgs* args);

//  FIXIT-L: Make the globals const or, if necessary, thread-local.
static RNAServiceElement svc_element =
{
    nullptr,
    &snmp_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "snmp",
};

static RNAServiceValidationPort pp[] =
{
    { &snmp_validate, SNMP_PORT, IpProtocol::TCP, 0 },
    { &snmp_validate, SNMP_PORT, IpProtocol::UDP, 0 },
    { &snmp_validate, 162, IpProtocol::UDP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule snmp_service_mod =
{
    "SNMP",
    &snmp_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static const uint8_t SNMP_PATTERN_2[] = { 0x02, 0x01, 0x00, 0x04 };
static const uint8_t SNMP_PATTERN_3[] = { 0x02, 0x01, 0x01, 0x04 };
static const uint8_t SNMP_PATTERN_4[] = { 0x02, 0x01, 0x03, 0x30 };

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_SNMP, APPINFO_FLAG_SERVICE_UDP_REVERSED|APPINFO_FLAG_SERVICE_ADDITIONAL }
};

static int16_t app_id = 0;

static int snmp_init(const IniServiceAPI* const init_api)
{
    app_id = AddProtocolReference("snmp");

    init_api->RegisterPattern(&snmp_validate, IpProtocol::UDP, SNMP_PATTERN_2,
        sizeof(SNMP_PATTERN_2), 2, "snmp", init_api->pAppidConfig);
    init_api->RegisterPattern(&snmp_validate, IpProtocol::UDP, SNMP_PATTERN_3,
        sizeof(SNMP_PATTERN_3), 2, "snmp", init_api->pAppidConfig);
    init_api->RegisterPattern(&snmp_validate, IpProtocol::UDP, SNMP_PATTERN_4,
        sizeof(SNMP_PATTERN_4), 2, "snmp", init_api->pAppidConfig);
    init_api->RegisterPattern(&snmp_validate, IpProtocol::UDP, SNMP_PATTERN_2,
        sizeof(SNMP_PATTERN_2), 3, "snmp", init_api->pAppidConfig);
    init_api->RegisterPattern(&snmp_validate, IpProtocol::UDP, SNMP_PATTERN_3,
        sizeof(SNMP_PATTERN_3), 3, "snmp", init_api->pAppidConfig);
    init_api->RegisterPattern(&snmp_validate, IpProtocol::UDP, SNMP_PATTERN_4,
        sizeof(SNMP_PATTERN_4), 3, "snmp", init_api->pAppidConfig);
    init_api->RegisterPattern(&snmp_validate, IpProtocol::UDP, SNMP_PATTERN_2,
        sizeof(SNMP_PATTERN_2), 4, "snmp", init_api->pAppidConfig);
    init_api->RegisterPattern(&snmp_validate, IpProtocol::UDP, SNMP_PATTERN_3,
        sizeof(SNMP_PATTERN_3),  4, "snmp", init_api->pAppidConfig);
    init_api->RegisterPattern(&snmp_validate, IpProtocol::UDP, SNMP_PATTERN_4,
        sizeof(SNMP_PATTERN_4), 4, "snmp", init_api->pAppidConfig);

    for (unsigned i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&snmp_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int snmp_ans1_length(const uint8_t** const data,
    const uint8_t* const end,
    uint32_t* const length)
{
    *length = 0;
    if (**data == 0x80)
        return -1;
    if (**data < 0x80)
    {
        *length = (uint32_t)**data;
        (*data)++;
    }
    else
    {
        int cnt = (**data) & 0x7F;
        (*data)++;
        for (; *data<end && cnt; cnt--, (*data)++)
        {
            *length <<= 8;
            *length |= **data;
        }
        if (cnt)
            return -1;
    }
    return 0;
}

static int snmp_verify_packet(const uint8_t** const data,
    const uint8_t* const end, uint8_t* const pdu,
    uint8_t* version_ret)
{
    uint32_t overall_length;
    uint32_t community_length;
    uint32_t global_length;
    uint32_t length;
    uint8_t version;
    uint8_t cls;
    const uint8_t* p;

    if (**data != 0x30)
        return -1;
    (*data)++;
    if (*data >= end)
        return -1;
    if (snmp_ans1_length(data, end, &overall_length))
        return -1;
    if (overall_length < 3 || (int)overall_length > end-(*data))
        return -1;
    if (**data != 0x02)
        return -1;
    (*data)++;
    if (**data != 0x01)
        return -1;
    (*data)++;
    version = **data;
    (*data)++;
    overall_length -= 3;
    if (!overall_length)
        return -1;
    switch (version)
    {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
        if (**data != 0x04)
            return -1;
        (*data)++;
        overall_length--;
        if (!overall_length)
            return -1;
        p = *data;
        if (snmp_ans1_length(data, *data+overall_length, &community_length))
            return -1;
        overall_length -= *data - p;
        if (overall_length < community_length)
            return -1;
        for (;
            community_length;
            (*data)++, community_length--, overall_length--)
        {
            if (!isprint(**data))
                return -1;
        }
        break;
    case SNMP_VERSION_2u:
        if (**data != 0x04)
            return -1;
        (*data)++;
        overall_length--;
        if (!overall_length)
            return -1;
        p = *data;
        if (snmp_ans1_length(data, *data+overall_length, &community_length))
            return -1;
        overall_length -= *data - p;
        if (!community_length || overall_length < community_length)
            return -1;
        if (**data != 1)
            return -1;
        *data += community_length;
        overall_length -= community_length;
        break;
    case SNMP_VERSION_3:
        /* Global header */
        if (**data != 0x30)
            return -1;
        (*data)++;
        overall_length--;
        if (!overall_length)
            return -1;
        p = *data;
        if (snmp_ans1_length(data, *data+overall_length, &global_length))
            return -1;
        overall_length -= *data - p;
        if (global_length < 2 || overall_length < global_length)
            return -1;

        /* Message id */
        if (**data != 0x02)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (global_length < length || length > sizeof(uint32_t))
            return -1;
        *data += length;
        global_length -= length;
        overall_length -= length;

        /* Max message size */
        if (global_length < 2)
            return -1;
        if (**data != 0x02)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (global_length < length || length > sizeof(uint32_t))
            return -1;
        *data += length;
        global_length -= length;
        overall_length -= length;

        /* Message flags */
        if (global_length < 2)
            return -1;
        if (**data != 0x04)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (length != 1 || global_length < length)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;

        /* Security model */
        if (global_length < 2)
            return -1;
        if (**data != 0x02)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (global_length < length || length > sizeof(uint32_t))
            return -1;
        *data += length;
        global_length -= length;
        overall_length -= length;

        /* Security Parameters */
        if (overall_length < 2)
            return -1;
        if (**data != 0x04)
            return -1;
        (*data)++;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+overall_length, &global_length))
            return -1;
        overall_length -= *data - p;
        if (overall_length < global_length)
            return -1;
        *data += global_length;
        overall_length -= global_length;

        /* Message */
        if (overall_length < 2)
            return -1;
        if (**data != 0x30)
            return -1;
        (*data)++;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+overall_length, &global_length))
            return -1;
        overall_length -= *data - p;
        if (overall_length < global_length)
            return -1;

        /* Context Engine ID */
        if (global_length < 2)
            return -1;
        if (**data != 0x04)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (global_length < length)
            return -1;
        *data += length;
        global_length -= length;
        overall_length -= length;

        /* Context Name */
        if (global_length < 2)
            return -1;
        if (**data != 0x04)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (global_length < length)
            return -1;
        *data += length;
        global_length -= length;
        overall_length -= length;
        break;
    default:
        return -1;
    }
    if (!overall_length)
        return -1;
    cls = (**data) & 0xC0;
    if (cls != 0x80 && cls != 0x40)
        return -1;
    *pdu = (**data) & 0x1F;
    *version_ret = version;
    return 0;
}

static int snmp_validate(ServiceValidationArgs* args)
{
    ServiceSNMPData* sd;
    ServiceSNMPData* tmp_sd;
    AppIdData* pf;
    uint8_t pdu;
    const sfip_t* sip;
    const sfip_t* dip;
    uint8_t version;
    const char* version_str = nullptr;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    Packet* pkt = args->pkt;
    const int dir = args->dir;
    uint16_t size = args->size;
    bool app_id_debug_session_flag = args->app_id_debug_session_flag;
    char* app_id_debug_session = args->app_id_debug_session;

    if (!size)
        goto inprocess;

    sd = (ServiceSNMPData*)snmp_service_mod.api->data_get(flowp, snmp_service_mod.flow_data_index);
    if (!sd)
    {
        sd = (ServiceSNMPData*)snort_calloc(sizeof(ServiceSNMPData));
        snmp_service_mod.api->data_add(flowp, sd, snmp_service_mod.flow_data_index, &snort_free);
        sd->state = SNMP_STATE_CONNECTION;
    }

    if (snmp_verify_packet(&data, data+size, &pdu, &version))
    {
        if (app_id_debug_session_flag)
            LogMessage("AppIdDbg %s snmp payload verify failed\n", app_id_debug_session);
        if (getAppIdFlag(flowp, APPID_SESSION_UDP_REVERSED))
        {
            if (dir == APP_ID_FROM_RESPONDER)
                goto bail;
            else
                goto fail;
        }
        else
        {
            if (dir == APP_ID_FROM_RESPONDER)
                goto fail;
            else
                goto bail;
        }
    }

    if (app_id_debug_session_flag)
        LogMessage("AppIdDbg %s snmp state %d\n", app_id_debug_session, sd->state);

    switch (sd->state)
    {
    case SNMP_STATE_CONNECTION:
        if (pdu != SNMP_PDU_GET_RESPONSE && dir == APP_ID_FROM_RESPONDER)
        {
            sd->state = SNMP_STATE_R_RESPONSE;
            setAppIdFlag(flowp, APPID_SESSION_UDP_REVERSED);
            break;
        }
        if (pdu == SNMP_PDU_GET_RESPONSE && dir == APP_ID_FROM_INITIATOR)
        {
            sd->state = SNMP_STATE_R_REQUEST;
            setAppIdFlag(flowp, APPID_SESSION_UDP_REVERSED);
            break;
        }

        if (dir == APP_ID_FROM_RESPONDER)
        {
            sd->state = SNMP_STATE_REQUEST;
            break;
        }

        if (pdu == SNMP_PDU_TRAP || pdu == SNMP_PDU_TRAPV2)
        {
            setAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_NOT_A_SERVICE);
            clearAppIdFlag(flowp, APPID_SESSION_CONTINUE);
            flowp->serviceAppId = APP_ID_SNMP;
            break;
        }
        sd->state = SNMP_STATE_RESPONSE;

        /*adding expected connection in case the server doesn't send from 161*/
        dip = pkt->ptrs.ip_api.get_dst();
        sip = pkt->ptrs.ip_api.get_src();
        pf = snmp_service_mod.api->flow_new(flowp, pkt, dip, 0, sip, pkt->ptrs.sp, flowp->proto,
            app_id, 0);
        if (pf)
        {
            tmp_sd = (ServiceSNMPData*)snort_calloc(sizeof(ServiceSNMPData));
            tmp_sd->state = SNMP_STATE_RESPONSE;
            snmp_service_mod.api->data_add(pf, tmp_sd,
                snmp_service_mod.flow_data_index, &snort_free);
            if (snmp_service_mod.api->data_add_id(pf, pkt->ptrs.dp, &svc_element))
            {
                setAppIdFlag(pf, APPID_SESSION_SERVICE_DETECTED);
                clearAppIdFlag(pf, APPID_SESSION_CONTINUE);
                tmp_sd->state = SNMP_STATE_ERROR;
                return SERVICE_ENULL;
            }
            PopulateExpectedFlow(flowp, pf, APPID_SESSION_EXPECTED_EVALUATE);
            pf->rnaServiceState = RNA_STATE_STATEFUL;
            pf->scan_flags |= SCAN_HOST_PORT_FLAG;
            pf->common.initiator_ip = *sip;
        }
        break;
    case SNMP_STATE_RESPONSE:
        if (pdu == SNMP_PDU_GET_RESPONSE)
        {
            if (dir == APP_ID_FROM_RESPONDER)
                goto success;
            goto fail;
        }
        if (dir == APP_ID_FROM_RESPONDER)
            goto fail;
        break;
    case SNMP_STATE_REQUEST:
        if (pdu != SNMP_PDU_GET_RESPONSE)
        {
            if (dir == APP_ID_FROM_INITIATOR)
                goto success;
            goto fail;
        }
        if (dir == APP_ID_FROM_INITIATOR)
            goto fail;
        break;
    case SNMP_STATE_R_RESPONSE:
        if (pdu == SNMP_PDU_GET_RESPONSE)
        {
            if (dir == APP_ID_FROM_INITIATOR)
                goto success;
            goto fail;
        }
        if (dir == APP_ID_FROM_INITIATOR)
            goto fail;
        break;
    case SNMP_STATE_R_REQUEST:
        if (pdu != SNMP_PDU_GET_RESPONSE)
        {
            if (dir == APP_ID_FROM_RESPONDER)
                goto success;
            goto fail;
        }
        if (dir == APP_ID_FROM_RESPONDER)
            goto fail;
        break;
    default:
        if (dir == APP_ID_FROM_RESPONDER)
            goto fail;
        else
            goto bail;
    }

inprocess:
    snmp_service_mod.api->service_inprocess(flowp, pkt, dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    switch (version)
    {
    case SNMP_VERSION_1:
        version_str = SNMP_VERSION_STR_1;
        break;
    case SNMP_VERSION_2c:
        version_str = SNMP_VERSION_STR_2c;
        break;
    case SNMP_VERSION_2u:
        version_str = SNMP_VERSION_STR_2u;
        break;
    case SNMP_VERSION_3:
        version_str = SNMP_VERSION_STR_3;
        break;
    default:
        version_str = nullptr;
        break;
    }
    snmp_service_mod.api->add_service(flowp, pkt, dir, &svc_element,
        APP_ID_SNMP,
        SNMP_VENDOR_STR, version_str, nullptr);
    return SERVICE_SUCCESS;

bail:
    snmp_service_mod.api->incompatible_data(flowp, pkt, dir, &svc_element,
        snmp_service_mod.flow_data_index,
        args->pConfig);
    return SERVICE_NOT_COMPATIBLE;

fail:
    snmp_service_mod.api->fail_service(flowp, pkt, dir, &svc_element,
        snmp_service_mod.flow_data_index,
        args->pConfig);
    return SERVICE_NOMATCH;
}

