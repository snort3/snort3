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

// service_tftp.cc author Sourcefire Inc.

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "main/snort_debug.h"
#include "log/messages.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "appid_api.h"
#include "appid_flow_data.h"
#include "application_ids.h"
#include "service_api.h"
#include "service_base.h"

#define TFTP_PORT   69

#define TFTP_COUNT_THRESHOLD 1
#define TFTP_MAX_PACKET_SIZE 512

enum TFTPState
{
    TFTP_STATE_CONNECTION,
    TFTP_STATE_TRANSFER,
    TFTP_STATE_ACK,
    TFTP_STATE_DATA,
    TFTP_STATE_ERROR
};

struct ServiceTFTPData
{
    TFTPState state;
    unsigned count;
    int last;
    uint16_t block;
};

#pragma pack(1)

struct ServiceTFTPHeader
{
    uint16_t opcode;
    union
    {
        uint16_t block;
        uint16_t errorcode;
    } d;
};

#pragma pack()

static int tftp_init(const IniServiceAPI* const api);
static int tftp_validate(ServiceValidationArgs* args);

static const RNAServiceElement svc_element =
{
    nullptr,
    &tftp_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "tftp",
};

// FIXIT thread safety, can this be const?
static RNAServiceValidationPort pp[] =
{
    { &tftp_validate, 69, IpProtocol::UDP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

// FIXIT thread safety, can this be const?
RNAServiceValidationModule tftp_service_mod =
{
    "TFTP",
    &tftp_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static const AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_TFTP, APPINFO_FLAG_SERVICE_ADDITIONAL }
};

static int16_t app_id = 0;

static int tftp_init(const IniServiceAPI* const init_api)
{
    app_id = AddProtocolReference("tftp");
    for (unsigned i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&tftp_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int tftp_verify_header(const uint8_t* data, uint16_t size,
    uint16_t* block)
{
    if (size < sizeof(ServiceTFTPHeader))
        return -1;
    const ServiceTFTPHeader* hdr = (ServiceTFTPHeader*)data;
    switch (ntohs(hdr->opcode))
    {
    case 3:
        if (size > sizeof(ServiceTFTPHeader) + TFTP_MAX_PACKET_SIZE)
            return -1;
        *block = ntohs(hdr->d.block);
        return TFTP_STATE_DATA;
    case 4:
        if (size != sizeof(ServiceTFTPHeader))
            return -1;
        *block = ntohs(hdr->d.block);
        return TFTP_STATE_ACK;
    case 5:
        if (ntohs(hdr->d.errorcode) > 7)
            return -1;
        if (size <= sizeof(ServiceTFTPHeader))
            return -1;
        if (data[size-1] != 0)
            return -1;
        return TFTP_STATE_ERROR;
    default:
        return -1;
    }
}

static int tftp_validate(ServiceValidationArgs* args)
{
    ServiceTFTPData* td;
    ServiceTFTPData* tmp_td;
    int mode;
    uint16_t block = 0;
    uint16_t tmp;
    AppIdData* pf;
    const sfip_t* sip;
    const sfip_t* dip;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    Packet* pkt = args->pkt;
    const int dir = args->dir;
    uint16_t size = args->size;
    char* app_id_debug_session = args->app_id_debug_session;

    if (!size)
        goto inprocess;

    td = (ServiceTFTPData*)tftp_service_mod.api->data_get(flowp, tftp_service_mod.flow_data_index);
    if (!td)
    {
        td = (ServiceTFTPData*)snort_calloc(sizeof(ServiceTFTPData));
        tftp_service_mod.api->data_add(flowp, td, tftp_service_mod.flow_data_index, &snort_free);
        td->state = TFTP_STATE_CONNECTION;
    }
    if (args->app_id_debug_session_flag)
        LogMessage("AppIdDbg %s tftp state %d\n", app_id_debug_session, td->state);

    if (td->state == TFTP_STATE_CONNECTION && dir == APP_ID_FROM_RESPONDER)
        goto fail;
    if ((td->state == TFTP_STATE_TRANSFER || td->state == TFTP_STATE_DATA) &&
        dir == APP_ID_FROM_INITIATOR)
    {
        goto inprocess;
    }
    switch (td->state)
    {
    case TFTP_STATE_CONNECTION:
        if (size < 6)
            goto bail;
        tmp = ntohs(*((uint16_t*)data));
        if (tmp != 0x0001 && tmp != 0x0002)
            goto bail;
        data += sizeof(uint16_t);
        size -= sizeof(uint16_t);
        if (!(*data))
            goto bail;
        for (; *data && size; data++, size--)
        {
            if (!isprint(*data))
                goto bail;
        }
        if (!size)
            goto bail;
        size--;
        data++;
        if (!size || !(*data))
            goto bail;
        if (data[size-1])
            goto bail;
        if (strcasecmp((char*)data, "netascii") && strcasecmp((char*)data, "octet"))
            goto bail;

        tmp_td = (ServiceTFTPData*)snort_calloc(sizeof(ServiceTFTPData));
        tmp_td->state = TFTP_STATE_TRANSFER;
        dip = pkt->ptrs.ip_api.get_dst();
        sip = pkt->ptrs.ip_api.get_src();
        pf = tftp_service_mod.api->flow_new(flowp, pkt, dip, 0, sip, pkt->ptrs.sp, flowp->proto,
            app_id, APPID_EARLY_SESSION_FLAG_FW_RULE);
        if (pf)
        {
            tftp_service_mod.api->data_add(pf, tmp_td,
                tftp_service_mod.flow_data_index, &snort_free);
            if (tftp_service_mod.api->data_add_id(pf, pkt->ptrs.dp, &svc_element))
            {
                setAppIdFlag(pf, APPID_SESSION_SERVICE_DETECTED);
                clearAppIdFlag(pf, APPID_SESSION_CONTINUE);
                tmp_td->state = TFTP_STATE_ERROR;
                return SERVICE_ENOMEM;
            }
            PopulateExpectedFlow(flowp, pf, APPID_SESSION_EXPECTED_EVALUATE);
            pf->common.initiator_ip = *sip;
            pf->rnaServiceState = RNA_STATE_STATEFUL;
            pf->scan_flags |= SCAN_HOST_PORT_FLAG;
        }
        else
        {
            snort_free(tmp_td);
            goto inprocess;   /* Assume that the flow already exists
                                 as in a retransmit situation */
        }
        break;
    case TFTP_STATE_TRANSFER:
        if ((mode=tftp_verify_header(data, size, &block)) < 0)
        {
            if (args->app_id_debug_session_flag)
                LogMessage("AppIdDbg %s tftp failed to verify\n", app_id_debug_session);
            goto fail;
        }
        if (args->app_id_debug_session_flag)
            LogMessage("AppIdDbg %s tftp mode %d and block %u\n", app_id_debug_session,
                mode, (unsigned)block);
        if (mode == TFTP_STATE_ACK)
        {
            if (block != 0)
            {
                td->state = TFTP_STATE_ERROR;
                goto fail;
            }
            td->last = 0;
            td->block = 0;
            td->state = TFTP_STATE_ACK;
        }
        else if (mode == TFTP_STATE_DATA)
        {
            if (block != 1)
            {
                td->state = TFTP_STATE_ERROR;
                goto fail;
            }
            td->block = 1;
            td->state = TFTP_STATE_DATA;
        }
        else if (mode == TFTP_STATE_ERROR)
            break;
        else
        {
            td->state = TFTP_STATE_ERROR;
            goto fail;
        }
        break;
    case TFTP_STATE_ACK:
        if ((mode=tftp_verify_header(data, size, &block)) < 0)
        {
            if (dir == APP_ID_FROM_RESPONDER)
                goto fail;
            else
            {
                if (args->app_id_debug_session_flag)
                    LogMessage("AppIdDbg %s tftp failed to verify\n", app_id_debug_session);
                goto bail;
            }
        }
        if (args->app_id_debug_session_flag)
            LogMessage("AppIdDbg %s tftp mode %d\n", app_id_debug_session, mode);
        if (mode == TFTP_STATE_ERROR)
        {
            td->state = TFTP_STATE_TRANSFER;
            break;
        }
        if (dir == APP_ID_FROM_INITIATOR && mode != TFTP_STATE_DATA)
        {
            if (args->app_id_debug_session_flag)
                LogMessage("AppIdDbg %s tftp bad mode\n", app_id_debug_session);
            goto bail;
        }
        if (dir == APP_ID_FROM_RESPONDER && mode != TFTP_STATE_ACK)
            goto fail;
        if (dir == APP_ID_FROM_INITIATOR)
        {
            if (size < sizeof(ServiceTFTPHeader) + TFTP_MAX_PACKET_SIZE)
                td->last = 1;
            break;
        }
        if (block == (uint16_t)(td->block + 1))
            td->block++;
        else if (block != td->block)
            goto fail;
        td->count++;
        if (td->count >= TFTP_COUNT_THRESHOLD)
            goto success;
        if (td->last)
            td->state = TFTP_STATE_TRANSFER;
        break;
    case TFTP_STATE_DATA:
        if ((mode=tftp_verify_header(data, size, &block)) < 0)
            goto fail;
        if (mode == TFTP_STATE_ERROR)
            td->state = TFTP_STATE_TRANSFER;
        else if (mode != TFTP_STATE_DATA)
            goto fail;
        if (block == (uint16_t)(td->block + 1))
            td->block++;
        else if (block != td->block)
            goto fail;
        td->count++;
        if (td->count >= TFTP_COUNT_THRESHOLD)
            goto success;
        if (size < sizeof(ServiceTFTPHeader) + TFTP_MAX_PACKET_SIZE)
            td->state = TFTP_STATE_TRANSFER;
        break;
    case TFTP_STATE_ERROR:
    default:
        goto fail;
    }

inprocess:
    tftp_service_mod.api->service_inprocess(flowp, pkt, dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    if (args->app_id_debug_session_flag)
        LogMessage("AppIdDbg %s tftp success\n", app_id_debug_session);
    tftp_service_mod.api->add_service(flowp, pkt, dir, &svc_element,
        APP_ID_TFTP, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

bail:
    tftp_service_mod.api->incompatible_data(flowp, pkt, dir, &svc_element,
        tftp_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOT_COMPATIBLE;

fail:
    tftp_service_mod.api->fail_service(flowp, pkt, dir, &svc_element,
        tftp_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

