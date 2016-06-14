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

// service_rexec.cc author Sourcefire Inc.

#include "service_rexec.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "protocols/packet.h"
#include "main/snort_debug.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#include "appid_api.h"
#include "app_info_table.h"
#include "appid_flow_data.h"
#include "application_ids.h"
#include "service_api.h"
#include "service_base.h"

#define REXEC_PORT  512
#define REXEC_MAX_PORT_PACKET 6

enum REXECState
{
    REXEC_STATE_PORT,
    REXEC_STATE_SERVER_CONNECT,
    REXEC_STATE_USERNAME,
    REXEC_STATE_PASSWORD,
    REXEC_STATE_COMMAND,
    REXEC_STATE_REPLY,
    REXEC_STATE_DONE,
    REXEC_STATE_STDERR_CONNECT_SYN,
    REXEC_STATE_STDERR_CONNECT_SYN_ACK
};

struct ServiceREXECData
{
    REXECState state;
    struct ServiceREXECData* parent;
    struct ServiceREXECData* child;
};

static int rexec_init(const IniServiceAPI* const init_api);
static int rexec_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &rexec_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "rexec"
};

static RNAServiceValidationPort pp[] =
{
    { &rexec_validate, REXEC_PORT, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule rexec_service_mod =
{
    "REXEC",
    &rexec_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_EXEC, APPINFO_FLAG_SERVICE_ADDITIONAL }
};

static int16_t app_id = 0;

static int rexec_init(const IniServiceAPI* const init_api)
{
    unsigned i;

    app_id = AddProtocolReference("rexec");

    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&rexec_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static void rexec_free_state(void* data)
{
    ServiceREXECData* rd = (ServiceREXECData*)data;

    if (rd)
    {
        if (rd->parent)
        {
            rd->parent->child = nullptr;
            rd->parent->parent = nullptr;
        }
        if (rd->child)
        {
            rd->child->parent = nullptr;
            rd->child->child = nullptr;
        }
        snort_free(rd);
    }
}

static int rexec_validate(ServiceValidationArgs* args)
{
    int i;
    uint32_t port;
    AppIdData* pf;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    Packet* pkt = args->pkt;
    const int dir = args->dir;
    uint16_t size = args->size;

    ServiceREXECData* rd = (ServiceREXECData*)rexec_service_mod.api->data_get(
        flowp, rexec_service_mod.flow_data_index);

    if (!rd)
    {
        if (!size)
            goto inprocess;
        rd = (ServiceREXECData*)snort_calloc(sizeof(ServiceREXECData));
        rexec_service_mod.api->data_add(flowp, rd,
            rexec_service_mod.flow_data_index, &rexec_free_state);
        rd->state = REXEC_STATE_PORT;
    }

    switch (rd->state)
    {
    case REXEC_STATE_PORT:
        if (dir != APP_ID_FROM_INITIATOR)
            goto bail;
        if (size > REXEC_MAX_PORT_PACKET)
            goto bail;
        if (data[size-1])
            goto bail;
        port = 0;
        for (i=0; i<size-1; i++)
        {
            if (!isdigit(data[i]))
                goto bail;
            port *= 10;
            port += data[i] - '0';
        }
        if (port > 65535)
            goto bail;
        if (port && pkt)
        {
            const sfip_t* sip;
            const sfip_t* dip;

            dip = pkt->ptrs.ip_api.get_dst();
            sip = pkt->ptrs.ip_api.get_src();
            pf = rexec_service_mod.api->flow_new(flowp, pkt, dip, 0, sip, (uint16_t)port,
                IpProtocol::TCP, app_id,
                APPID_EARLY_SESSION_FLAG_FW_RULE);
            if (pf)
            {
                ServiceREXECData* tmp_rd = (ServiceREXECData*)snort_calloc(
                    sizeof(ServiceREXECData));
                tmp_rd->state = REXEC_STATE_STDERR_CONNECT_SYN;
                tmp_rd->parent = rd;

                rexec_service_mod.api->data_add(pf, tmp_rd,
                    rexec_service_mod.flow_data_index, &rexec_free_state);
                if (rexec_service_mod.api->data_add_id(pf, (uint16_t)port, &svc_element))
                {
                    pf->rnaServiceState = RNA_STATE_FINISHED;
                    tmp_rd->state = REXEC_STATE_DONE;
                    tmp_rd->parent = nullptr;
                    return SERVICE_ENULL;
                }
                rd->child = tmp_rd;
                rd->state = REXEC_STATE_SERVER_CONNECT;
                pf->rnaServiceState = RNA_STATE_STATEFUL;
                pf->scan_flags |= SCAN_HOST_PORT_FLAG;
                PopulateExpectedFlow(flowp, pf,
                    APPID_SESSION_CONTINUE |
                    APPID_SESSION_REXEC_STDERR |
                    APPID_SESSION_NO_TPI |
                    APPID_SESSION_SERVICE_DETECTED |
                    APPID_SESSION_NOT_A_SERVICE |
                    APPID_SESSION_PORT_SERVICE_DONE);
                pf->rnaServiceState = RNA_STATE_STATEFUL;
            }
            else
                rd->state = REXEC_STATE_USERNAME;
        }
        else
            rd->state = REXEC_STATE_USERNAME;
        break;
    case REXEC_STATE_SERVER_CONNECT:
        if (!size)
            break;
        /* The only valid way out of this state is for the child flow to change it. */
        goto fail;
    case REXEC_STATE_USERNAME:
        if (!size)
            break;
        if (dir != APP_ID_FROM_INITIATOR)
            goto bail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]) || isspace(data[i]))
                goto bail;
        rd->state = REXEC_STATE_PASSWORD;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
    /* Fall through */
    case REXEC_STATE_PASSWORD:
        if (!size)
            break;
        if (dir != APP_ID_FROM_INITIATOR)
            goto bail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]))
                goto bail;
        rd->state = REXEC_STATE_COMMAND;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
    /* Fall through */
    case REXEC_STATE_COMMAND:
        if (!size)
            break;
        if (dir != APP_ID_FROM_INITIATOR)
            goto bail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]))
                goto bail;
        rd->state = REXEC_STATE_COMMAND;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
        if (!size)
        {
            rd->state = REXEC_STATE_REPLY;
            break;
        }
        if (data[size-1])
            goto bail;
        /* stdin */
        for (i=0; i<size && data[i]; i++)
        {
            if (!isprint(data[i]))
                goto bail;
        }
        i++;
        if (i != size)
            goto bail;
        rd->state = REXEC_STATE_REPLY;
        break;
    case REXEC_STATE_REPLY:
        if (!size)
            goto inprocess;
        if (dir != APP_ID_FROM_RESPONDER)
            goto fail;
        if (size != 1)
            goto fail;
        goto success;
        break;
    case REXEC_STATE_STDERR_CONNECT_SYN:
        rd->state = REXEC_STATE_STDERR_CONNECT_SYN_ACK;
        break;
    case REXEC_STATE_STDERR_CONNECT_SYN_ACK:
        if (rd->parent && rd->parent->state == REXEC_STATE_SERVER_CONNECT)
        {
            rd->parent->state = REXEC_STATE_USERNAME;
            clearAppIdFlag(flowp, APPID_SESSION_REXEC_STDERR);
        }
        goto bail;
    default:
        goto bail;
    }

inprocess:
    if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
    {
        rexec_service_mod.api->service_inprocess(flowp, pkt, dir, &svc_element);
    }
    return SERVICE_INPROCESS;

success:
    if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
    {
        rexec_service_mod.api->add_service(flowp, pkt, dir, &svc_element,
            APP_ID_EXEC, nullptr, nullptr, nullptr);
    }
    return SERVICE_SUCCESS;

bail:
    if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
    {
        rexec_service_mod.api->incompatible_data(flowp, pkt, dir, &svc_element,
            rexec_service_mod.flow_data_index,
            args->pConfig);
    }
    clearAppIdFlag(flowp, APPID_SESSION_CONTINUE);
    return SERVICE_NOT_COMPATIBLE;

fail:
    if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
    {
        rexec_service_mod.api->fail_service(flowp, pkt, dir, &svc_element,
            rexec_service_mod.flow_data_index,
            args->pConfig);
    }
    clearAppIdFlag(flowp, APPID_SESSION_CONTINUE);
    return SERVICE_NOMATCH;
}

