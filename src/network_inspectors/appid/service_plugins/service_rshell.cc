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

// service_rshell.cc author Sourcefire Inc.

#include "service_rshell.h"

#include "application_ids.h"
#include "service_api.h"
#include "service_base.h"
#include "app_info_table.h"

#include "log/messages.h"
#include "main/snort_debug.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#define RSHELL_PORT  514
#define RSHELL_MAX_PORT_PACKET 6

enum RSHELLState
{
    RSHELL_STATE_PORT,
    RSHELL_STATE_SERVER_CONNECT,
    RSHELL_STATE_USERNAME,
    RSHELL_STATE_USERNAME2,
    RSHELL_STATE_COMMAND,
    RSHELL_STATE_REPLY,
    RSHELL_STATE_DONE,
    RSHELL_STATE_STDERR_CONNECT_SYN,
    RSHELL_STATE_STDERR_CONNECT_SYN_ACK
};

struct ServiceRSHELLData
{
    RSHELLState state;
    ServiceRSHELLData* parent;
    ServiceRSHELLData* child;
};

static int rshell_init(const IniServiceAPI* const init_api);
static int rshell_validate(ServiceValidationArgs* args);

//  FIXIT-L: Make the globals const or, if necessary, thread-local.
static RNAServiceElement svc_element =
{
    nullptr,
    &rshell_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "rshell"
};

static RNAServiceValidationPort pp[] =
{
    { &rshell_validate, RSHELL_PORT, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule rshell_service_mod =
{
    "RSHELL",
    &rshell_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_SHELL, APPINFO_FLAG_SERVICE_ADDITIONAL }
};

static int16_t app_id = 0;

static int rshell_init(const IniServiceAPI* const init_api)
{
    unsigned i;

    app_id = AddProtocolReference("rsh-error");

    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&rshell_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static void rshell_free_state(void* data)
{
    ServiceRSHELLData* rd = (ServiceRSHELLData*)data;

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

static int rshell_validate(ServiceValidationArgs* args)
{
    ServiceRSHELLData* rd = nullptr;
    ServiceRSHELLData* tmp_rd;
    int i;
    uint32_t port;
    AppIdData* pf;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    Packet* pkt = args->pkt;
    const int dir = args->dir;
    uint16_t size = args->size;
    bool app_id_debug_session_flag = args->app_id_debug_session_flag;
    char* app_id_debug_session = args->app_id_debug_session;

    rd = (ServiceRSHELLData*)rshell_service_mod.api->data_get(flowp,
        rshell_service_mod.flow_data_index);
    if (!rd)
    {
        if (!size)
            goto inprocess;
        rd = (ServiceRSHELLData*)snort_calloc(sizeof(ServiceRSHELLData));
        rshell_service_mod.api->data_add(flowp, rd,
            rshell_service_mod.flow_data_index, &rshell_free_state);
        rd->state = RSHELL_STATE_PORT;
    }

    if (app_id_debug_session_flag)
        LogMessage("AppIdDbg %s rshell state %d\n", app_id_debug_session, rd->state);

    switch (rd->state)
    {
    case RSHELL_STATE_PORT:
        if (dir != APP_ID_FROM_INITIATOR)
            goto fail;
        if (size > RSHELL_MAX_PORT_PACKET)
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
        if (port)
        {
            const sfip_t* sip;
            const sfip_t* dip;

            tmp_rd = (ServiceRSHELLData*)snort_calloc(sizeof(ServiceRSHELLData));
            tmp_rd->state = RSHELL_STATE_STDERR_CONNECT_SYN;
            tmp_rd->parent = rd;
            dip = pkt->ptrs.ip_api.get_dst();
            sip = pkt->ptrs.ip_api.get_src();
            // FIXIT-M can flow_new return null?
            pf = rshell_service_mod.api->flow_new(flowp, pkt, dip, 0, sip, (uint16_t)port,
                IpProtocol::TCP, app_id, APPID_EARLY_SESSION_FLAG_FW_RULE);
            if (pf)
            {
                pf->rnaClientState = RNA_STATE_FINISHED;
                rshell_service_mod.api->data_add(pf, tmp_rd,
                    rshell_service_mod.flow_data_index, &rshell_free_state);
                if (rshell_service_mod.api->data_add_id(pf, (uint16_t)port, &svc_element))
                {
                    pf->rnaServiceState = RNA_STATE_FINISHED;
                    tmp_rd->state = RSHELL_STATE_DONE;
                    tmp_rd->parent = nullptr;
                    return SERVICE_ENOMEM;
                }
                pf->scan_flags |= SCAN_HOST_PORT_FLAG;
                PopulateExpectedFlow(flowp, pf,
                    APPID_SESSION_NO_TPI |
                    APPID_SESSION_IGNORE_HOST |
                    APPID_SESSION_NOT_A_SERVICE |
                    APPID_SESSION_PORT_SERVICE_DONE);
                pf->rnaServiceState = RNA_STATE_STATEFUL;
            }
            else
            {
                snort_free(tmp_rd);
                return SERVICE_ENOMEM;
            }
            rd->child = tmp_rd;
            rd->state = RSHELL_STATE_SERVER_CONNECT;
        }
        else
            rd->state = RSHELL_STATE_USERNAME;
        break;
    case RSHELL_STATE_SERVER_CONNECT:
        if (!size)
            break;
        /* The only valid way out of this state is for the child flow to change it. */
        goto fail;
    case RSHELL_STATE_USERNAME:
        if (!size)
            break;
        if (dir != APP_ID_FROM_INITIATOR)
            goto fail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]) || isspace(data[i]))
                goto bail;
        rd->state = RSHELL_STATE_USERNAME2;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
    /* Fall through */
    case RSHELL_STATE_USERNAME2:
        if (!size)
            break;
        if (dir != APP_ID_FROM_INITIATOR)
            goto fail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]) || isspace(data[i]))
                goto bail;
        rd->state = RSHELL_STATE_COMMAND;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
    /* Fall through */
    case RSHELL_STATE_COMMAND:
        if (!size)
            break;
        if (dir != APP_ID_FROM_INITIATOR)
            goto fail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]))
                goto bail;
        rd->state = RSHELL_STATE_COMMAND;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
        if (!size)
        {
            rd->state = RSHELL_STATE_REPLY;
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
        rd->state = RSHELL_STATE_REPLY;
        break;
    case RSHELL_STATE_REPLY:
        if (!size)
            goto inprocess;
        if (dir != APP_ID_FROM_RESPONDER)
            goto fail;
        if (size == 1)
            goto success;
        if (*data == 0x01)
        {
            data++;
            size--;
            for (i=0; i<size && data[i]; i++)
            {
                if (!isprint(data[i]) && data[i] != 0x0A && data[i] != 0x0D && data[i] != 0x09)
                    goto fail;
            }
            goto success;
        }
        goto fail;
        break;
    case RSHELL_STATE_STDERR_CONNECT_SYN:
        rd->state = RSHELL_STATE_STDERR_CONNECT_SYN_ACK;
        break;
    case RSHELL_STATE_STDERR_CONNECT_SYN_ACK:
        if (rd->parent && rd->parent->state == RSHELL_STATE_SERVER_CONNECT)
            rd->parent->state = RSHELL_STATE_USERNAME;
        setAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED);
        return SERVICE_SUCCESS;
    default:
        goto bail;
    }

inprocess:
    rshell_service_mod.api->service_inprocess(flowp, pkt, dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    rshell_service_mod.api->add_service(flowp, pkt, dir, &svc_element,
        APP_ID_SHELL, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

bail:
    rshell_service_mod.api->incompatible_data(flowp, pkt, dir, &svc_element,
        rshell_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOT_COMPATIBLE;

fail:
    rshell_service_mod.api->fail_service(flowp, pkt, dir, &svc_element,
        rshell_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

