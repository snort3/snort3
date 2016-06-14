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

// service_lpr.cc author Sourcefire Inc.

#include "main/snort_debug.h"
#include "utils/util.h"

#include "application_ids.h"
#include "appid_flow_data.h"
#include "service_api.h"

#define LPR_COUNT_THRESHOLD 5

enum LPRState
{
    LPR_STATE_COMMAND,
    LPR_STATE_RECEIVE,
    LPR_STATE_REPLY1,
    LPR_STATE_REPLY,
    LPR_STATE_IGNORE
};

enum LPRCommand
{
    LPR_CMD_PRINT = 1,
    LPR_CMD_RECEIVE,
    LPR_CMD_SHORT_STATE,
    LPR_CMD_LONG_STATE,
    LPR_CMD_REMOVE
};

enum LPRSubCommand
{
    LPR_SUBCMD_ABORT = 1,
    LPR_SUBCMD_CONTROL,
    LPR_SUBCMD_DATA
};

struct ServiceLPRData
{
    LPRState state;
    unsigned no_data_count;
    unsigned count;
};

static int lpr_init(const IniServiceAPI* const init_api);
static int lpr_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &lpr_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "lpr"
};

static RNAServiceValidationPort pp[] =
{
    { &lpr_validate, 515, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule lpr_service_mod =
{
    "LPR",
    &lpr_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_PRINTSRV, 0 }
};

static int lpr_init(const IniServiceAPI* const init_api)
{
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&lpr_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int lpr_validate(ServiceValidationArgs* args)
{
    ServiceLPRData* ld;
    int i;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;

    ld = (ServiceLPRData*)lpr_service_mod.api->data_get(flowp, lpr_service_mod.flow_data_index);
    if (!ld)
    {
        ld = (ServiceLPRData*)snort_calloc(sizeof(ServiceLPRData));
        lpr_service_mod.api->data_add(flowp, ld, lpr_service_mod.flow_data_index, &snort_free);
        ld->state = LPR_STATE_COMMAND;
    }

    switch (ld->state)
    {
    case LPR_STATE_COMMAND:
        if (dir != APP_ID_FROM_INITIATOR)
            goto bail;
        if (size < 3)
            goto bail;
        switch (*data)
        {
        case LPR_CMD_RECEIVE:
            if (data[size-1] != 0x0A)
                goto bail;
            size--;
            for (i=1; i<size; i++)
                if (!isprint(data[i]) || isspace(data[i]))
                    goto bail;
            ld->state = LPR_STATE_REPLY;
            break;
        case LPR_CMD_PRINT:
            ld->state = LPR_STATE_IGNORE;
            break;
        case LPR_CMD_SHORT_STATE:
            ld->state = LPR_STATE_IGNORE;
            break;
        case LPR_CMD_LONG_STATE:
            ld->state = LPR_STATE_IGNORE;
            break;
        case LPR_CMD_REMOVE:
            ld->state = LPR_STATE_IGNORE;
            break;
        default:
            goto bail;
        }
        break;
    case LPR_STATE_RECEIVE:
        if (dir != APP_ID_FROM_INITIATOR)
            goto inprocess;
        if (size < 2)
            goto bail;
        switch (*data)
        {
        case LPR_SUBCMD_ABORT:
            if (size != 2)
                goto bail;
            if (data[1] != 0x0A)
                goto bail;
            ld->state = LPR_STATE_REPLY;
            break;
        case LPR_SUBCMD_CONTROL:
        case LPR_SUBCMD_DATA:
            if (size < 5)
                goto bail;
            if (data[size-1] != 0x0A)
                goto bail;
            if (!isdigit(data[1]))
                goto bail;
            for (i=2; i<size; i++)
            {
                if (data[i] == 0x0A)
                    goto bail;
                else if (isspace(data[i]))
                    break;
                if (!isdigit(data[i]))
                    goto bail;
            }
            i++;
            if (i >= size)
                goto bail;
            for (; i<size-1; i++)
                if (!isprint(data[i]) || isspace(data[i]))
                    goto bail;
            ld->state = LPR_STATE_REPLY1;
            break;
        default:
            goto bail;
        }
        break;
    case LPR_STATE_REPLY1:
        if (dir != APP_ID_FROM_RESPONDER)
            goto inprocess;
        if (size != 1)
            goto fail;
        ld->count++;
        if (ld->count >= LPR_COUNT_THRESHOLD)
        {
            ld->state = LPR_STATE_IGNORE;
            goto success;
        }
        ld->state = LPR_STATE_REPLY;
        break;
    case LPR_STATE_REPLY:
        if (dir != APP_ID_FROM_RESPONDER)
            goto inprocess;
        if (size != 1)
            goto fail;
        ld->count++;
        if (ld->count >= LPR_COUNT_THRESHOLD)
        {
            ld->state = LPR_STATE_IGNORE;
            goto success;
        }
        ld->state = LPR_STATE_RECEIVE;
        break;
    case LPR_STATE_IGNORE:
        break;
    default:
        goto bail;
    }
inprocess:
    lpr_service_mod.api->service_inprocess(flowp, args->pkt, dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    lpr_service_mod.api->add_service(flowp, args->pkt, dir, &svc_element,
        APP_ID_PRINTSRV, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

fail:
    lpr_service_mod.api->fail_service(flowp, args->pkt, dir, &svc_element,
        lpr_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;

bail:
    lpr_service_mod.api->incompatible_data(flowp, args->pkt, dir, &svc_element,
        lpr_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOT_COMPATIBLE;
}

