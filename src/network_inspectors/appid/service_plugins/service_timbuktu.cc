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

// service_timbuktu.cc author Sourcefire Inc.

#include "appid_flow_data.h"
#include "application_ids.h"
#include "service_api.h"

#include "main/snort_debug.h"
#include "utils/util.h"

static const char svc_name[] = "timbuktu";
static char TIMBUKTU_BANNER[]  = "\001\001";

#define TIMBUKTU_PORT    407

#define TIMBUKTU_BANNER_LEN (sizeof(TIMBUKTU_BANNER)-1)

enum TIMBUKTUState
{
    TIMBUKTU_STATE_BANNER,
    TIMBUKTU_STATE_MESSAGE_LEN,
    TIMBUKTU_STATE_MESSAGE_DATA
};

struct ServiceTIMBUKTUData
{
    TIMBUKTUState state;
    unsigned stringlen;
    unsigned pos;
};

#pragma pack(1)
struct ServiceTIMBUKTUMsg
{
    uint16_t any;
    uint8_t res;
    uint8_t len;
    uint8_t message;
};
#pragma pack()

static int timbuktu_init(const IniServiceAPI* const init_api);
static int timbuktu_validate(ServiceValidationArgs* args);

static const RNAServiceElement svc_element =
{
    nullptr,
    &timbuktu_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "timbuktu"
};

// FIXIT thread safety, can this be const?
static RNAServiceValidationPort pp[] =
{
    { &timbuktu_validate, TIMBUKTU_PORT, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

// FIXIT thread safety, can this be const?
SO_PUBLIC RNAServiceValidationModule timbuktu_service_mod =
{
    svc_name,
    &timbuktu_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static const AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_TIMBUKTU, 0 }
};

static int timbuktu_init(const IniServiceAPI* const init_api)
{
    init_api->RegisterPattern(&timbuktu_validate, IpProtocol::TCP, (const
        u_int8_t*)TIMBUKTU_BANNER,
        sizeof(TIMBUKTU_BANNER)-1, 0, svc_name, init_api->pAppidConfig);
    for (unsigned i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&timbuktu_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int timbuktu_validate(ServiceValidationArgs* args)
{
    ServiceTIMBUKTUData* ss;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    uint16_t size = args->size;
    uint16_t offset=0;

    if (!size)
        goto inprocess;
    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    ss = (ServiceTIMBUKTUData*)timbuktu_service_mod.api->data_get(flowp,
        timbuktu_service_mod.flow_data_index);
    if (!ss)
    {
        ss = (ServiceTIMBUKTUData*)snort_calloc(sizeof(ServiceTIMBUKTUData));
        timbuktu_service_mod.api->data_add(flowp, ss,
            timbuktu_service_mod.flow_data_index, &snort_free);
        ss->state = TIMBUKTU_STATE_BANNER;
    }

    offset = 0;
    while (offset < size)
    {
        switch (ss->state)
        {
        case TIMBUKTU_STATE_BANNER:
            if (data[offset] !=  TIMBUKTU_BANNER[ss->pos])
                goto fail;
            if (ss->pos >= TIMBUKTU_BANNER_LEN-1)
            {
                ss->pos = 0;
                ss->state = TIMBUKTU_STATE_MESSAGE_LEN;
                break;
            }
            ss->pos++;
            break;
        case TIMBUKTU_STATE_MESSAGE_LEN:
            ss->pos++;
            if (ss->pos >= offsetof(ServiceTIMBUKTUMsg, message))
            {
                ss->stringlen = data[offset];
                ss->state = TIMBUKTU_STATE_MESSAGE_DATA;
                if (!ss->stringlen)
                {
                    if (offset == size-1)
                        goto success;
                    goto fail;
                }
                ss->pos = 0;
            }
            break;

        case TIMBUKTU_STATE_MESSAGE_DATA:
            ss->pos++;
            if (ss->pos == ss->stringlen)
            {
                if (offset == (size-1))
                    goto success;
                goto fail;
            }
            break;
        default:
            goto fail;
        }
        offset++;
    }

inprocess:
    timbuktu_service_mod.api->service_inprocess(flowp, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    timbuktu_service_mod.api->add_service(flowp, args->pkt, args->dir, &svc_element,
        APP_ID_TIMBUKTU, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

fail:
    timbuktu_service_mod.api->fail_service(flowp, args->pkt, args->dir, &svc_element,
        timbuktu_service_mod.flow_data_index,
        args->pConfig);
    return SERVICE_NOMATCH;
}

