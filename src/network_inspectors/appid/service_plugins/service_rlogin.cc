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

// service_rlogin.cc author Sourcefire Inc.

#include "service_rlogin.h"

#include "service_api.h"
#include "application_ids.h"

#include "main/snort_debug.h"
#include "protocols/tcp.h"
#include "utils/util.h"

#define RLOGIN_PASSWORD "Password: "
enum RLOGINState
{
    RLOGIN_STATE_HANDSHAKE,
    RLOGIN_STATE_PASSWORD,
    RLOGIN_STATE_CRLF,
    RLOGIN_STATE_DATA,
    RLOGIN_STATE_DONE
};

struct ServiceRLOGINData
{
    RLOGINState state;
};

static int rlogin_init(const IniServiceAPI* const init_api);
static int rlogin_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &rlogin_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "rlogin"
};

static RNAServiceValidationPort pp[] =
{
    { &rlogin_validate, 513, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule rlogin_service_mod =
{
    "RLOGIN",
    &rlogin_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_RLOGIN, 0 }
};

static int rlogin_init(const IniServiceAPI* const init_api)
{
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&rlogin_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int rlogin_validate(ServiceValidationArgs* args)
{
    ServiceRLOGINData* rd;
    AppIdData* flowp = args->flowp;
    Packet* pkt = args->pkt;
    const uint8_t* data = args->data;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;
    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    rd = (ServiceRLOGINData*)rlogin_service_mod.api->data_get(flowp,
        rlogin_service_mod.flow_data_index);
    if (!rd)
    {
        rd = (ServiceRLOGINData*)snort_calloc(sizeof(ServiceRLOGINData));
        rlogin_service_mod.api->data_add(flowp, rd, rlogin_service_mod.flow_data_index,
            &snort_free);
        rd->state = RLOGIN_STATE_HANDSHAKE;
    }

    switch (rd->state)
    {
    case RLOGIN_STATE_HANDSHAKE:
        if (size != 1)
            goto fail;
        if (*data)
            goto fail;
        rd->state = RLOGIN_STATE_PASSWORD;
        break;
    case RLOGIN_STATE_PASSWORD:
        if (pkt->ptrs.tcph->are_flags_set(TH_URG) && size >= pkt->ptrs.tcph->urp())
        {
            if (size != 1)
                goto fail;
            if (*data != 0x80)
                goto fail;
            rd->state = RLOGIN_STATE_DATA;
        }
        else
        {
            if (size != sizeof(RLOGIN_PASSWORD)-1)
                goto fail;
            if (strncmp((char*)data, RLOGIN_PASSWORD, sizeof(RLOGIN_PASSWORD)-1))
                goto fail;
            rd->state = RLOGIN_STATE_CRLF;
        }
        break;
    case RLOGIN_STATE_CRLF:
        if (size != 2)
            goto fail;
        if (*data != 0x0A || *(data+1) != 0x0D)
            goto fail;
        rd->state = RLOGIN_STATE_DATA;
        break;
    case RLOGIN_STATE_DATA:
        rd->state = RLOGIN_STATE_DONE;
        goto success;
    default:
        goto fail;
    }

inprocess:
    rlogin_service_mod.api->service_inprocess(flowp, pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    rlogin_service_mod.api->add_service(flowp, pkt, args->dir, &svc_element,
        APP_ID_RLOGIN, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

fail:
    rlogin_service_mod.api->fail_service(flowp, pkt, args->dir, &svc_element,
        rlogin_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

