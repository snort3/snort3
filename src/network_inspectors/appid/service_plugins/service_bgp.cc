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

// service_bgp.cc author Sourcefire Inc.

#include "service_bgp.h"
#include "application_ids.h"

#include "main/snort_debug.h"
#include "utils/util.h"

static const unsigned BGP_PORT = 179;

static const unsigned BGP_V1_TYPE_OPEN = 1;
static const unsigned BGP_V1_TYPE_OPEN_CONFIRM = 5;
static const unsigned BGP_TYPE_OPEN = 1;
static const unsigned BGP_TYPE_KEEPALIVE = 4;

static const unsigned BGP_OPEN_LINK_MAX = 3;

static const unsigned BGP_VERSION_MAX = 4;
static const unsigned BGP_VERSION_MIN = 2;

enum BGPState
{
    BGP_STATE_CONNECTION,
    BGP_STATE_OPENSENT
};

#pragma pack(1)

struct ServiceBGPData
{
    BGPState state;
    int v1;
};

union ServiceBGPHeader
{
    struct
    {
        uint16_t marker;
        uint16_t len;
        uint8_t version;
        uint8_t type;
        uint16_t hold;
    } v1;
    struct
    {
        uint32_t marker[4];
        uint16_t len;
        uint8_t type;
    } v;
};

struct ServiceBGPOpen
{
    uint8_t version;
    uint16_t as;
    uint16_t holdtime;
};

struct ServiceBGPV1Open
{
    uint16_t system;
    uint8_t link;
    uint8_t auth;
};

#pragma pack()

static int bgp_init(const IniServiceAPI* const init_api);
static int bgp_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &bgp_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "bgp"
};

static RNAServiceValidationPort pp[] =
{
    { &bgp_validate, BGP_PORT, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule bgp_service_mod =
{
    "BGP",
    &bgp_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static uint8_t BGP_PATTERN[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_BGP, 0 }
};

static int bgp_init(const IniServiceAPI* const init_api)
{
    init_api->RegisterPattern(&bgp_validate, IpProtocol::TCP, BGP_PATTERN, sizeof(BGP_PATTERN), 0,
        "bgp", init_api->pAppidConfig);
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&bgp_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int bgp_validate(ServiceValidationArgs* args)
{
    ServiceBGPData* bd;
    const ServiceBGPHeader* bh;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    uint16_t size = args->size;
    uint16_t len;

    if (!size)
        goto inprocess;
    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    if (size < sizeof(ServiceBGPHeader))
        goto fail;

    bd = (ServiceBGPData*)bgp_service_mod.api->data_get(flowp, bgp_service_mod.flow_data_index);
    if (!bd)
    {
        bd = (ServiceBGPData*)snort_calloc(sizeof(ServiceBGPData));
        bgp_service_mod.api->data_add(flowp, bd, bgp_service_mod.flow_data_index, &snort_free);
        bd->state = BGP_STATE_CONNECTION;
    }

    bh = (const ServiceBGPHeader*)data;
    switch (bd->state)
    {
    case BGP_STATE_CONNECTION:
        if (size >= sizeof(bh->v1) + sizeof(ServiceBGPV1Open) &&
            bh->v1.marker == 0xFFFF &&
            bh->v1.version == 0x01 && bh->v1.type == BGP_V1_TYPE_OPEN)
        {
            ServiceBGPV1Open* open;

            len = ntohs(bh->v1.len);
            if (len > 1024)
                goto fail;
            open = (ServiceBGPV1Open*)(data + sizeof(bh->v1));
            if (open->link > BGP_OPEN_LINK_MAX)
                goto fail;
            bd->v1 = 1;
        }
        else if (size >= sizeof(bh->v) + sizeof(ServiceBGPOpen) &&
            bh->v.marker[0] == 0xFFFFFFFF &&
            bh->v.marker[1] == 0xFFFFFFFF &&
            bh->v.marker[2] == 0xFFFFFFFF &&
            bh->v.marker[3] == 0xFFFFFFFF &&
            bh->v.type == BGP_TYPE_OPEN)
        {
            ServiceBGPOpen* open;

            len = ntohs(bh->v.len);
            if (len > 4096)
                goto fail;
            open = (ServiceBGPOpen*)(data + sizeof(bh->v));
            if (open->version > BGP_VERSION_MAX ||
                open->version < BGP_VERSION_MIN)
            {
                goto fail;
            }
            bd->v1 = 0;
        }
        else
            goto fail;
        bd->state = BGP_STATE_OPENSENT;
        break;
    case BGP_STATE_OPENSENT:
        if (bd->v1)
        {
            if (size >= sizeof(bh->v1) && bh->v1.marker == 0xFFFF &&
                bh->v1.version == 0x01 &&
                bh->v1.type == BGP_V1_TYPE_OPEN_CONFIRM)
            {
                len = ntohs(bh->v1.len);
                if (len != sizeof(bh->v1))
                    goto fail;
                goto success;
            }
        }
        else
        {
            if (size >= sizeof(bh->v) &&
                bh->v.type == BGP_TYPE_KEEPALIVE)
            {
                len = ntohs(bh->v.len);
                if (len != sizeof(bh->v))
                    goto fail;
                goto success;
            }
        }
    default:
        goto fail;
    }

inprocess:
    bgp_service_mod.api->service_inprocess(flowp, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

fail:
    bgp_service_mod.api->fail_service(flowp, args->pkt, args->dir, &svc_element,
        bgp_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;

success:
    bgp_service_mod.api->add_service(flowp, args->pkt, args->dir, &svc_element,
        APP_ID_BGP, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;
}

