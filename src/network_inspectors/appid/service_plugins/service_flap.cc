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

// service_flap.cc author Sourcefire Inc.

#include "service_flap.h"
#include "application_ids.h"

#include "main/snort_debug.h"
#include "utils/util.h"

#define FLAP_PORT   5190

enum FLAPState
{
    FLAP_STATE_ACK,
    FLAP_STATE_COOKIE
};

#define FNAC_SIGNON 0x0017
#define FNAC_GENERIC 0x0001
#define FNAC_SUB_SIGNON_REPLY 0x0007
#define FNAC_SUB_SERVER_READY 0x0003

struct ServiceFLAPData
{
    FLAPState state;
};

#pragma pack(1)

struct FLAPFNACSignOn
{
    uint16_t len;
};

struct FLAPFNAC
{
    uint16_t family;
    uint16_t subtype;
    uint16_t flags;
    uint32_t id;
};

struct FLAPTLV
{
    uint16_t subtype;
    uint16_t len;
};

struct FLAPHeader
{
    uint8_t start;
    uint8_t type;
    uint16_t seq;
    uint16_t len;
};

#pragma pack()

static int flap_init(const IniServiceAPI* const init_api);
static int flap_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &flap_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "flap"
};

static RNAServiceValidationPort pp[] =
{
    { &flap_validate, 5190, IpProtocol::TCP, 0 },
    { &flap_validate, 9898, IpProtocol::TCP, 0 },
    { &flap_validate, 4443, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule flap_service_mod =
{
    "FLAP",
    &flap_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static uint8_t FLAP_PATTERN[] = { 0x2A, 0x01 };

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_AOL_INSTANT_MESSENGER, 0 }
};

static int flap_init(const IniServiceAPI* const init_api)
{
    init_api->RegisterPattern(&flap_validate, IpProtocol::TCP, FLAP_PATTERN,
            sizeof(FLAP_PATTERN), 0, "flap", init_api->pAppidConfig);
    //unsigned i;
    for (unsigned i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&flap_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int flap_validate(ServiceValidationArgs* args)
{
    ServiceFLAPData* sf;
    const uint8_t* data = args->data;
    const FLAPHeader* hdr = (const FLAPHeader*)args->data;
    const FLAPFNAC* ff;
    const FLAPTLV* tlv;
    AppIdData* flowp = args->flowp;
    uint16_t size = args->size;
    uint16_t len;

    if (!size)
        goto inprocess;
    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    sf = (ServiceFLAPData*)flap_service_mod.api->data_get(flowp, flap_service_mod.flow_data_index);
    if (!sf)
    {
        sf = (ServiceFLAPData*)snort_calloc(sizeof(ServiceFLAPData));
        flap_service_mod.api->data_add(flowp, sf, flap_service_mod.flow_data_index, &snort_free);
        sf->state = FLAP_STATE_ACK;
    }

    switch (sf->state)
    {
    case FLAP_STATE_ACK:
        sf->state = FLAP_STATE_COOKIE;
        if (size < sizeof(FLAPHeader))
            goto fail;
        if (hdr->start != 0x2A)
            goto fail;
        if (hdr->type != 0x01)
            goto fail;
        if (ntohs(hdr->len) != 4)
            goto fail;
        if (size - sizeof(FLAPHeader) != 4)
            goto fail;
        if (ntohl(*((uint32_t*)(data + sizeof(FLAPHeader)))) != 0x00000001)
            goto fail;
        goto inprocess;
    case FLAP_STATE_COOKIE:
        if (size < sizeof(FLAPHeader) + sizeof(FLAPFNAC))
            goto fail;
        if (hdr->start != 0x2A)
            goto fail;
        if ((uint16_t)ntohs(hdr->len) != (uint16_t)(size - sizeof(FLAPHeader)))
            goto fail;
        if (hdr->type == 0x02)
        {
            ff = (FLAPFNAC*)(data + sizeof(FLAPHeader));
            if (ntohs(ff->family) == FNAC_SIGNON)
            {
                FLAPFNACSignOn* ffs = (FLAPFNACSignOn*)((uint8_t*)ff + sizeof(FLAPFNAC));

                if (ntohs(ff->subtype) != FNAC_SUB_SIGNON_REPLY)
                    goto fail;
                if ((uint16_t)ntohs(ffs->len) != (uint16_t)(size -
                    (sizeof(FLAPHeader) +
                    sizeof(FLAPFNAC) +
                    sizeof(FLAPFNACSignOn))))
                    goto fail;
            }
            else if (ntohs(ff->family) == FNAC_GENERIC)
            {
                if (ntohs(ff->subtype) != FNAC_SUB_SERVER_READY)
                    goto fail;
            }
            else
                goto fail;
            goto success;
        }
        if (hdr->type == 0x04)
        {
            data += sizeof(FLAPHeader);
            size -= sizeof(FLAPHeader);
            while (size >= sizeof(FLAPTLV))
            {
                tlv = (FLAPTLV*)data;
                data += sizeof(FLAPTLV);
                size -= sizeof(FLAPTLV);
                len = ntohs(tlv->len);
                if (size < len)
                    goto fail;
                size -= len;
                data += len;
            }
            if (size)
                goto fail;
            goto success;
        }
        goto fail;
    }

fail:
    flap_service_mod.api->fail_service(flowp, args->pkt, args->dir, &svc_element,
        flap_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;

success:
    flap_service_mod.api->add_service(flowp, args->pkt, args->dir, &svc_element,
        APP_ID_AOL_INSTANT_MESSENGER, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

inprocess:
    flap_service_mod.api->service_inprocess(flowp, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;
}

