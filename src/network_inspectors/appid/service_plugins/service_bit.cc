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

// service_bit.cc author Sourcefire Inc.

#include "main/snort_debug.h"
#include "utils/util.h"
#include "application_ids.h"
#include "service_api.h"

static const char svc_name[] = "bt";
static const uint8_t BIT_BANNER[]  = "\023BitTorrent protocol";

#define BIT_PORT    6881

#define BIT_BANNER_LEN (sizeof(BIT_BANNER)-1)
#define RES_LEN 8
#define SHA_LEN 20
#define PEER_ID_LEN 20
#define LAST_BANNER_OFFSET      (BIT_BANNER_LEN+RES_LEN+SHA_LEN+PEER_ID_LEN - 1)

enum BITState
{
    BIT_STATE_BANNER,
    BIT_STATE_BANNER_DC,
    BIT_STATE_MESSAGE_LEN,
    BIT_STATE_MESSAGE_DATA
};

struct ServiceBITData
{
    BITState state;
    unsigned stringlen;
    unsigned pos;
    union
    {
        uint32_t len;
        uint8_t raw_len[4];
    } l;
};

#pragma pack(1)
struct ServiceBITMsg
{
    uint32_t len;
    uint8_t code;
};
#pragma pack()

static int bit_init(const IniServiceAPI* const init_api);
static int bit_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &bit_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "bit"
};

static RNAServiceValidationPort pp[] =
{
    { &bit_validate, BIT_PORT, IpProtocol::TCP, 0 },
    { &bit_validate, BIT_PORT+1, IpProtocol::TCP, 0 },
    { &bit_validate, BIT_PORT+2, IpProtocol::TCP, 0 },
    { &bit_validate, BIT_PORT+3, IpProtocol::TCP, 0 },
    { &bit_validate, BIT_PORT+4, IpProtocol::TCP, 0 },
    { &bit_validate, BIT_PORT+5, IpProtocol::TCP, 0 },
    { &bit_validate, BIT_PORT+6, IpProtocol::TCP, 0 },
    { &bit_validate, BIT_PORT+7, IpProtocol::TCP, 0 },
    { &bit_validate, BIT_PORT+8, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

// FIXIT - Why is there no service_bit.h that declares this extern like all the others?
SO_PUBLIC RNAServiceValidationModule bit_service_mod =
{
    svc_name,
    &bit_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_BITTORRENT, 0 }
};

static int bit_init(const IniServiceAPI* const init_api)
{
    init_api->RegisterPattern(&bit_validate, IpProtocol::TCP, (const uint8_t*)BIT_BANNER,
        sizeof(BIT_BANNER)-1, 0, svc_name, init_api->pAppidConfig);
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&bit_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int bit_validate(ServiceValidationArgs* args)
{
    ServiceBITData* ss;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    uint16_t size = args->size;
    uint16_t offset;

    if (!size)
        goto inprocess;
    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    ss = (ServiceBITData*)bit_service_mod.api->data_get(flowp, bit_service_mod.flow_data_index);
    if (!ss)
    {
        ss = (ServiceBITData*)snort_calloc(sizeof(ServiceBITData));
        bit_service_mod.api->data_add(flowp, ss, bit_service_mod.flow_data_index, &snort_free);
        ss->state = BIT_STATE_BANNER;
    }

    offset = 0;
    while (offset < size)
    {
        switch (ss->state)
        {
        case BIT_STATE_BANNER:
            if (data[offset] !=  BIT_BANNER[ss->pos])
                goto fail;
            if (ss->pos == BIT_BANNER_LEN-1)
                ss->state = BIT_STATE_BANNER_DC;
            ss->pos++;
            break;
        case BIT_STATE_BANNER_DC:
            if (ss->pos == LAST_BANNER_OFFSET)
            {
                ss->pos = 0;
                ss->state = BIT_STATE_MESSAGE_LEN;
                break;
            }
            ss->pos++;
            break;
        case BIT_STATE_MESSAGE_LEN:
            ss->l.raw_len[ss->pos] = data[offset];
            ss->pos++;
            if (ss->pos >= offsetof(ServiceBITMsg, code))
            {
                ss->stringlen = ntohl(ss->l.len);
                ss->state = BIT_STATE_MESSAGE_DATA;
                if (!ss->stringlen)
                {
                    if (offset == size-1)
                        goto success;
                    goto fail;
                }
                ss->pos = 0;
            }
            break;

        case BIT_STATE_MESSAGE_DATA:
            ss->pos++;
            if (ss->pos == ss->stringlen)
                goto success;
            break;
        default:
            goto fail;
        }
        offset++;
    }

inprocess:
    bit_service_mod.api->service_inprocess(flowp, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    bit_service_mod.api->add_service(flowp, args->pkt, args->dir, &svc_element,
        APP_ID_BITTORRENT, nullptr, nullptr,  nullptr);
    return SERVICE_SUCCESS;

fail:
    bit_service_mod.api->fail_service(flowp, args->pkt, args->dir, &svc_element,
        bit_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

