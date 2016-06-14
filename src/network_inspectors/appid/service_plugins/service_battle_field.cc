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

// service_battle_field.cc author Sourcefire Inc.

#include "service_battle_field.h"
#include "application_ids.h"

#include "main/snort_debug.h"
#include "utils/util.h"

enum CONNECTION_STATES
{
    CONN_STATE_INIT,
    CONN_STATE_HELLO_DETECTED,
    CONN_STATE_SERVICE_DETECTED,
    CONN_STATE_MESSAGE_DETECTED,
    CONN_STATE_MAX
};

static const unsigned MAX_PACKET_INSPECTION_COUNT = 10;

struct ServiceData
{
    uint32_t state;
    uint32_t messageId;
    uint32_t packetCount;
};

static int battle_field_init(const IniServiceAPI* const init_api);
static int battle_field_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &battle_field_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "battle_field"
};

static RNAServiceValidationPort pp[] =
{
    { &battle_field_validate, 4711,  IpProtocol::TCP, 0 },
    { &battle_field_validate, 16567, IpProtocol::UDP, 0 },
    { &battle_field_validate, 27900, IpProtocol::UDP, 0 },
    { &battle_field_validate, 27900, IpProtocol::TCP, 0 },
    { &battle_field_validate, 29900, IpProtocol::UDP, 0 },
    { &battle_field_validate, 29900, IpProtocol::TCP, 0 },
    { &battle_field_validate, 27901, IpProtocol::TCP, 0 },
    { &battle_field_validate, 28910, IpProtocol::UDP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

static const char PATTERN_HELLO[] = "battlefield2\x00";
static const char PATTERN_2[] = "\xfe\xfd";
static const char PATTERN_3[] = "\x11\x20\x00\x01\x00\x00\x50\xb9\x10\x11";
static const char PATTERN_4[] = "\x11\x20\x00\x01\x00\x00\x30\xb9\x10\x11";
static const char PATTERN_5[] = "\x11\x20\x00\x01\x00\x00\xa0\x98\x00\x11";
static const char PATTERN_6[] = "\xfe\xfd\x09\x00\x00\x00\x00";

RNAServiceValidationModule battlefield_service_mod =
{
    "BattleField",
    &battle_field_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_BATTLEFIELD, 0 }
};

static int battle_field_init(const IniServiceAPI* const init_api)
{
    init_api->RegisterPattern(&battle_field_validate, IpProtocol::TCP, (uint8_t*)PATTERN_HELLO,
        sizeof(PATTERN_HELLO)-1,  5, "battle_field", init_api->pAppidConfig);
    init_api->RegisterPattern(&battle_field_validate, IpProtocol::TCP, (uint8_t*)PATTERN_2,
        sizeof(PATTERN_2)-1,  0, "battle_field", init_api->pAppidConfig);
    init_api->RegisterPattern(&battle_field_validate, IpProtocol::TCP, (uint8_t*)PATTERN_3,
        sizeof(PATTERN_3)-1,  0, "battle_field", init_api->pAppidConfig);
    init_api->RegisterPattern(&battle_field_validate, IpProtocol::TCP, (uint8_t*)PATTERN_4,
        sizeof(PATTERN_4)-1,  0, "battle_field", init_api->pAppidConfig);
    init_api->RegisterPattern(&battle_field_validate, IpProtocol::TCP, (uint8_t*)PATTERN_5,
        sizeof(PATTERN_5)-1,  0, "battle_field", init_api->pAppidConfig);
    init_api->RegisterPattern(&battle_field_validate, IpProtocol::TCP, (uint8_t*)PATTERN_6,
        sizeof(PATTERN_6)-1,  0, "battle_field", init_api->pAppidConfig);

    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&battle_field_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int battle_field_validate(ServiceValidationArgs* args)
{
    ServiceData* fd;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    Packet* pkt = args->pkt;
    uint16_t size = args->size;

    if (!size)
    {
        goto inprocess_nofd;
    }

    fd = (ServiceData*)battlefield_service_mod.api->data_get(flowp,
        battlefield_service_mod.flow_data_index);
    if (!fd)
    {
        fd = (ServiceData*)snort_calloc(sizeof(ServiceData));
        battlefield_service_mod.api->data_add(flowp, fd,
            battlefield_service_mod.flow_data_index, &snort_free);
    }

    switch (fd->state)
    {
    case CONN_STATE_INIT:
        if ((pkt->ptrs.sp >= 27000 || pkt->ptrs.dp >= 27000) && size >= 4)
        {
            if (data[0] == 0xfe && data[1] == 0xfd)
            {
                fd->messageId = (data[2]<<8) | data[3];
                fd->state = CONN_STATE_MESSAGE_DETECTED;
                goto inprocess;
            }
        }

        if (size == 18 &&  memcmp(data+5, PATTERN_HELLO, sizeof(PATTERN_HELLO)-1) == 0)
        {
            fd->state = CONN_STATE_HELLO_DETECTED;
            goto inprocess;
        }
        break;

    case CONN_STATE_MESSAGE_DETECTED:
        if (size > 8)
        {
            if ((uint32_t)(data[0]<<8 | data[1]) == fd->messageId)
            {
                goto success;
            }

            if (data[0] == 0xfe && data[1] == 0xfd)
            {
                fd->messageId = (data[2]<<8) | data[3];
                goto inprocess;
            }
        }

        fd->state = CONN_STATE_INIT;
        goto inprocess;
        break;

    case CONN_STATE_HELLO_DETECTED:
        if ((size == 7) && (memcmp(data, PATTERN_6, sizeof(PATTERN_6)-1) == 0))
        {
            goto success;
        }

        if ((size > 10)
            && ((memcmp(data, PATTERN_3, sizeof(PATTERN_3)-1) == 0)
            || (memcmp(data, PATTERN_4, sizeof(PATTERN_4)-1) == 0)
            || (memcmp(data, PATTERN_5, sizeof(PATTERN_5)-1) == 0)))
        {
            goto success;
        }
        break;
    case CONN_STATE_SERVICE_DETECTED:
        goto success;
    }

    battlefield_service_mod.api->fail_service(flowp, pkt, args->dir, &svc_element,
        battlefield_service_mod.flow_data_index,
        args->pConfig);
    return SERVICE_NOMATCH;

inprocess:
    fd->packetCount++;
    if (fd->packetCount >= MAX_PACKET_INSPECTION_COUNT)
        goto fail;
inprocess_nofd:
    battlefield_service_mod.api->service_inprocess(flowp, pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    if (args->dir != APP_ID_FROM_RESPONDER)
    {
        fd->state = CONN_STATE_SERVICE_DETECTED;
        goto inprocess;
    }

    battlefield_service_mod.api->add_service(flowp, pkt, args->dir, &svc_element,
        APP_ID_BATTLEFIELD, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

fail:
    battlefield_service_mod.api->fail_service(flowp, pkt, args->dir, &svc_element,
        battlefield_service_mod.flow_data_index,
        args->pConfig);
    return SERVICE_NOMATCH;
}

