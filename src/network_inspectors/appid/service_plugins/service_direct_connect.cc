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

// service_direct_connect.cc author Sourcefire Inc.

#include "service_direct_connect.h"
#include "application_ids.h"

#include "main/snort_debug.h"
#include "utils/util.h"

enum CONNECTION_STATES
{
    CONN_STATE_INIT,
    CONN_STATE_1,
    CONN_STATE_2,
    CONN_STATE_SERVICE_DETECTED,
    CONN_STATE_MAX
};

#define MAX_PACKET_INSPECTION_COUNT      10

struct ServiceData
{
    uint32_t state;
    uint32_t packetCount;
};

static int direct_connect_init(const IniServiceAPI* const init_api);
static int direct_connect_validate(ServiceValidationArgs* args);
static int validateDirectConnectTcp(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, const Packet* pkt, ServiceData* serviceData,
    const AppIdConfig* pConfig);
static int validateDirectConnectUdp(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, const Packet* pkt, ServiceData* serviceData,
    const AppIdConfig* pConfig);

static RNAServiceElement svc_element =
{
    nullptr,
    &direct_connect_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "direct_connect"
};

static RNAServiceValidationPort pp[] =
{
    { &direct_connect_validate, 411, IpProtocol::TCP, 0 },
    { &direct_connect_validate, 411, IpProtocol::UDP, 0 },
    { &direct_connect_validate, 412, IpProtocol::TCP, 0 },
    { &direct_connect_validate, 412, IpProtocol::UDP, 0 },
    { &direct_connect_validate, 413, IpProtocol::TCP, 0 },
    { &direct_connect_validate, 413, IpProtocol::UDP, 0 },
    { &direct_connect_validate, 414, IpProtocol::TCP, 0 },
    { &direct_connect_validate, 414, IpProtocol::UDP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

#define PATTERN1     "$Lock "
#define PATTERN2     "$MyNick "
#define PATTERN3     "HSUP ADBAS0"
#define PATTERN4     "HSUP ADBASE"
#define PATTERN5     "CSUP ADBAS0"
#define PATTERN6     "CSUP ADBASE"
#define PATTERN7     "$SR "

RNAServiceValidationModule directconnect_service_mod =
{
    "DirectConnect",
    &direct_connect_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_DIRECT_CONNECT, 0 }
};

static int direct_connect_init(const IniServiceAPI* const init_api)
{
    init_api->RegisterPattern(&direct_connect_validate, IpProtocol::TCP, (uint8_t*)PATTERN1,
        sizeof(PATTERN1)-1,  0, "direct_connect", init_api->pAppidConfig);
    init_api->RegisterPattern(&direct_connect_validate, IpProtocol::TCP, (uint8_t*)PATTERN2,
        sizeof(PATTERN2)-1,  0, "direct_connect", init_api->pAppidConfig);
    init_api->RegisterPattern(&direct_connect_validate, IpProtocol::TCP, (uint8_t*)PATTERN3,
        sizeof(PATTERN3)-1,  0, "direct_connect", init_api->pAppidConfig);
    init_api->RegisterPattern(&direct_connect_validate, IpProtocol::TCP, (uint8_t*)PATTERN4,
        sizeof(PATTERN4)-1,  0, "direct_connect", init_api->pAppidConfig);
    init_api->RegisterPattern(&direct_connect_validate, IpProtocol::TCP, (uint8_t*)PATTERN5,
        sizeof(PATTERN5)-1,  0, "direct_connect", init_api->pAppidConfig);
    init_api->RegisterPattern(&direct_connect_validate, IpProtocol::TCP, (uint8_t*)PATTERN6,
        sizeof(PATTERN6)-1,  0, "direct_connect", init_api->pAppidConfig);
    init_api->RegisterPattern(&direct_connect_validate, IpProtocol::UDP, (uint8_t*)PATTERN7,
        sizeof(PATTERN7)-1,  0, "direct_connect", init_api->pAppidConfig);

    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&direct_connect_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int direct_connect_validate(ServiceValidationArgs* args)
{
    ServiceData* fd;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    uint16_t size = args->size;

    if (!size)
    {
        directconnect_service_mod.api->service_inprocess(flowp, args->pkt, args->dir,
            &svc_element);
        return SERVICE_INPROCESS;
    }

    fd = (ServiceData*)directconnect_service_mod.api->data_get(flowp,
        directconnect_service_mod.flow_data_index);
    if (!fd)
    {
        fd = (ServiceData*)snort_calloc(sizeof(ServiceData));
        directconnect_service_mod.api->data_add(flowp, fd,
            directconnect_service_mod.flow_data_index, &snort_free);
    }

    if (flowp->proto == IpProtocol::TCP)
        return validateDirectConnectTcp(data, size, args->dir, flowp, args->pkt, fd,
            args->pConfig);
    else
        return validateDirectConnectUdp(data, size, args->dir, flowp, args->pkt, fd,
            args->pConfig);
}

static int validateDirectConnectTcp(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, const Packet* pkt, ServiceData* serviceData,
    const AppIdConfig* pConfig)
{
    switch (serviceData->state)
    {
    case CONN_STATE_INIT:
        if (size > 6
            && data[size-2] == '|'
            && data[size-1] == '$')
        {
            if (memcmp(data, PATTERN1, sizeof(PATTERN1)-1) == 0)
            {
                printf("maybe first directconnect to hub  detected\n");
                serviceData->state = CONN_STATE_1;
                goto inprocess;
            }

            if (memcmp(data, PATTERN2, sizeof(PATTERN2)-1) == 0)
            {
                printf("maybe first dc connect between peers  detected\n");
                serviceData->state = CONN_STATE_2;
                goto inprocess;
            }
        }

        if (size >= 11)
        {
            if (memcmp(data, PATTERN3, sizeof(PATTERN3)-1) == 0
                || memcmp(data, PATTERN4, sizeof(PATTERN4)-1) == 0
                || memcmp(data, PATTERN5, sizeof(PATTERN5)-1) == 0
                || memcmp(data, PATTERN6, sizeof(PATTERN6)-1) == 0)
            {
                goto success;
            }
        }
        break;

    case CONN_STATE_1:
        printf ("ValidateDirectConnectTcp(): state 1 size %d\n", size);
        if (size >= 11)
        {
            if (memcmp(data, PATTERN3, sizeof(PATTERN3)-1) == 0
                || memcmp(data, PATTERN4, sizeof(PATTERN4)-1) == 0
                || memcmp(data, PATTERN5, sizeof(PATTERN5)-1) == 0
                || memcmp(data, PATTERN6, sizeof(PATTERN6)-1) == 0)
            {
                printf("found directconnect HSUP ADBAS E in second packet\n");
                goto success;
            }
        }

        if (size > 6)
        {
            if ((data[0] == '$' || data[0] == '<')
                && data[size-2] == '|'
                && data[size-1] == '$')
            {
                goto success;
            }
            else
            {
                goto inprocess;
            }
        }
        break;

    case CONN_STATE_2:
        if (size > 6)
        {
            if (data[0] == '$' && data[size-2] == '|' && data[size-1] == '$')
            {
                goto success;
            }
            else
            {
                goto inprocess;
            }
        }
        break;

    case CONN_STATE_SERVICE_DETECTED:
        goto success;
    }

inprocess:
    serviceData->packetCount++;
    if (serviceData->packetCount >= MAX_PACKET_INSPECTION_COUNT)
        goto fail;

    directconnect_service_mod.api->service_inprocess(flowp, pkt, dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    if (dir != APP_ID_FROM_RESPONDER)
    {
        serviceData->state = CONN_STATE_SERVICE_DETECTED;
        goto inprocess;
    }

    directconnect_service_mod.api->add_service(flowp, pkt, dir, &svc_element,
        APP_ID_DIRECT_CONNECT, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

fail:
    directconnect_service_mod.api->fail_service(flowp, pkt, dir, &svc_element,
        directconnect_service_mod.flow_data_index, pConfig);
    return SERVICE_NOMATCH;
}

static int validateDirectConnectUdp(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, const Packet* pkt, ServiceData* serviceData,
    const AppIdConfig* pConfig)
{
    if (dir == APP_ID_FROM_RESPONDER && serviceData->state == CONN_STATE_SERVICE_DETECTED)
    {
        goto reportSuccess;
    }

    if (size > 58)
    {
        if (memcmp(data, PATTERN7, sizeof(PATTERN7)-1) == 0
            && data[size-3] == ')'
            && data[size-2] == '|'
            && data[size-1] == '$')
        {
            goto success;
        }
        serviceData->state +=  1;

        if (serviceData->state != CONN_STATE_SERVICE_DETECTED)
            goto inprocess;
        else
            goto fail;
    }

inprocess:
    serviceData->packetCount++;
    if (serviceData->packetCount >= MAX_PACKET_INSPECTION_COUNT)
        goto fail;

    directconnect_service_mod.api->service_inprocess(flowp, pkt, dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    if (dir != APP_ID_FROM_RESPONDER)
    {
        serviceData->state = CONN_STATE_SERVICE_DETECTED;
        goto inprocess;
    }

reportSuccess:
    directconnect_service_mod.api->add_service(flowp, pkt, dir, &svc_element,
        APP_ID_DIRECT_CONNECT, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

fail:
    directconnect_service_mod.api->fail_service(flowp, pkt, dir, &svc_element,
        directconnect_service_mod.flow_data_index, pConfig);
    return SERVICE_NOMATCH;
}

