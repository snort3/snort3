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

// service_radius.cc author Sourcefire Inc.

#include "service_radius.h"

#include "main/snort_debug.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "appid_flow_data.h"
#include "application_ids.h"
#include "service_api.h"

#define RADIUS_CODE_ACCESS_REQUEST       1
#define RADIUS_CODE_ACCESS_ACCEPT        2
#define RADIUS_CODE_ACCESS_REJECT        3
#define RADIUS_CODE_ACCOUNTING_REQUEST   4
#define RADIUS_CODE_ACCOUNTING_RESPONSE  5
#define RADIUS_CODE_ACCESS_CHALLENGE    11

enum RADIUSState
{
    RADIUS_STATE_REQUEST,
    RADIUS_STATE_RESPONSE
};

struct ServiceRADIUSData
{
    RADIUSState state;
    uint8_t id;
};

#pragma pack(1)

struct RADIUSHeader
{
    uint8_t code;
    uint8_t id;
    uint16_t length;
    uint8_t auth[16];
};

#pragma pack()

static int radius_init(const IniServiceAPI* const init_api);
static int radius_validate(ServiceValidationArgs* args);
static int radius_validate_accounting(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &radius_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "radius"
};

static RNAServiceElement acct_svc_element =
{
    nullptr,
    &radius_validate_accounting,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "radacct"
};

static RNAServiceValidationPort pp[] =
{
    { &radius_validate, 1812, IpProtocol::UDP, 0 },
    { &radius_validate, 1812, IpProtocol::UDP, 1 },
    { &radius_validate_accounting, 1813, IpProtocol::UDP, 0 },
    { &radius_validate_accounting, 1813, IpProtocol::UDP, 1 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule radius_service_mod =
{
    "RADIUS",
    &radius_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_RADIUS_ACCT, APPINFO_FLAG_SERVICE_UDP_REVERSED },
    { APP_ID_RADIUS, APPINFO_FLAG_SERVICE_UDP_REVERSED }
};

static int radius_init(const IniServiceAPI* const init_api)
{
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&radius_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int radius_validate(ServiceValidationArgs* args)
{
    ServiceRADIUSData* rd;
    const RADIUSHeader* hdr = (const RADIUSHeader*)args->data;
    uint16_t len;
    int new_dir;
    AppIdData* flowp = args->flowp;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;
    if (size < sizeof(RADIUSHeader))
        goto fail;

    rd = (ServiceRADIUSData*)radius_service_mod.api->data_get(flowp,
        radius_service_mod.flow_data_index);
    if (!rd)
    {
        rd = (ServiceRADIUSData*)snort_calloc(sizeof(ServiceRADIUSData));
        radius_service_mod.api->data_add(flowp, rd, radius_service_mod.flow_data_index,
            &snort_free);
        rd->state = RADIUS_STATE_REQUEST;
    }

    new_dir = dir;
    if (rd->state == RADIUS_STATE_REQUEST)
    {
        if (hdr->code == RADIUS_CODE_ACCESS_ACCEPT ||
            hdr->code == RADIUS_CODE_ACCESS_REJECT ||
            hdr->code == RADIUS_CODE_ACCESS_CHALLENGE)
        {
            setAppIdFlag(flowp, APPID_SESSION_UDP_REVERSED);
            rd->state = RADIUS_STATE_RESPONSE;
            new_dir = APP_ID_FROM_RESPONDER;
        }
    }
    else if (getAppIdFlag(flowp, APPID_SESSION_UDP_REVERSED))
    {
        new_dir = (dir == APP_ID_FROM_RESPONDER) ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    }

    switch (rd->state)
    {
    case RADIUS_STATE_REQUEST:
        if (new_dir != APP_ID_FROM_INITIATOR)
            goto inprocess;
        if (hdr->code != RADIUS_CODE_ACCESS_REQUEST)
        {
            goto not_compatible;
        }
        len = ntohs(hdr->length);
        if (len > size)
        {
            goto not_compatible;
        }
        /* Must contain a username attribute */
        if (len < sizeof(RADIUSHeader)+3)
        {
            goto not_compatible;
        }
        rd->id = hdr->id;
        rd->state = RADIUS_STATE_RESPONSE;
        break;
    case RADIUS_STATE_RESPONSE:
        if (new_dir != APP_ID_FROM_RESPONDER)
            goto inprocess;
        if (hdr->code != RADIUS_CODE_ACCESS_ACCEPT &&
            hdr->code != RADIUS_CODE_ACCESS_REJECT &&
            hdr->code != RADIUS_CODE_ACCESS_CHALLENGE)
        {
            goto fail;
        }
        len = ntohs(hdr->length);
        if (len > size)
            goto fail;
        /* Must contain a username attribute */
        if (len < sizeof(RADIUSHeader))
            goto fail;
        if (hdr->id != rd->id)
        {
            rd->state = RADIUS_STATE_REQUEST;
            goto inprocess;
        }
        goto success;
    default:
        goto fail;
    }
inprocess:
    radius_service_mod.api->service_inprocess(flowp, args->pkt, dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    radius_service_mod.api->add_service(flowp, args->pkt, dir, &svc_element,
        APP_ID_RADIUS, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

not_compatible:
    radius_service_mod.api->incompatible_data(flowp, args->pkt, dir, &svc_element,
        radius_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOT_COMPATIBLE;

fail:
    radius_service_mod.api->fail_service(flowp, args->pkt, dir, &svc_element,
        radius_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

static int radius_validate_accounting(ServiceValidationArgs* args)
{
    ServiceRADIUSData* rd;
    const RADIUSHeader* hdr = (const RADIUSHeader*)args->data;
    uint16_t len;
    int new_dir;
    AppIdData* flowp = args->flowp;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;
    if (size < sizeof(RADIUSHeader))
        goto fail;

    rd = (ServiceRADIUSData*)radius_service_mod.api->data_get(flowp,
        radius_service_mod.flow_data_index);
    if (!rd)
    {
        rd = (ServiceRADIUSData*)snort_calloc(sizeof(ServiceRADIUSData));
        radius_service_mod.api->data_add(flowp, rd, radius_service_mod.flow_data_index,
            &snort_free);
        rd->state = RADIUS_STATE_REQUEST;
    }

    new_dir = dir;
    if (rd->state == RADIUS_STATE_REQUEST)
    {
        if (hdr->code == RADIUS_CODE_ACCOUNTING_RESPONSE)
        {
            setAppIdFlag(flowp, APPID_SESSION_UDP_REVERSED);
            rd->state = RADIUS_STATE_RESPONSE;
            new_dir = APP_ID_FROM_RESPONDER;
        }
    }
    else if (getAppIdFlag(flowp, APPID_SESSION_UDP_REVERSED))
    {
        new_dir = (dir == APP_ID_FROM_RESPONDER) ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    }

    switch (rd->state)
    {
    case RADIUS_STATE_REQUEST:
        if (new_dir != APP_ID_FROM_INITIATOR)
            goto inprocess;
        if (hdr->code != RADIUS_CODE_ACCOUNTING_REQUEST)
        {
            goto not_compatible;
        }
        len = ntohs(hdr->length);
        if (len > size)
        {
            goto not_compatible;
        }
        /* Must contain a username attribute */
        if (len < sizeof(RADIUSHeader)+3)
        {
            goto not_compatible;
        }
        rd->id = hdr->id;
        rd->state = RADIUS_STATE_RESPONSE;
        break;
    case RADIUS_STATE_RESPONSE:
        if (new_dir != APP_ID_FROM_RESPONDER)
            goto inprocess;
        if (hdr->code != RADIUS_CODE_ACCOUNTING_RESPONSE)
            goto fail;
        len = ntohs(hdr->length);
        if (len > size)
            goto fail;
        /* Must contain a NAS-IP-Address or NAS-Identifier attribute */
        if (len < sizeof(RADIUSHeader))
            goto fail;
        if (hdr->id != rd->id)
        {
            rd->state = RADIUS_STATE_REQUEST;
            goto inprocess;
        }
        goto success;
    default:
        goto fail;
    }
inprocess:
    radius_service_mod.api->service_inprocess(flowp, args->pkt, dir, &acct_svc_element);
    return SERVICE_INPROCESS;

success:
    radius_service_mod.api->add_service(flowp, args->pkt, dir, &acct_svc_element,
        APP_ID_RADIUS_ACCT, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

not_compatible:
    radius_service_mod.api->incompatible_data(flowp, args->pkt, dir, &acct_svc_element,
        radius_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOT_COMPATIBLE;

fail:
    radius_service_mod.api->fail_service(flowp, args->pkt, dir, &acct_svc_element,
        radius_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

