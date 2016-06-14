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

// service_ntp.cc author Sourcefire Inc.

#include "service_ntp.h"

#include "main/snort_debug.h"

#include "appid_flow_data.h"
#include "application_ids.h"
#include "service_api.h"

#pragma pack(1)

struct ServiceNTPTimestamp
{
    uint32_t sec;
    uint32_t frac;
};

struct ServiceNTPHeader
{
    uint8_t LVM;
    uint8_t stratum;
    uint8_t poll;
    int8_t precision;
    uint32_t delay;
    uint32_t dispersion;
    uint32_t id;
    ServiceNTPTimestamp ref;
    ServiceNTPTimestamp orig;
    ServiceNTPTimestamp recv;
    ServiceNTPTimestamp xmit;
};

struct ServiceNTPOptional
{
    uint32_t keyid;
    uint32_t digest[4];
};

#pragma pack()

static int ntp_init(const IniServiceAPI* const init_api);
static int ntp_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &ntp_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "ntp"
};

static RNAServiceValidationPort pp[] =
{
    { &ntp_validate, 123, IpProtocol::UDP, 0 },
    { &ntp_validate, 123, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule ntp_service_mod =
{
    "NTP",
    &ntp_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_NTP, 0 }
};

static int ntp_init(const IniServiceAPI* const init_api)
{
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&ntp_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int ntp_validate(ServiceValidationArgs* args)
{
    const ServiceNTPHeader* nh;
    uint8_t ver;
    uint8_t mode;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;
    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    nh = (ServiceNTPHeader*)data;

    mode = nh->LVM & 0x07;
    if (mode == 0 || mode == 7 || mode == 3)
        goto fail;
    ver = nh->LVM & 0x38;
    if (ver > 0x20 || ver < 0x08)
        goto fail;
    if (mode != 6)
    {
        if (ver < 0x18)
        {
            if (size != sizeof(ServiceNTPHeader))
                goto fail;
        }
        else if (size < sizeof(ServiceNTPHeader) ||
            size > sizeof(ServiceNTPHeader)+sizeof(ServiceNTPOptional))
        {
            goto fail;
        }

        if (nh->stratum > 15)
            goto fail;
        if (nh->poll && (nh->poll < 4 || nh->poll > 14))
            goto fail;
        if (nh->precision > -6 || nh->precision < -20)
            goto fail;
    }
    else
    {
        if (size < 2)
            goto fail;
        if (!(nh->stratum & 0x80))
            goto fail;
        if (!(nh->stratum & 0x1F))
            goto fail;
    }

    ntp_service_mod.api->add_service(flowp, args->pkt, args->dir, &svc_element,
        APP_ID_NTP, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

inprocess:
    ntp_service_mod.api->service_inprocess(flowp, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

fail:
    ntp_service_mod.api->fail_service(flowp, args->pkt, args->dir, &svc_element,
        ntp_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

