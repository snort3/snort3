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

// service_mysql.cc author Sourcefire Inc.

#include "service_mysql.h"

#include "main/snort_debug.h"

#include "application_ids.h"
#include "app_info_table.h"
#include "appid_flow_data.h"

#include "service_api.h"

#pragma pack(1)

struct ServiceMYSQLHdr
{
    union
    {
        uint32_t len;
        struct
        {
            uint8_t len[3];
            uint8_t packet;
        } p;
    } l;
    IpProtocol proto;
};

#pragma pack()

static int svc_mysql_init(const IniServiceAPI* const init_api);
static int svc_mysql_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element
{
    nullptr,
    &svc_mysql_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "mysql"
};

static RNAServiceValidationPort pp[]
{
    { &svc_mysql_validate, 3306, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule mysql_service_mod
{
    "MYSQL",
    &svc_mysql_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[]
{
    { APP_ID_MYSQL, APPINFO_FLAG_SERVICE_ADDITIONAL }
};

static int svc_mysql_init(const IniServiceAPI* const init_api)
{
    for ( unsigned i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++ )
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&svc_mysql_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int svc_mysql_validate(ServiceValidationArgs* args)
{
    const uint8_t* data = args->data;
    const ServiceMYSQLHdr* hdr = (const ServiceMYSQLHdr*)data;
    uint32_t len;
    const uint8_t* end;
    const uint8_t* p = nullptr;
    AppIdData* flowp = args->flowp;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;
    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;
    if (size < sizeof(ServiceMYSQLHdr))
        goto fail;

    len = hdr->l.p.len[0];
    len |= hdr->l.p.len[1] << 8;
    len |= hdr->l.p.len[2] << 16;
    len += 4;
    if (len > size)
        goto fail;
    if (hdr->l.p.packet)
        goto fail;
    if (hdr->proto != (IpProtocol)0x0A)
        goto fail;

    end = data + len;
    data += sizeof(ServiceMYSQLHdr);
    p = data;
    for (; data<end && *data; data++)
    {
        if (!isprint(*data))
            goto fail;
    }
    if (data >= end)
        goto fail;
    if (data == p)
        p = nullptr;
    data += 5;
    if (data >= end)
        goto fail;
    for (; data<end && *data; data++)
    {
        if (!isprint(*data))
            goto fail;
    }
    data += 6;
    if (data >= end)
        goto fail;
    mysql_service_mod.api->add_service(flowp, args->pkt, args->dir, &svc_element,
        APP_ID_MYSQL, nullptr, (char*)p, nullptr);
    return SERVICE_SUCCESS;

inprocess:
    mysql_service_mod.api->service_inprocess(flowp, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

fail:
    mysql_service_mod.api->fail_service(flowp, args->pkt, args->dir, &svc_element,
        mysql_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

