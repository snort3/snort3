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

// service_rsync.cc author Sourcefire Inc.

#include "service_rsync.h"

#include "application_ids.h"
#include "service_api.h"
#include "app_info_table.h"

#include "main/snort_debug.h"
#include "utils/util.h"

#define RSYNC_PORT  873

#define RSYNC_BANNER "@RSYNCD: "

enum RSYNCState
{
    RSYNC_STATE_BANNER,
    RSYNC_STATE_MOTD,
    RSYNC_STATE_DONE
};

struct ServiceRSYNCData
{
    RSYNCState state;
};

static int rsync_init(const IniServiceAPI* const init_api);
static int rsync_validate(ServiceValidationArgs* args);

//  FIXIT-L: Make the globals const or, if necessary, thread-local.
static RNAServiceElement svc_element =
{
    nullptr,
    &rsync_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "rsync"
};

static RNAServiceValidationPort pp[] =
{
    { &rsync_validate, RSYNC_PORT, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule rsync_service_mod =
{
    "RSYNC",
    &rsync_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_RSYNC, APPINFO_FLAG_SERVICE_ADDITIONAL }
};

static int rsync_init(const IniServiceAPI* const init_api)
{
    init_api->RegisterPattern(&rsync_validate, IpProtocol::TCP, (uint8_t*)RSYNC_BANNER,
        sizeof(RSYNC_BANNER)-1, 0, "rsync", init_api->pAppidConfig);
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&rsync_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int rsync_validate(ServiceValidationArgs* args)
{
    ServiceRSYNCData* rd;
    int i;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;
    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    rd = (ServiceRSYNCData*)rsync_service_mod.api->data_get(flowp,
        rsync_service_mod.flow_data_index);
    if (!rd)
    {
        rd = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
        rsync_service_mod.api->data_add(flowp, rd, rsync_service_mod.flow_data_index, &snort_free);
        rd->state = RSYNC_STATE_BANNER;
    }

    switch (rd->state)
    {
    case RSYNC_STATE_BANNER:
        if (size < sizeof(RSYNC_BANNER)-1)
            goto fail;
        if (data[size-1] != 0x0A)
            goto fail;
        if (strncmp((char*)data, RSYNC_BANNER, sizeof(RSYNC_BANNER)-1))
            goto fail;
        data += sizeof(RSYNC_BANNER) - 1;
        size -= sizeof(RSYNC_BANNER) - 1;
        for (i=0; i<size-1; i++)
            if (!isdigit(data[i]) && data[i] != '.')
                goto fail;
        rd->state = RSYNC_STATE_MOTD;
        break;
    case RSYNC_STATE_MOTD:
        if (data[size-1] != 0x0A)
            goto fail;
        for (i=0; i<size-1; i++)
            if (!isprint(data[i]) && !isspace(data[i]))
                goto fail;
        rd->state = RSYNC_STATE_DONE;
        goto success;
    default:
        goto fail;
    }

inprocess:
    rsync_service_mod.api->service_inprocess(flowp, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    rsync_service_mod.api->add_service(flowp, args->pkt, args->dir, &svc_element,
        APP_ID_RSYNC, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

fail:
    rsync_service_mod.api->fail_service(flowp, args->pkt, args->dir, &svc_element,
        rsync_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

