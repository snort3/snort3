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

// service_telnet.cc author Sourcefire Inc.

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "main/snort_debug.h"
#include "utils/util.h"

#include "appid_flow_data.h"
#include "application_ids.h"
#include "service_api.h"
#include "appid_module.h"

#define TELNET_COUNT_THRESHOLD 3

#define TELNET_IAC 255
#define TELNET_MIN_CMD 236
#define TELNET_MIN_DATA_CMD 250
#define TELNET_SUB_NEG_CMD 250
#define TELNET_SUB_NEG_END_CMD 240
#define TELNET_CMD_MAX_OPTION 44

enum TELNET_COMMAND_VALUE
{
    TELNET_CMD_SE = 240,
    TELNET_CMD_NOP,
    TELNET_CMD_DMARK,
    TELNET_CMD_BREAK,
    TELNET_CMD_IP,
    TELNET_CMD_AO,
    TELNET_CMD_AYT,
    TELNET_CMD_EC,
    TELNET_CMD_EL,
    TELNET_CMD_GA,
    TELNET_CMD_SB,
    TELNET_CMD_WILL,
    TELNET_CMD_WONT,
    TELNET_CMD_DO,
    TELNET_CMD_DONT,
    TELNET_CMD_IAC
};

struct ServiceTelnetData
{
    unsigned count;
};

static int telnet_init(const IniServiceAPI* const init_api);
static int telnet_validate(ServiceValidationArgs* args);

static const RNAServiceElement svc_element =
{
    nullptr,
    &telnet_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "telnet",
};

// FIXIT thread safety, can this be const?
static RNAServiceValidationPort pp[] =
{
    { &telnet_validate, 23, IpProtocol::TCP, 0 },
    { &telnet_validate, 23, IpProtocol::UDP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

// FIXIT thread safety, can this be const?
RNAServiceValidationModule telnet_service_mod =
{
    "TELNET",
    &telnet_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static const AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_TELNET, 0 }
};

static int telnet_init(const IniServiceAPI* const init_api)
{
    for (unsigned i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&telnet_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int telnet_validate(ServiceValidationArgs* args)
{
    ServiceTelnetData* td;
    const uint8_t* end;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;
    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    td = (ServiceTelnetData*)telnet_service_mod.api->data_get(flowp,
        telnet_service_mod.flow_data_index);
    if (!td)
    {
        td = (ServiceTelnetData*)snort_calloc(sizeof(ServiceTelnetData));
        telnet_service_mod.api->data_add(flowp, td, telnet_service_mod.flow_data_index,
            &snort_free);
    }

    for (end=(data+size); data<end; data++)
    {
        /* Currently we only look for the first packet to contain
           wills, won'ts, dos, and don'ts */
        if (*data != TELNET_CMD_IAC)
            goto fail;
        data++;
        if (data >= end)
            goto fail;
        switch (*data)
        {
        case TELNET_CMD_WILL:
        case TELNET_CMD_WONT:
        case TELNET_CMD_DO:
        case TELNET_CMD_DONT:
            data++;
            if (data >= end)
                goto fail;
            td->count++;
            if (td->count >= TELNET_COUNT_THRESHOLD)
                goto success;
            break;
        default:
            goto fail;
        }
    }
inprocess:
    telnet_service_mod.api->service_inprocess(flowp, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    telnet_service_mod.api->add_service(flowp, args->pkt, args->dir, &svc_element,
        APP_ID_TELNET, nullptr, nullptr, nullptr);
    appid_stats.telnet_flows++;
    return SERVICE_SUCCESS;

fail:
    telnet_service_mod.api->fail_service(flowp, args->pkt, args->dir, &svc_element,
        telnet_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

