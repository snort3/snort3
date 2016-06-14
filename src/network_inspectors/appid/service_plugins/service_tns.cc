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

// service_tns.cc author Sourcefire Inc.

#include "app_info_table.h"
#include "appid_flow_data.h"
#include "application_ids.h"
#include "service_api.h"

#include "main/snort_debug.h"
#include "utils/util.h"

static const char svc_name[] = "oracle";
static const uint8_t TNS_BANNER[]  = "\000\000";

#define TNS_BANNER_LEN    (sizeof(TNS_BANNER)-1)
#define TNS_PORT    1521

#define TNS_TYPE_CONNECT 1
#define TNS_TYPE_ACCEPT 2
#define TNS_TYPE_ACK 3
#define TNS_TYPE_REFUSE 4
#define TNS_TYPE_REDIRECT 5
#define TNS_TYPE_DATA 6
#define TNS_TYPE_NULL 7
#define TNS_TYPE_ABORT 9
#define TNS_TYPE_RESEND 11
#define TNS_TYPE_MARKER 12
#define TNS_TYPE_ATTENTION 13
#define TNS_TYPE_CONTROL 14
#define TNS_TYPE_MAX 19

enum TNSState
{
    TNS_STATE_MESSAGE_LEN,
    TNS_STATE_MESSAGE_CHECKSUM,
    TNS_STATE_MESSAGE,
    TNS_STATE_MESSAGE_RES,
    TNS_STATE_MESSAGE_HD_CHECKSUM,
    TNS_STATE_MESSAGE_ACCEPT,
    TNS_STATE_MESSAGE_DATA
};

#define ACCEPT_VERSION_OFFSET   8
#define MAX_VERSION_SIZE    12
struct ServiceTNSData
{
    TNSState state;
    unsigned stringlen;
    unsigned pos;
    unsigned message;
    union
    {
        uint16_t len;
        uint8_t raw_len[2];
    } l;
    const char* version;
};

#pragma pack(1)
struct ServiceTNSMsg
{
    uint16_t len;
    uint16_t checksum;
    uint8_t msg;
    uint8_t res;
    uint16_t hdchecksum;
    uint8_t data;
};
#pragma pack()

static int tns_init(const IniServiceAPI* const init_api);
static int tns_validate(ServiceValidationArgs* args);

static const RNAServiceElement svc_element =
{
    nullptr,
    &tns_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "tns"
};

// FIXIT thread safety, can this be const?
static RNAServiceValidationPort pp[] =
{
    { &tns_validate, TNS_PORT, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

// FIXIT thread safety, can this be const?
SO_PUBLIC RNAServiceValidationModule tns_service_mod =
{
    svc_name,
    &tns_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static const AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_ORACLE_TNS, APPINFO_FLAG_SERVICE_ADDITIONAL },
};

static int tns_init(const IniServiceAPI* const init_api)
{
    init_api->RegisterPattern(&tns_validate, IpProtocol::TCP, (const uint8_t*)TNS_BANNER,
        TNS_BANNER_LEN, 2, svc_name, init_api->pAppidConfig);
    for (unsigned i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&tns_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int tns_validate(ServiceValidationArgs* args)
{
    ServiceTNSData* ss;
    uint16_t offset;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;
    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    ss = (ServiceTNSData*)tns_service_mod.api->data_get(flowp, tns_service_mod.flow_data_index);
    if (!ss)
    {
        ss = (ServiceTNSData*)snort_calloc(sizeof(ServiceTNSData));
        tns_service_mod.api->data_add(flowp, ss, tns_service_mod.flow_data_index, &snort_free);
        ss->state = TNS_STATE_MESSAGE_LEN;
    }

    offset = 0;
    while (offset < size)
    {
        switch (ss->state)
        {
        case TNS_STATE_MESSAGE_LEN:
            ss->l.raw_len[ss->pos++] = data[offset];
            if (ss->pos >= offsetof(ServiceTNSMsg, checksum))
            {
                ss->stringlen = ntohs(ss->l.len);
                if (ss->stringlen == 2)
                {
                    if (offset == (size - 1))
                        goto success;
                    goto fail;
                }
                else if (ss->stringlen < 2)
                    goto fail;
                else
                {
                    ss->state = TNS_STATE_MESSAGE_CHECKSUM;
                }
            }
            break;

        case TNS_STATE_MESSAGE_CHECKSUM:
            if (data[offset] != 0)
                goto fail;
            ss->pos++;
            if (ss->pos >= offsetof(ServiceTNSMsg, msg))
            {
                ss->state = TNS_STATE_MESSAGE;
            }
            break;

        case TNS_STATE_MESSAGE:
            ss->message = data[offset];
            if (ss->message < TNS_TYPE_CONNECT || ss->message > TNS_TYPE_MAX)
                goto fail;
            ss->pos++;
            ss->state = TNS_STATE_MESSAGE_RES;
            break;

        case TNS_STATE_MESSAGE_RES:
            ss->pos++;
            ss->state = TNS_STATE_MESSAGE_HD_CHECKSUM;
            break;

        case TNS_STATE_MESSAGE_HD_CHECKSUM:
            ss->pos++;
            if (ss->pos >= offsetof(ServiceTNSMsg, data))
            {
                switch (ss->message)
                {
                case TNS_TYPE_ACCEPT:
                    ss->state = TNS_STATE_MESSAGE_ACCEPT;
                    break;
                case TNS_TYPE_ACK:
                case TNS_TYPE_REFUSE:
                case TNS_TYPE_REDIRECT:
                case TNS_TYPE_DATA:
                case TNS_TYPE_NULL:
                case TNS_TYPE_ABORT:
                case TNS_TYPE_MARKER:
                case TNS_TYPE_ATTENTION:
                case TNS_TYPE_CONTROL:
                    if (ss->pos == ss->stringlen)
                    {
                        if (offset == (size - 1))
                            goto success;
                        else
                            goto fail;
                    }
                    ss->state = TNS_STATE_MESSAGE_DATA;
                    break;
                case TNS_TYPE_RESEND:
                    if (ss->pos == ss->stringlen)
                    {
                        if (offset == (size - 1))
                        {
                            ss->state = TNS_STATE_MESSAGE_LEN;
                            ss->pos = 0;
                            goto inprocess;
                        }
                        else
                            goto fail;
                    }
                    break;
                case TNS_TYPE_CONNECT:
                default:
                    goto fail;
                }
            }
            break;

        case TNS_STATE_MESSAGE_ACCEPT:
            ss->l.raw_len[ss->pos - ACCEPT_VERSION_OFFSET] = data[offset];
            ss->pos++;
            if (ss->pos >= (ACCEPT_VERSION_OFFSET + 2))
            {
                switch (ntohs(ss->l.len))
                {
                case 0x136:
                    ss->version = "8";
                    break;
                case 0x137:
                    ss->version = "9i R1";
                    break;
                case 0x138:
                    ss->version = "9i R2";
                    break;
                case 0x139:
                    ss->version = "10g R1/R2";
                    break;
                case 0x13A:
                    ss->version = "11g R1";
                    break;
                default:
                    break;
                }
                ss->state = TNS_STATE_MESSAGE_DATA;
            }
            break;
        case TNS_STATE_MESSAGE_DATA:
            ss->pos++;
            if (ss->pos == ss->stringlen)
            {
                if (offset == (size - 1))
                    goto success;
                else
                    goto fail;
            }
            break;
        default:
            goto fail;
        }
        offset++;
    }

inprocess:
    tns_service_mod.api->service_inprocess(flowp, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    tns_service_mod.api->add_service(flowp, args->pkt, args->dir, &svc_element, APP_ID_ORACLE_TNS,
        nullptr, ss->version ? ss->version : nullptr, nullptr);
    return SERVICE_SUCCESS;

fail:
    tns_service_mod.api->fail_service(flowp, args->pkt, args->dir, &svc_element,
        tns_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

