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

// service_smtp.cc author Sourcefire Inc.

#include "service_smtp.h"

#include "main/snort_debug.h"
#include "utils/util.h"

#include "service_util.h"
#include "application_ids.h"
#include "service_api.h"
#include "appid_module.h"

#define SMTP_PORT   25
#define SMTP_CLOSING_CONN "closing connection\x0d\x0a"

enum SMTPState
{
    SMTP_STATE_CONNECTION,
    SMTP_STATE_HELO,
    SMTP_STATE_TRANSFER,
    SMTP_STATE_CONNECTION_ERROR,
    SMTP_STATE_STARTTLS
};

struct ServiceSMTPData
{
    SMTPState state;
    int code;
    int multiline;
    int set_flags;
};

#pragma pack(1)

struct ServiceSMTPCode
{
    uint8_t code[3];
    uint8_t sp;
};

#pragma pack()

static int smtp_init(const IniServiceAPI* const init_api);
static int smtp_validate(ServiceValidationArgs* args);

//  FIXIT-L: Make the globals const or, if necessary, thread-local.
static RNAServiceElement svc_element =
{
    nullptr,
    &smtp_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "smtp"
};

static RNAServiceValidationPort pp[] =
{
    { &smtp_validate, 25, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule smtp_service_mod =
{
    "SMTP",
    &smtp_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_SMTP,  0 },
    { APP_ID_SMTPS, 0 }
};

static int smtp_init(const IniServiceAPI* const init_api)
{
    const char SMTP_PATTERN1[] = "220 ";
    const char SMTP_PATTERN2[] = "220-";
    const char SMTP_PATTERN3[] = "SMTP";
    const char SMTP_PATTERN4[] = "smtp";

    init_api->RegisterPattern(&smtp_validate, IpProtocol::TCP, (uint8_t*)SMTP_PATTERN1,
        sizeof(SMTP_PATTERN1) - 1, 0, "smtp", init_api->pAppidConfig);
    init_api->RegisterPattern(&smtp_validate, IpProtocol::TCP, (uint8_t*)SMTP_PATTERN2,
        sizeof(SMTP_PATTERN2) - 1, 0, "smtp", init_api->pAppidConfig);
    init_api->RegisterPattern(&smtp_validate, IpProtocol::TCP, (uint8_t*)SMTP_PATTERN3,
        sizeof(SMTP_PATTERN3) - 1, -1, "smtp", init_api->pAppidConfig);
    init_api->RegisterPattern(&smtp_validate, IpProtocol::TCP, (uint8_t*)SMTP_PATTERN4,
        sizeof(SMTP_PATTERN4) - 1, -1, "smtp", init_api->pAppidConfig);

    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&smtp_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int smtp_validate_reply(const uint8_t* data, uint16_t* offset,
    uint16_t size, int* multi, int* code)
{
    const ServiceSMTPCode* code_hdr;
    int tmp;

    /* Trim any blank lines (be a little tolerant) */
    for (; *offset<size; (*offset)++)
    {
        if (data[*offset] != 0x0D && data[*offset] != 0x0A)
            break;
    }

    if (size - *offset < (int)sizeof(ServiceSMTPCode))
    {
        for (; *offset<size; (*offset)++)
        {
            if (!isspace(data[*offset]))
                return -1;
        }
        return 0;
    }

    code_hdr = (ServiceSMTPCode*)(data + *offset);

    if (code_hdr->code[0] < '1' || code_hdr->code[0] > '5')
        return -1;
    tmp = (code_hdr->code[0] - '0') * 100;

    if (code_hdr->code[1] < '0' || code_hdr->code[1] > '5')
        return -1;
    tmp += (code_hdr->code[1] - '0') * 10;

    if (!isdigit(code_hdr->code[2]))
        return -1;
    tmp += code_hdr->code[2] - '0';

    if (*multi && tmp != *code)
        return -1;
    *code = tmp;
    if (code_hdr->sp == '-')
        *multi = 1;
    else if (code_hdr->sp == ' ')
        *multi = 0;
    else
        return -1;

    /* We have a valid code, now we need to see if the rest of the line
        is okay */

    *offset += sizeof(ServiceSMTPCode);
    for (; *offset < size; (*offset)++)
    {
        if (data[*offset] == 0x0D)
        {
            (*offset)++;
            if (*offset >= size)
                return -1;
            if (data[*offset] != 0x0A)
                return -1;
        }
        if (data[*offset] == 0x0A)
        {
            if (*multi)
            {
                if ((*offset + 1) >= size)
                    return 0;

                if (size - (*offset + 1) < (int)sizeof(ServiceSMTPCode))
                    return -1;

                code_hdr = (ServiceSMTPCode*)(data + *offset + 1);

                if (code_hdr->code[0] < '1' || code_hdr->code[0] > '5')
                    return -1;
                tmp = (code_hdr->code[0] - '0') * 100;

                if (code_hdr->code[1] < '1' || code_hdr->code[1] > '5')
                    return -1;
                tmp += (code_hdr->code[1] - '0') * 10;

                if (!isdigit(code_hdr->code[2]))
                    return -1;
                tmp += code_hdr->code[2] - '0';

                if (tmp != *code)
                    return -1;

                if (code_hdr->sp == ' ')
                    *multi = 0;
                else if (code_hdr->sp != '-')
                    return -1;

                *offset += sizeof(ServiceSMTPCode);
            }
            else
            {
                (*offset)++;
                return *code;
            }
        }
        else if (!isprint(data[*offset]))
            return -1;
    }

    return 0;
}

static int smtp_validate(ServiceValidationArgs* args)
{
    ServiceSMTPData* fd;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    uint16_t size = args->size;
    uint16_t offset;

    if (!size)
        goto inprocess;
    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    fd = (ServiceSMTPData*)smtp_service_mod.api->data_get(flowp, smtp_service_mod.flow_data_index);
    if (!fd)
    {
        fd = (ServiceSMTPData*)snort_calloc(sizeof(ServiceSMTPData));
        smtp_service_mod.api->data_add(flowp, fd, smtp_service_mod.flow_data_index, &snort_free);
        fd->state = SMTP_STATE_CONNECTION;
    }
    else
    {
        if (getAppIdFlag(flowp, APPID_SESSION_ENCRYPTED) && fd->state == SMTP_STATE_TRANSFER)
        {
            fd->state = SMTP_STATE_STARTTLS;
        }
    }

    if (!fd->set_flags)
    {
        fd->set_flags = 1;
        setAppIdFlag(flowp, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    offset = 0;
    while (offset < size)
    {
        if (smtp_validate_reply(data, &offset, size, &fd->multiline, &fd->code) < 0)
            goto fail;
        if (!fd->code)
            goto inprocess;
        switch (fd->state)
        {
        case SMTP_STATE_CONNECTION:
            switch (fd->code)
            {
            case 220:
                fd->state = SMTP_STATE_HELO;
                break;
            case 421:
                if (service_strstr(data, size, (const uint8_t*)SMTP_CLOSING_CONN,
                    sizeof(SMTP_CLOSING_CONN)-1))
                    goto success;
            case 520:
                fd->state = SMTP_STATE_CONNECTION_ERROR;
                break;
            default:
                goto fail;
            }
            break;
        case SMTP_STATE_HELO:
            switch (fd->code)
            {
            case 250:
                fd->state = SMTP_STATE_TRANSFER;
                break;
            case 500:
            case 501:
            case 504:
                break;
            case 421:
            case 553:
                fd->state = SMTP_STATE_CONNECTION_ERROR;
                break;
            default:
                goto fail;
            }
            break;
        case SMTP_STATE_STARTTLS:
            if (fd->code == 220)
                goto success;
            /* STARTTLS failed. */
            clearAppIdFlag(flowp, APPID_SESSION_ENCRYPTED); // not encrypted after all
            fd->state = SMTP_STATE_HELO; // revert the state
            break;
        case SMTP_STATE_TRANSFER:
            goto success;
        case SMTP_STATE_CONNECTION_ERROR:
        default:
            goto fail;
        }
    }

inprocess:
    smtp_service_mod.api->service_inprocess(flowp, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    smtp_service_mod.api->add_service(flowp, args->pkt, args->dir, &svc_element,
        fd->state == SMTP_STATE_STARTTLS ? APP_ID_SMTPS : APP_ID_SMTP,
        nullptr, nullptr, nullptr);
    if (fd->state == SMTP_STATE_STARTTLS)
        appid_stats.smtps_flows++;
    else
        appid_stats.smtp_flows++;

    return SERVICE_SUCCESS;

fail:
    smtp_service_mod.api->fail_service(flowp, args->pkt, args->dir, &svc_element,
        smtp_service_mod.flow_data_index, args->pConfig);
    return SERVICE_NOMATCH;
}

