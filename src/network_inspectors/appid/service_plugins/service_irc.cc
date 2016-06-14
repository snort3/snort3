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

// service_irc.cc author Sourcefire Inc.

#include "service_irc.h"

#include "main/snort_debug.h"
#include "utils/util.h"

#include "appid_flow_data.h"
#include "application_ids.h"

#define IRC_COUNT_THRESHOLD 10

static const char* const IRC_USER="USER ";
static const char* const IRC_NOTICE="NOTICE ";
static const char* const IRC_ERROR="ERROR ";
static const char* const IRC_PONG="PONG ";
static const char* const IRC_PING="PING ";

enum IRCState
{
    IRC_STATE_BEGIN,
    IRC_STATE_MID_PREFIX,
    IRC_STATE_COMMAND_BEGIN,
    IRC_STATE_MID_COMMAND,
    IRC_STATE_MID_NUMERIC_COMMAND,
    IRC_STATE_LINE,
    IRC_STATE_MID_TERM,
    IRC_STATE_FOUND_USER,
    IRC_STATE_USER_USERNAME,
    IRC_STATE_USER_HOSTNAME,
    IRC_STATE_USER_SERVERNAME,
    IRC_STATE_USER_REALNAME_BEGIN,
    IRC_STATE_USER_REALNAME,
    IRC_STATE_USER_MID_TERM
};

struct ServiceIRCData
{
    IRCState state;
    unsigned pos;
    const char* command;
    IRCState initiator_state;
    unsigned initiator_pos;
    const char* initiator_command;
    unsigned count;
};

static int irc_init(const IniServiceAPI* const init_api);
static int irc_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &irc_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "irc"
};

static RNAServiceValidationPort pp[] =
{
    { &irc_validate, 6667, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule irc_service_mod =
{
    "IRC",
    &irc_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_IRCD, 0 }
};

static int irc_init(const IniServiceAPI* const init_api)
{
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
        init_api->RegisterAppId(&irc_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int irc_validate(ServiceValidationArgs* args)
{
    ServiceIRCData* id;
    const uint8_t* end;
    IRCState* state;
    unsigned* pos;
    const char** command;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;

    id = (ServiceIRCData*)irc_service_mod.api->data_get(flowp, irc_service_mod.flow_data_index);
    if (!id)
    {
        id =  (ServiceIRCData*)snort_calloc(sizeof(ServiceIRCData));
        irc_service_mod.api->data_add(flowp, id, irc_service_mod.flow_data_index, &snort_free);
        id->initiator_state = IRC_STATE_BEGIN;
        id->state = IRC_STATE_BEGIN;
    }

    end = (const uint8_t*)(data + size);

    if (dir == APP_ID_FROM_RESPONDER)
    {
        state = &id->state;
        pos = &id->pos;
        command = &id->command;
    }
    else
    {
        state = &id->initiator_state;
        pos = &id->initiator_pos;
        command = &id->initiator_command;
    }

    for (; data<end; data++)
    {
        switch (*state)
        {
        case IRC_STATE_BEGIN:
            if (*data == ':')
            {
                *state = IRC_STATE_MID_PREFIX;
                break;
            }
        /* Fall through */
        case IRC_STATE_COMMAND_BEGIN:
            if (*data == ' ')
                break;
            else if (isdigit(*data))
            {
                *state = IRC_STATE_MID_NUMERIC_COMMAND;
                *pos = 1;
                break;
            }
            else
            {
                if (dir == APP_ID_FROM_RESPONDER)
                {
                    if (*data == IRC_NOTICE[0])
                        *command = IRC_NOTICE;
                    else if (*data == IRC_ERROR[0])
                        *command = IRC_ERROR;
                    else if (*data == IRC_PONG[0])
                        *command = IRC_PONG;
                    else
                        goto fail;
                }
                else
                {
                    if (*data == IRC_USER[0])
                        *command = IRC_USER;
                    else
                    {
                        *state = IRC_STATE_LINE;
                        break;
                    }
                }
            }

            *pos = 1;
            *state = IRC_STATE_MID_COMMAND;
            break;
        case IRC_STATE_MID_COMMAND:
            if (*data != (*command)[*pos])
            {
                if (*command == IRC_PONG && *pos == 1 && *data == IRC_PING[1])
                {
                    *command = IRC_PING;
                }
                else
                    goto fail;
            }
            (*pos)++;
            if (!(*command)[*pos])
            {
                if (dir == APP_ID_FROM_RESPONDER)
                {
                    *state = IRC_STATE_LINE;
                }
                else
                {
                    *state = IRC_STATE_USER_USERNAME;
                }
            }
            break;
        case IRC_STATE_LINE:
            if (*data == 0x0D)
                *state = IRC_STATE_MID_TERM;
            else if (*data == 0x0A)
            {
                *state = IRC_STATE_BEGIN;
                if (dir == APP_ID_FROM_RESPONDER)
                {
                    id->count++;
                    if (id->count >= IRC_COUNT_THRESHOLD && id->initiator_state ==
                        IRC_STATE_FOUND_USER)
                        goto success;
                }
            }
            break;
        case IRC_STATE_MID_TERM:
            if (*data != 0x0A)
                goto fail;
            *state = IRC_STATE_BEGIN;
            if (dir == APP_ID_FROM_RESPONDER)
            {
                id->count++;
                if (id->count >= IRC_COUNT_THRESHOLD && id->initiator_state ==
                    IRC_STATE_FOUND_USER)
                    goto success;
            }
            break;
        case IRC_STATE_MID_NUMERIC_COMMAND:
            if (*pos < 3)
            {
                if (!isdigit(*data))
                    goto fail;
                (*pos)++;
            }
            else
            {
                if (*data != ' ')
                    goto fail;
                *state = IRC_STATE_LINE;
            }
            break;
        case IRC_STATE_MID_PREFIX:
            if (*data == ' ')
                *state = IRC_STATE_COMMAND_BEGIN;
            else if (!isprint(*data))
                goto fail;
            break;
        case IRC_STATE_USER_USERNAME:
            if (*data == ' ')
                *state = IRC_STATE_USER_HOSTNAME;
            else if (*data == 0x0D || *data == 0x0A)
                goto fail;
            break;
        case IRC_STATE_USER_HOSTNAME:
            if (*data == ' ')
                *state = IRC_STATE_USER_SERVERNAME;
            else if (*data == 0x0D || *data == 0x0A)
                goto fail;
            break;
        case IRC_STATE_USER_SERVERNAME:
            if (*data == ' ')
                *state = IRC_STATE_USER_REALNAME_BEGIN;
            else if (*data == 0x0D || *data == 0x0A)
                goto fail;
            break;
        case IRC_STATE_USER_REALNAME_BEGIN:
            if (*data == ':')
                *state = IRC_STATE_USER_REALNAME;
            else
                goto fail;
            break;
        case IRC_STATE_USER_REALNAME:
            if (*data == 0x0D)
                *state = IRC_STATE_USER_MID_TERM;
            else if (*data == 0x0A)
                *state = IRC_STATE_FOUND_USER;
            break;
        case IRC_STATE_USER_MID_TERM:
            if (*data != 0x0A)
                goto fail;
            *state = IRC_STATE_FOUND_USER;
            break;
        case IRC_STATE_FOUND_USER:
            goto inprocess;
        default:
            goto fail;
        }
    }
inprocess:
    irc_service_mod.api->service_inprocess(flowp, args->pkt, dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    irc_service_mod.api->add_service(flowp, args->pkt, dir, &svc_element,
        APP_ID_IRCD, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

fail:
    if (dir == APP_ID_FROM_RESPONDER)
    {
        irc_service_mod.api->fail_service(flowp, args->pkt, dir, &svc_element,
            irc_service_mod.flow_data_index, args->pConfig);
    }
    else
    {
        irc_service_mod.api->incompatible_data(flowp, args->pkt, dir, &svc_element,
            irc_service_mod.flow_data_index, args->pConfig);
    }
    return SERVICE_NOMATCH;
}

