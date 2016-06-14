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

// client_app_tns.cc author Sourcefire Inc.

#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "utils/sflsq.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "application_ids.h"
#include "client_app_api.h"

static const char TNS_BANNER[] = "\000\000";
#define TNS_BANNER_LEN (sizeof(TNS_BANNER)-1)

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

#define CONNECT_VERSION_OFFSET 8
#define CONNECT_DATA_OFFSET 26

#define USER_STRING "user="
#define MAX_USER_POS ((int)sizeof(USER_STRING) - 2)

enum TNSState
{
    TNS_STATE_MESSAGE_LEN = 0,
    TNS_STATE_MESSAGE_CHECKSUM,
    TNS_STATE_MESSAGE,
    TNS_STATE_MESSAGE_RES,
    TNS_STATE_MESSAGE_HD_CHECKSUM,
    TNS_STATE_MESSAGE_DATA,
    TNS_STATE_MESSAGE_CONNECT,
    TNS_STATE_MESSAGE_CONNECT_OFFSET_DC,
    TNS_STATE_MESSAGE_CONNECT_OFFSET,
    TNS_STATE_MESSAGE_CONNECT_PREDATA,
    TNS_STATE_MESSAGE_CONNECT_DATA,
    TNS_STATE_COLLECT_USER
};

#define MAX_VERSION_SIZE    12
struct ClientTNSData
{
    TNSState state;
    unsigned stringlen;
    unsigned offsetlen;
    unsigned pos;
    unsigned message;
    union
    {
        uint16_t len;
        uint8_t raw_len[2];
    } l;
    const char* version;
    uint8_t* data;
};

#pragma pack(1)
struct ClientTNSMsg
{
    uint16_t len;
    uint16_t checksum;
    uint8_t msg;
    uint8_t res;
    uint16_t hdchecksum;
    uint8_t data;
};
#pragma pack()

struct TNS_CLIENT_APP_CONFIG
{
    int enabled;
};

#ifdef REMOVED_WHILE_NOT_IN_USE
static const char* msg_type[] =
{
    nullptr,
    "Connect",
    "Accept",
    "Acknowledge",
    "Refuse",
    "Redirect",
    "Data",
    "Null",
    nullptr,
    "Abort",
    nullptr,
    "Resend",
    "Marker",
    "Attention",
    "Control",
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr
};
#endif
THREAD_LOCAL TNS_CLIENT_APP_CONFIG tns_config;

static CLIENT_APP_RETCODE tns_init(const IniClientAppAPI* const init_api, SF_LIST* config);
static CLIENT_APP_RETCODE tns_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet* pkt, struct Detector* userData, const AppIdConfig* pConfig);

SO_PUBLIC RNAClientAppModule tns_client_mod =
{
    "TNS",                  // name
    IpProtocol::TCP,            // proto
    &tns_init,              // init
    nullptr,                // clean
    &tns_validate,          // validate
    1,                      // minimum_matches
    nullptr,                // api
    nullptr,                // userData
    0,                      // precedence
    nullptr,                // finalize,
    1,                      // provides_user
    0                       // flow_data_index
};

struct Client_App_Pattern
{
    const u_int8_t* pattern;
    unsigned length;
    int index;
    unsigned appId;
};

static Client_App_Pattern patterns[] =
{
    { (const uint8_t*)TNS_BANNER, sizeof(TNS_BANNER)-1, 2, APP_ID_ORACLE_DATABASE },
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_ORACLE_DATABASE, APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER }
};

static CLIENT_APP_RETCODE tns_init(const IniClientAppAPI* const init_api, SF_LIST* config)
{
    unsigned i;

    if (config)
    {
        SF_LNODE* cursor;
        RNAClientAppModuleConfigItem* item;

        for (item = (RNAClientAppModuleConfigItem*)sflist_first(config, &cursor);
            item;
            item = (RNAClientAppModuleConfigItem*)sflist_next(&cursor))
        {
            DebugFormat(DEBUG_LOG,"Processing %s: %s\n",item->name, item->value);
            if (strcasecmp(item->name, "enabled") == 0)
            {
                tns_config.enabled = atoi(item->value);
            }
        }
    }

    tns_config.enabled = 1;

    if (tns_config.enabled)
    {
        for (i=0; i < sizeof(patterns)/sizeof(*patterns); i++)
        {
            DebugFormat(DEBUG_LOG,"registering patterns: %s: %d\n",
            		(const char*)patterns[i].pattern, patterns[i].index);
            init_api->RegisterPattern(&tns_validate, IpProtocol::TCP, patterns[i].pattern,
                patterns[i].length, patterns[i].index, init_api->pAppidConfig);
        }
    }

    unsigned j;
    for (j=0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[j].appId);
        init_api->RegisterAppId(&tns_validate, appIdRegistry[j].appId,
            appIdRegistry[j].additionalInfo, init_api->pAppidConfig);
    }

    return CLIENT_APP_SUCCESS;
}

#define TNS_MAX_INFO_SIZE    63
static CLIENT_APP_RETCODE tns_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet*, struct Detector*, const AppIdConfig*)
{
    char username[TNS_MAX_INFO_SIZE+1];
    ClientTNSData* fd;
    uint16_t offset;
    int user_pos = 0;
    int user_size = 0;
    uint16_t user_start = 0;
    uint16_t user_end = 0;

    if (dir != APP_ID_FROM_INITIATOR)
        return CLIENT_APP_INPROCESS;

    fd = (ClientTNSData*)tns_client_mod.api->data_get(flowp, tns_client_mod.flow_data_index);
    if (!fd)
    {
        fd = (ClientTNSData*)snort_calloc(sizeof(ClientTNSData));
        tns_client_mod.api->data_add(flowp, fd, tns_client_mod.flow_data_index, &snort_free);
        fd->state = TNS_STATE_MESSAGE_LEN;
    }

    offset = 0;
    while (offset < size)
    {
        switch (fd->state)
        {
        case TNS_STATE_MESSAGE_LEN:
            fd->l.raw_len[fd->pos++] = data[offset];
            if (fd->pos >= offsetof(ClientTNSMsg, checksum))
            {
                fd->stringlen = ntohs(fd->l.len);
                if (fd->stringlen == 2)
                {
                    if (offset == size - 1)
                        goto done;
                    return CLIENT_APP_EINVALID;
                }
                else if (fd->stringlen < 2)
                    return CLIENT_APP_EINVALID;
                else if (fd->stringlen > size)
                    return CLIENT_APP_EINVALID;
                else
                    fd->state = TNS_STATE_MESSAGE_CHECKSUM;
            }
            break;

        case TNS_STATE_MESSAGE_CHECKSUM:
            if (data[offset] != 0)
                return CLIENT_APP_EINVALID;
            fd->pos++;
            if (fd->pos >= offsetof(ClientTNSMsg, msg))
                fd->state = TNS_STATE_MESSAGE;
            break;

        case TNS_STATE_MESSAGE:
            fd->message = data[offset];
            if (fd->message < TNS_TYPE_CONNECT || fd->message > TNS_TYPE_MAX)
                return CLIENT_APP_EINVALID;
            fd->pos++;
            fd->state = TNS_STATE_MESSAGE_RES;
            break;
        case TNS_STATE_MESSAGE_RES:
            fd->state = TNS_STATE_MESSAGE_HD_CHECKSUM;
            fd->pos++;
            break;
        case TNS_STATE_MESSAGE_HD_CHECKSUM:
            fd->pos++;
            if (fd->pos >= offsetof(ClientTNSMsg, data))
            {
                switch (fd->message)
                {
                case TNS_TYPE_CONNECT:
                    fd->state = TNS_STATE_MESSAGE_CONNECT;
                    break;
                case TNS_TYPE_ACK:
                case TNS_TYPE_REFUSE:
                case TNS_TYPE_DATA:
                case TNS_TYPE_NULL:
                case TNS_TYPE_ABORT:
                case TNS_TYPE_RESEND:
                case TNS_TYPE_MARKER:
                case TNS_TYPE_ATTENTION:
                case TNS_TYPE_CONTROL:
                    if (fd->pos >= fd->stringlen)
                    {
                        if (offset == (size - 1))
                            goto done;
                        return CLIENT_APP_EINVALID;
                    }
                    fd->state = TNS_STATE_MESSAGE_DATA;
                    break;
                case TNS_TYPE_ACCEPT:
                case TNS_TYPE_REDIRECT:
                default:
                    return CLIENT_APP_EINVALID;
                }
            }
            break;
        case TNS_STATE_MESSAGE_CONNECT:
            fd->l.raw_len[fd->pos - CONNECT_VERSION_OFFSET] = data[offset];
            fd->pos++;
            if (fd->pos >= (CONNECT_VERSION_OFFSET + 2))
            {
                {
                    switch (ntohs(fd->l.len))
                    {
                    case 0x136:
                        fd->version = "8";
                        break;
                    case 0x137:
                        fd->version = "9i R1";
                        break;
                    case 0x138:
                        fd->version = "9i R2";
                        break;
                    case 0x139:
                        fd->version = "10g R1/R2";
                        break;
                    case 0x13A:
                        fd->version = "11g R1";
                        break;
                    default:
                        break;
                    }
                }
                fd->l.len = 0;
                fd->state = TNS_STATE_MESSAGE_CONNECT_OFFSET_DC;
            }
            break;
        case TNS_STATE_MESSAGE_CONNECT_OFFSET_DC:
            fd->pos++;
            if (fd->pos >= CONNECT_DATA_OFFSET)
                fd->state = TNS_STATE_MESSAGE_CONNECT_OFFSET;
            break;
        case TNS_STATE_MESSAGE_CONNECT_OFFSET:
            fd->l.raw_len[fd->pos - CONNECT_DATA_OFFSET] = data[offset];
            fd->pos++;
            if (fd->pos >= (CONNECT_DATA_OFFSET + 2))
            {
                fd->offsetlen = ntohs(fd->l.len);
                if (fd->offsetlen > size)
                {
                    return CLIENT_APP_EINVALID;
                }
                fd->state = TNS_STATE_MESSAGE_CONNECT_PREDATA;
            }
            break;
        case TNS_STATE_MESSAGE_CONNECT_PREDATA:
            fd->pos++;
            if (fd->pos >= fd->offsetlen)
            {
                fd->state = TNS_STATE_MESSAGE_CONNECT_DATA;
            }
            break;
        case TNS_STATE_MESSAGE_CONNECT_DATA:
            if (tolower(data[offset]) != USER_STRING[user_pos])
            {
                user_pos = 0;
                if (tolower(data[offset]) == USER_STRING[user_pos])
                    user_pos++;
            }
            else if (++user_pos > MAX_USER_POS)
            {
                user_start = offset+1;
                fd->state = TNS_STATE_COLLECT_USER;
            }

            fd->pos++;
            if (fd->pos  >= fd->stringlen)
            {
                if (offset == (size - 1))
                    goto done;
                return CLIENT_APP_EINVALID;
            }
            break;
        case TNS_STATE_COLLECT_USER:
            if (user_end == 0 && data[offset] == ')')
            {
                user_end = offset;
            }

            fd->pos++;
            if (fd->pos  >= fd->stringlen)
            {
                if (offset == (size - 1))
                    goto done;
                return CLIENT_APP_EINVALID;
            }
            break;
        case TNS_STATE_MESSAGE_DATA:
            fd->pos++;
            if (fd->pos >= fd->stringlen)
            {
                if (offset == (size - 1))
                    goto done;
                return CLIENT_APP_EINVALID;
            }
            break;
        default:
            goto inprocess;
        }
        offset++;
    }
inprocess:
    return CLIENT_APP_INPROCESS;

done:
    tns_client_mod.api->add_app(flowp, APP_ID_ORACLE_TNS, APP_ID_ORACLE_DATABASE, fd->version);
    if (user_start && user_end && ((user_size = user_end - user_start) > 0))
    {
        /* we truncate extra long usernames */
        if (user_size > TNS_MAX_INFO_SIZE)
            user_size = TNS_MAX_INFO_SIZE;
        memcpy(username, &data[user_start], user_size);
        username[user_size] = 0;
        tns_client_mod.api->add_user(flowp, username, APP_ID_ORACLE_DATABASE, 1);
    }
    setAppIdFlag(flowp, APPID_SESSION_CLIENT_DETECTED);
    return CLIENT_APP_SUCCESS;
}

