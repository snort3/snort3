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

// client_app_timbuktu.cc author Sourcefire Inc.

#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "utils/sflsq.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "application_ids.h"
#include "client_app_api.h"

static const char TIMBUKTU_BANNER[] = "\000\001";

#define TIMBUKTU_BANNER_LEN (sizeof(TIMBUKTU_BANNER)-1)
#define MAX_ANY_SIZE    2

enum TIMBUKTUState
{
    TIMBUKTU_STATE_BANNER = 0,
    TIMBUKTU_STATE_ANY_MESSAGE_LEN,
    TIMBUKTU_STATE_MESSAGE_LEN,
    TIMBUKTU_STATE_MESSAGE_DATA
};

struct ClientTIMBUKTUData
{
    TIMBUKTUState state;
    uint16_t stringlen;
    unsigned pos;
    union
    {
        uint16_t len;
        uint8_t raw_len[2];
    } l;
};

#pragma pack(1)
struct ClientTIMBUKTUMsg
{
    uint16_t len;
    uint8_t message;
};
#pragma pack()

struct TIMBUKTU_CLIENT_APP_CONFIG
{
    int enabled;
};

THREAD_LOCAL TIMBUKTU_CLIENT_APP_CONFIG timbuktu_config;

static CLIENT_APP_RETCODE timbuktu_init(const IniClientAppAPI* const init_api, SF_LIST* config);
static CLIENT_APP_RETCODE timbuktu_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet* pkt, struct Detector* userData, const AppIdConfig* pConfig);

SO_PUBLIC RNAClientAppModule timbuktu_client_mod =
{
    "TIMBUKTU",             // name
    IpProtocol::TCP,            // proto
    &timbuktu_init,         // init
    nullptr,                // clean
    &timbuktu_validate,     // validate
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
    { (const uint8_t*)TIMBUKTU_BANNER, sizeof(TIMBUKTU_BANNER)-1, 0, APP_ID_TIMBUKTU },
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_TIMBUKTU, 0 }
};

static CLIENT_APP_RETCODE timbuktu_init(const IniClientAppAPI* const init_api, SF_LIST* config)
{
    unsigned i;

    timbuktu_config.enabled = 1;

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
                timbuktu_config.enabled = atoi(item->value);
            }
        }
    }

    if (timbuktu_config.enabled)
    {
        for (i=0; i < sizeof(patterns)/sizeof(*patterns); i++)
        {
            DebugFormat(DEBUG_LOG,"registering patterns: %s: %d\n",
            		(const char*)patterns[i].pattern, patterns[i].index);
            init_api->RegisterPattern(&timbuktu_validate, IpProtocol::TCP, patterns[i].pattern,
                patterns[i].length, patterns[i].index, init_api->pAppidConfig);
        }
    }

    unsigned j;
    for (j=0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[j].appId);
        init_api->RegisterAppId(&timbuktu_validate, appIdRegistry[j].appId,
            appIdRegistry[j].additionalInfo, init_api->pAppidConfig);
    }

    return CLIENT_APP_SUCCESS;
}

static CLIENT_APP_RETCODE timbuktu_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet*, struct Detector*, const AppIdConfig*)
{
    ClientTIMBUKTUData* fd;
    uint16_t offset;

    if (dir != APP_ID_FROM_INITIATOR)
        return CLIENT_APP_INPROCESS;

    fd = (ClientTIMBUKTUData*)timbuktu_client_mod.api->data_get(flowp,
        timbuktu_client_mod.flow_data_index);
    if (!fd)
    {
        fd = (ClientTIMBUKTUData*)snort_calloc(sizeof(ClientTIMBUKTUData));
        timbuktu_client_mod.api->data_add(flowp, fd,
            timbuktu_client_mod.flow_data_index, &snort_free);
        fd->state = TIMBUKTU_STATE_BANNER;
    }

    offset = 0;
    while (offset < size)
    {
        switch (fd->state)
        {
        case TIMBUKTU_STATE_BANNER:
            if (data[offset] != TIMBUKTU_BANNER[fd->pos])
                return CLIENT_APP_EINVALID;
            if (fd->pos >= TIMBUKTU_BANNER_LEN-1)
            {
                fd->pos = 0;
                fd->state = TIMBUKTU_STATE_ANY_MESSAGE_LEN;
                break;
            }
            fd->pos++;
            break;
        /* cheeck any 2 bytes fisrt */
        case TIMBUKTU_STATE_ANY_MESSAGE_LEN:
            fd->pos++;
            if (fd->pos >= MAX_ANY_SIZE)
            {
                fd->pos = 0;
                fd->state = TIMBUKTU_STATE_MESSAGE_LEN;
                break;
            }
            break;
        case TIMBUKTU_STATE_MESSAGE_LEN:
            if (fd->pos < offsetof(ClientTIMBUKTUMsg, message))
            {
                fd->l.raw_len[fd->pos] = data[offset];
            }
            fd->pos++;
            if (fd->pos >= offsetof(ClientTIMBUKTUMsg, message))
            {
                fd->stringlen = ntohs(fd->l.len);
                if (!fd->stringlen)
                {
                    if (offset == size - 1)
                        goto done;
                    return CLIENT_APP_EINVALID;
                }
                else if ((fd->stringlen + TIMBUKTU_BANNER_LEN + MAX_ANY_SIZE + offsetof(
                    ClientTIMBUKTUMsg, message)) > size)
                    return CLIENT_APP_EINVALID;
                fd->state = TIMBUKTU_STATE_MESSAGE_DATA;
                fd->pos = 0;
            }
            break;
        case TIMBUKTU_STATE_MESSAGE_DATA:
            fd->pos++;
            if (fd->pos == fd->stringlen)
            {
                if (offset == size - 1)
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
    timbuktu_client_mod.api->add_app(flowp, APP_ID_TIMBUKTU, APP_ID_TIMBUKTU, nullptr);
    setAppIdFlag(flowp, APPID_SESSION_CLIENT_DETECTED);
    return CLIENT_APP_SUCCESS;
}

