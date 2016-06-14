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

// client_app_bit.cc author Sourcefire Inc.

#include "client_app_api.h"
#include "application_ids.h"

#include "main/snort_debug.h"
#include "utils/util.h"

static const char BIT_BANNER[] = "\023BitTorrent protocol";

#define BIT_BANNER_LEN (sizeof(BIT_BANNER)-1)
#define RES_LEN 8
#define SHA_LEN 20
#define MAX_STR_LEN 20
#define PEER_ID_LEN 20
#define MAX_VER_LEN 4
#define LAST_BANNER_OFFSET  (BIT_BANNER_LEN+RES_LEN+SHA_LEN+PEER_ID_LEN - 1)

enum BITState
{
    BIT_STATE_BANNER = 0,
    BIT_STATE_BANNER_DC,
    BIT_STATE_MESSAGE_LEN,
    BIT_STATE_MESSAGE_DATA
};

struct ClientBITData
{
    BITState state;
    unsigned stringlen;
    unsigned pos;
    union
    {
        uint32_t len;
        uint8_t raw_len[4];
    } l;
};

#pragma pack(1)
struct ClientBITMsg
{
    uint32_t len;
    uint8_t code;
};
#pragma pack()

struct BIT_CLIENT_APP_CONFIG
{
    int enabled;
};

THREAD_LOCAL BIT_CLIENT_APP_CONFIG bit_config;

static CLIENT_APP_RETCODE bit_init(const IniClientAppAPI* const init_api, SF_LIST* config);
static CLIENT_APP_RETCODE bit_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet* pkt, struct Detector* userData,
    const AppIdConfig* pConfig);

SO_PUBLIC RNAClientAppModule bit_client_mod =
{
    "BIT",
    IpProtocol::TCP,
    &bit_init,
    nullptr,
    &bit_validate,
    1,
    nullptr,
    nullptr,
    0,
    nullptr,
    0,
    0
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
    { (const uint8_t*)BIT_BANNER, sizeof(BIT_BANNER)-1, 0, APP_ID_BITTORRENT },
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_BITTORRENT, 0 }
};

static CLIENT_APP_RETCODE bit_init(const IniClientAppAPI* const init_api, SF_LIST* config)
{
    unsigned i;
    RNAClientAppModuleConfigItem* item;

    bit_config.enabled = 1;

    if (config)
    {
        SF_LNODE* cursor = nullptr;
        for (item = (RNAClientAppModuleConfigItem*)sflist_first(config, &cursor);
            item;
            item = (RNAClientAppModuleConfigItem*)sflist_next(&cursor))
        {
            DebugFormat(DEBUG_LOG,"Processing %s: %s\n",item->name, item->value);
            if (strcasecmp(item->name, "enabled") == 0)
            {
                bit_config.enabled = atoi(item->value);
            }
        }
    }

    if (bit_config.enabled)
    {
        for (i=0; i < sizeof(patterns)/sizeof(*patterns); i++)
        {
            DebugFormat(DEBUG_LOG,"registering patterns: %s: %d\n",
            		(const char*)patterns[i].pattern, patterns[i].index);
            init_api->RegisterPattern(&bit_validate, IpProtocol::TCP, patterns[i].pattern,
                patterns[i].length, patterns[i].index, init_api->pAppidConfig);
        }
    }

    unsigned j;
    for (j=0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[j].appId);
        init_api->RegisterAppId(&bit_validate, appIdRegistry[j].appId,
            appIdRegistry[j].additionalInfo, init_api->pAppidConfig);
    }

    return CLIENT_APP_SUCCESS;
}

static CLIENT_APP_RETCODE bit_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet*, struct Detector*, const AppIdConfig*)
{
    ClientBITData* fd;
    uint16_t offset;

    if (dir != APP_ID_FROM_INITIATOR)
        return CLIENT_APP_INPROCESS;

    fd = (ClientBITData*)bit_client_mod.api->data_get(flowp, bit_client_mod.flow_data_index);
    if (!fd)
    {
        fd = (ClientBITData*)snort_calloc(sizeof(ClientBITData));
        bit_client_mod.api->data_add(flowp, fd, bit_client_mod.flow_data_index, &snort_free);
        fd->state = BIT_STATE_BANNER;
    }

    offset = 0;
    while (offset < size)
    {
        switch (fd->state)
        {
        case BIT_STATE_BANNER:
            if (data[offset] != BIT_BANNER[fd->pos])
                return CLIENT_APP_EINVALID;
            if (fd->pos == BIT_BANNER_LEN-1)
                fd->state = BIT_STATE_BANNER_DC;
            fd->pos++;
            break;
        case BIT_STATE_BANNER_DC:
            if (fd->pos == LAST_BANNER_OFFSET)
            {
                fd->pos = 0;
                fd->state = BIT_STATE_MESSAGE_LEN;
                break;
            }
            fd->pos++;
            break;
        case BIT_STATE_MESSAGE_LEN:
            fd->l.raw_len[fd->pos] = data[offset];
            fd->pos++;
            if (fd->pos >= offsetof(ClientBITMsg, code))
            {
                fd->stringlen = ntohl(fd->l.len);
                fd->state = BIT_STATE_MESSAGE_DATA;
                if (!fd->stringlen)
                {
                    if (offset == size-1)
                        goto done;
                    return CLIENT_APP_EINVALID;
                }
                fd->pos = 0;
            }
            break;

        case BIT_STATE_MESSAGE_DATA:
            fd->pos++;
            if (fd->pos == fd->stringlen)
                goto done;
            break;
        default:
            goto inprocess;
        }
        offset++;
    }
inprocess:
    return CLIENT_APP_INPROCESS;

done:
    bit_client_mod.api->add_app(flowp, APP_ID_BITTORRENT, APP_ID_BITTORRENT, nullptr);
    setAppIdFlag(flowp, APPID_SESSION_CLIENT_DETECTED);
    return CLIENT_APP_SUCCESS;
}

