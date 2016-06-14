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

// client_app_aim.cc author Sourcefire Inc.

#include "client_app_api.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdint>

#include "main/snort_debug.h"
#include "utils/sflsq.h"

#include "app_info_table.h"
#include "application_ids.h"

#pragma pack(1)

struct FLAPFNACSignOn
{
    uint16_t len;
};

struct FLAPFNAC
{
    uint16_t family;
    uint16_t subtype;
    uint16_t flags;
    uint32_t id;
};

struct FLAPTLV
{
    uint16_t subtype;
    uint16_t len;
};

struct FLAPHeader
{
    uint8_t start;
    uint8_t channel;
    uint16_t seq;
    uint16_t len;
};

#pragma pack()

struct AIM_CLIENT_APP_CONFIG
{
    int enabled;
};

THREAD_LOCAL AIM_CLIENT_APP_CONFIG aim_config;

#define MAX_VERSION_SIZE    64

static CLIENT_APP_RETCODE aim_init(const IniClientAppAPI* const, SF_LIST* config);
static CLIENT_APP_RETCODE aim_validate(
    const uint8_t* data, uint16_t size, const int dir, AppIdData*, Packet*,
    Detector*, const AppIdConfig*);

RNAClientAppModule aim_client_mod =
{
    "AIM",                  // name
    IpProtocol::TCP,        // proto
    &aim_init,              // init
    nullptr,                // clean
    &aim_validate,          // validate
    2,                      // minimum_matches
    nullptr,                // api
    nullptr,                // userData
    0,                      // precedence
    nullptr,                // finalize,
    1,                      // provides_user
    0                       // flow_data_index
};

struct Client_App_Pattern
{
    const uint8_t* pattern;
    unsigned length;
    int index;
    unsigned appId;
};

static const uint8_t NEW_CONNECTION[] = "\x02a\x001";
static const uint8_t AIM_PROTOCOL_VERSION[] = "\x000\x004\x000\x000\x000\x001";
static const uint8_t OLDER_AOL[] = "AOL Instant Messenger";
static const uint8_t AOL[] = "imApp";
static const uint8_t NETSCAPE_AOL[] = "Netscape 2000 an approved user of AOL Instant Messenger";

static Client_App_Pattern patterns[] =
{
    { NEW_CONNECTION, sizeof(NEW_CONNECTION)-1, 0, 0 },
    { AIM_PROTOCOL_VERSION, sizeof(AIM_PROTOCOL_VERSION)-1, 4, 0 },
    { OLDER_AOL, sizeof(OLDER_AOL)-1, -1, APP_ID_AOL_INSTANT_MESSENGER },
    { AOL, sizeof(AOL)-1, -1, APP_ID_AOL_INSTANT_MESSENGER },
    { NETSCAPE_AOL, sizeof(NETSCAPE_AOL), -1, APP_ID_AOL_NETSCAPE },
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_AOL_NETSCAPE, APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
    { APP_ID_AOL_INSTANT_MESSENGER, APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
};

static CLIENT_APP_RETCODE aim_init(const IniClientAppAPI* const init_api, SF_LIST* config)
{
    aim_config.enabled = 1;

    if ( config )
    {
        SF_LNODE* cursor = nullptr;
        RNAClientAppModuleConfigItem* item = nullptr;

        for ( item = (RNAClientAppModuleConfigItem*)sflist_first(config, &cursor);
            item;
            item = (RNAClientAppModuleConfigItem*)sflist_next(&cursor) )
        {
            DebugFormat(DEBUG_INSPECTOR, "Processing %s: %s\n", item->name, item->value);
            if (strcasecmp(item->name, "enabled") == 0)
                aim_config.enabled = atoi(item->value);
        }
    }

    if (aim_config.enabled)
    {
        for (unsigned i = 0; i < sizeof(patterns)/sizeof(*patterns); i++)
        {
            DebugFormat(DEBUG_INSPECTOR, "registering pattern length %u at %d\n",
                patterns[i].length, patterns[i].index);

            init_api->RegisterPattern(&aim_validate, IpProtocol::TCP, patterns[i].pattern,
                patterns[i].length, patterns[i].index, init_api->pAppidConfig);
        }
    }

    for (unsigned j = 0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_INSPECTOR, "registering appId: %d\n",
            appIdRegistry[j].appId);

        init_api->RegisterAppId(&aim_validate, appIdRegistry[j].appId,
            appIdRegistry[j].additionalInfo, init_api->pAppidConfig);
    }

    return CLIENT_APP_SUCCESS;
}

template<typename Hdr>
static inline const Hdr* advance(const uint8_t*& cur, const uint8_t* const end)
{
    assert(end >= cur);
    if ( (size_t)(end - cur) < sizeof(Hdr) )
        return nullptr;

    cur += sizeof(Hdr);
    return reinterpret_cast<const Hdr*>(cur);
}

static inline bool check_username(
    const uint8_t* const data, const FLAPTLV* tlv, char* const buf, char* const buf_end)
{
    const uint8_t* const end = data + tlv->len;
    char* ptr = buf;
    *buf_end = '\0';

    for ( const uint8_t* cur = data; cur < end; ++cur )
    {
        if (isalnum(*cur) || *cur == '.' || *cur == '@' || *cur == '-' || *cur == '_')
        {
            if ( ptr < buf_end )
                *ptr++ = *cur;
        }
        else
            return false;
    }

    return true;
}

static CLIENT_APP_RETCODE aim_validate(
    const uint8_t* const data, uint16_t size, const int dir, AppIdData* flowp,
    Packet*, Detector*, const AppIdConfig*)
{
    if ( dir != APP_ID_FROM_INITIATOR )
        return CLIENT_APP_INPROCESS;

    const uint8_t* const end = data + size;
    const uint8_t* cur = data;

    while ( cur < end )
    {
        auto fh = advance<FLAPHeader>(cur, end);
        if ( !fh )
            goto bail;

        if (fh->start != 0x2a || fh->channel < 1 || fh->channel > 5)
            goto bail;

        uint16_t len = ntohs(fh->len);

        if (len > (end - cur))
            goto bail;

        bool check_user_name = false;

        if ( fh->channel == 0x02 )
        {
            auto fnac = advance<FLAPFNAC>(cur, end);
            if ( !fnac )
                goto bail;

            if (fnac->family == htons(0x0017) && fnac->subtype == htons(0x0006))
                check_user_name = true;

            len -= sizeof(*fnac);
        }
        else if ( fh->channel == 0x01 )
        {
            if ( len < 4 || memcmp(cur, &AIM_PROTOCOL_VERSION[2], 4) != 0 )
                goto bail;

            len -= 4;
            cur += 4;
        }

        if ( len )
        {
            bool got_id = false;
            uint16_t major = 0;
            uint16_t minor = 0;
            uint16_t lesser = 0;

            const uint8_t* const frame_end = cur + len;

            while ( cur < frame_end )
            {
                auto tlv = advance<FLAPTLV>(cur, frame_end);
                if ( !tlv )
                    goto bail;

                if (frame_end - cur < tlv->len)
                    goto bail;

                switch ( ntohs(tlv->subtype) )
                {
                case 0x0001:
                    if ( check_user_name )
                    {
                        constexpr auto USERNAME_LEN = 256;
                        char username[USERNAME_LEN];

                        if ( check_username(cur, tlv, username, username + USERNAME_LEN) )
                            aim_client_mod.api->add_user(flowp, username,
                                APP_ID_AOL_INSTANT_MESSENGER, 1);
                    }
                    break;
                case 0x0003:
                    got_id = true;
                    break;
                case 0x0017:
                    got_id = true;
                    major = ntohs(*(uint16_t*)cur);
                    break;
                case 0x0018:
                    got_id = true;
                    minor = ntohs(*(uint16_t*)cur);
                    break;
                case 0x0019:
                    got_id = true;
                    lesser = ntohs(*(uint16_t*)cur);
                    break;
                default:
                    break;
                }

                cur += tlv->len;
            }

            if ( got_id )
            {
                char version[MAX_VERSION_SIZE];

                snprintf(version, sizeof(version), "%d.%d.%d", major, minor, lesser);
                aim_client_mod.api->add_app(
                    flowp, APP_ID_AOL_INSTANT_MESSENGER,
                    APP_ID_AOL_INSTANT_MESSENGER, version);
            }
        }
    }

    return CLIENT_APP_INPROCESS;

bail:
    setAppIdFlag(flowp, APPID_SESSION_CLIENT_DETECTED);
    return CLIENT_APP_SUCCESS;
}

