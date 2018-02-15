//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_app_aim.h"

#include "app_info_table.h"

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

#define MAX_VERSION_SIZE    64

static const uint8_t NEW_CONNECTION[] = "\x02a\x001";
static const uint8_t AIM_PROTOCOL_VERSION[] = "\x000\x004\x000\x000\x000\x001";
static const uint8_t OLDER_AOL[] = "AOL Instant Messenger";
static const uint8_t AOL[] = "imApp";
static const uint8_t NETSCAPE_AOL[] = "Netscape 2000 an approved user of AOL Instant Messenger";

AimClientDetector::AimClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "AIM";
    proto = IpProtocol::TCP;
    minimum_matches = 2;
    provides_user = true;

    tcp_patterns =
    {
        { NEW_CONNECTION, sizeof(NEW_CONNECTION) - 1, 0, 0, 0 },
        { AIM_PROTOCOL_VERSION, sizeof(AIM_PROTOCOL_VERSION) - 1, 4, 0, 0 },
        { OLDER_AOL, sizeof(OLDER_AOL) - 1, -1, 0, APP_ID_AOL_INSTANT_MESSENGER },
        { AOL, sizeof(AOL) - 1, -1, 0, APP_ID_AOL_INSTANT_MESSENGER },
        { NETSCAPE_AOL, sizeof(NETSCAPE_AOL) - 1, -1, 0, APP_ID_AOL_NETSCAPE },
    };

    appid_registry =
    {
        { APP_ID_AOL_NETSCAPE, APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
        { APP_ID_AOL_INSTANT_MESSENGER, APPINFO_FLAG_CLIENT_ADDITIONAL |
          APPINFO_FLAG_CLIENT_USER },
    };

    handler->register_detector(name, this, proto);
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

int AimClientDetector::validate(AppIdDiscoveryArgs& args)
{
    if ( args.dir != APP_ID_FROM_INITIATOR )
        return APPID_INPROCESS;

    const uint8_t* const end = args.data + args.size;
    const uint8_t* cur = args.data;

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
                            add_user(args.asd, username, APP_ID_AOL_INSTANT_MESSENGER, true);
                    }
                    break;
                case 0x0003:
                    got_id = true;
                    break;
                case 0x0017:
                    got_id = true;
                    major = ntohs(*(const uint16_t*)cur);
                    break;
                case 0x0018:
                    got_id = true;
                    minor = ntohs(*(const uint16_t*)cur);
                    break;
                case 0x0019:
                    got_id = true;
                    lesser = ntohs(*(const uint16_t*)cur);
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
                add_app(args.asd, APP_ID_AOL_INSTANT_MESSENGER, APP_ID_AOL_INSTANT_MESSENGER,
                    version);
            }
        }
    }

    return APPID_INPROCESS;

bail:
    // FIXIT-L - why are we setting client detected here?
    args.asd.set_client_detected();
    return APPID_SUCCESS;
}

