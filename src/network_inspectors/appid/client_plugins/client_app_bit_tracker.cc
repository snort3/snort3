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

// client_app_bit_tracker.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_app_bit_tracker.h"

#include "app_info_table.h"
#include "application_ids.h"

#include "protocols/packet.h"
#include "utils/sflsq.h"
#include "utils/util.h"

static const char UDP_BIT_QUERY[] = "d1:a";
static const char UDP_BIT_RESPONSE[] = "d1:r";
static const char UDP_BIT_ERROR[] = "d1:e";
static const char UDP_BIT_FIRST[] = "d1:";
static const char UDP_BIT_COMMON_END[] = "1:y1:";

#define UDP_BIT_FIRST_LEN (sizeof(UDP_BIT_FIRST)-1)
#define UDP_BIT_COMMON_END_LEN (sizeof(UDP_BIT_COMMON_END)-1)
#define UDP_BIT_END_LEN (UDP_BIT_COMMON_END_LEN+2)

enum  BITState
{
    BIT_STATE_BANNER = 0,
    BIT_STATE_TYPES,
    BIT_STATE_DC,
    BIT_STATE_CHECK_END,
    BIT_STATE_CHECK_END_TYPES,
    BIT_STATE_CHECK_LAST
};

enum BITType
{
    BIT_TYPE_REQUEST = 1,
    BIT_TYPE_RESPONSE,
    BIT_TYPE_ERROR
};

struct ClientBITData
{
    BITState state;
    BITType type;
    unsigned pos;
};

BitTrackerClientDetector::BitTrackerClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "BIT-UDP";
    proto = IpProtocol::UDP;
    minimum_matches = 1;
    provides_user = true;

    udp_patterns =
    {
        { (const uint8_t*)UDP_BIT_QUERY,    sizeof(UDP_BIT_QUERY) - 1,    -1, 0, APP_ID_BITTRACKER_CLIENT },
        { (const uint8_t*)UDP_BIT_RESPONSE, sizeof(UDP_BIT_RESPONSE) - 1, -1, 0, APP_ID_BITTRACKER_CLIENT },
        { (const uint8_t*)UDP_BIT_ERROR,    sizeof(UDP_BIT_ERROR) - 1,    -1, 0, APP_ID_BITTRACKER_CLIENT },
    };

    appid_registry =
    {
        { APP_ID_BITTRACKER_CLIENT, 0 }
    };

    handler->register_detector(name, this, proto);
}


int BitTrackerClientDetector::validate(AppIdDiscoveryArgs& args)
{
    ClientBITData* fd;
    uint16_t offset;

    if (args.size < (UDP_BIT_FIRST_LEN + UDP_BIT_END_LEN + 3))
        return APPID_EINVALID;

    fd = (ClientBITData*)data_get(args.asd);
    if (!fd)
    {
        fd = (ClientBITData*)snort_calloc(sizeof(ClientBITData));
        data_add(args.asd, fd, &snort_free);
        fd->state = BIT_STATE_BANNER;
    }

    offset = 0;
    while (offset < args.size)
    {
        switch (fd->state)
        {
        case BIT_STATE_BANNER:
            if (args.data[offset] != UDP_BIT_FIRST[fd->pos])
                return APPID_EINVALID;
            if (fd->pos == UDP_BIT_FIRST_LEN-1)
                fd->state = BIT_STATE_TYPES;
            fd->pos++;
            break;
        case BIT_STATE_TYPES:
            switch (args.data[offset])
            {
            case 'a':
                fd->type = BIT_TYPE_REQUEST;
                fd->state = BIT_STATE_DC;
                break;
            case 'r':
                fd->type = BIT_TYPE_RESPONSE;
                fd->state = BIT_STATE_DC;
                break;
            case 'e':
                fd->type = BIT_TYPE_ERROR;
                fd->state = BIT_STATE_DC;
                break;
            default:
                return APPID_EINVALID;
            }
            break;

        case BIT_STATE_DC:
            if (offset < (args.size - UDP_BIT_END_LEN))
                break;
            else if (offset == (args.size - UDP_BIT_END_LEN) &&
                args.data[offset] == UDP_BIT_COMMON_END[0])
            {
                fd->state = BIT_STATE_CHECK_END;
                fd->pos = 0;
            }
            else
                return APPID_EINVALID;
        /*fall through */
        case BIT_STATE_CHECK_END:
            if (args.data[offset] != UDP_BIT_COMMON_END[fd->pos])
                return APPID_EINVALID;
            if (fd->pos == UDP_BIT_COMMON_END_LEN-1)
                fd->state = BIT_STATE_CHECK_END_TYPES;
            fd->pos++;
            break;

        case BIT_STATE_CHECK_END_TYPES:
            switch (args.data[offset])
            {
            case 'q':
                if (fd->type != BIT_TYPE_REQUEST)
                    return APPID_EINVALID;
                fd->state = BIT_STATE_CHECK_LAST;
                break;
            case 'r':
                if (fd->type != BIT_TYPE_RESPONSE)
                    return APPID_EINVALID;
                fd->state = BIT_STATE_CHECK_LAST;
                break;
            case 'e':
                if (fd->type != BIT_TYPE_ERROR)
                    return APPID_EINVALID;
                fd->state = BIT_STATE_CHECK_LAST;
                break;
            default:
                return APPID_EINVALID;
            }
            break;

        case BIT_STATE_CHECK_LAST:
            switch (args.data[offset])
            {
            case 'e':
                goto done;
            default:
                return APPID_EINVALID;
            }
            break;

        default:
            goto inprocess;
        }
        offset++;
    }
inprocess:
    return APPID_INPROCESS;

done:
    add_app(args.asd, APP_ID_BITTORRENT, APP_ID_BITTRACKER_CLIENT, nullptr);
    return APPID_SUCCESS;
}

