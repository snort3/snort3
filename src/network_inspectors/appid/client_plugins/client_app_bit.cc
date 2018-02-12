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

// client_app_bit.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_app_bit.h"

#include "application_ids.h"

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

BitClientDetector::BitClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "BIT";
    proto = IpProtocol::TCP;
    minimum_matches = 1;

    tcp_patterns =
    {
        { (const uint8_t*)BIT_BANNER, BIT_BANNER_LEN, -1, 0, APP_ID_BITTORRENT }
    };

    appid_registry =
    {
        { APP_ID_BITTORRENT, 0 }
    };

    handler->register_detector(name, this, proto);
}


int BitClientDetector::validate(AppIdDiscoveryArgs& args)
{
    ClientBITData* fd;
    uint16_t offset;

    if (args.dir != APP_ID_FROM_INITIATOR)
        return APPID_INPROCESS;

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
            if (args.data[offset] != BIT_BANNER[fd->pos])
                return APPID_EINVALID;
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
            fd->l.raw_len[fd->pos] = args.data[offset];
            fd->pos++;
            if (fd->pos >= offsetof(ClientBITMsg, code))
            {
                fd->stringlen = ntohl(fd->l.len);
                fd->state = BIT_STATE_MESSAGE_DATA;
                if (!fd->stringlen)
                {
                    if (offset == args.size - 1)
                        goto done;
                    return APPID_EINVALID;
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
    return APPID_INPROCESS;

done:
    add_app(args.asd, APP_ID_BITTORRENT, APP_ID_BITTORRENT, nullptr);
    return APPID_SUCCESS;
}

