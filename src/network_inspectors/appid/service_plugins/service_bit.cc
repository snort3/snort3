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

// service_bit.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_bit.h"

static const uint8_t BIT_BANNER[]  = "\023BitTorrent protocol";

#define BIT_PORT    6881

#define BIT_BANNER_LEN (sizeof(BIT_BANNER)-1)
#define RES_LEN 8
#define SHA_LEN 20
#define PEER_ID_LEN 20
#define LAST_BANNER_OFFSET      (BIT_BANNER_LEN+RES_LEN+SHA_LEN+PEER_ID_LEN - 1)

enum BITState
{
    BIT_STATE_BANNER,
    BIT_STATE_BANNER_DC,
    BIT_STATE_MESSAGE_LEN,
    BIT_STATE_MESSAGE_DATA
};

struct ServiceBITData
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
struct ServiceBITMsg
{
    uint32_t len;
    uint8_t code;
};
#pragma pack()

BitServiceDetector::BitServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "bit";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)BIT_BANNER, sizeof(BIT_BANNER) - 1, 0, 0, 0 },
    };

    appid_registry =
    {
        { APP_ID_BITTORRENT, 0 }
    };

    service_ports =
    {
        { BIT_PORT, IpProtocol::TCP,   false },
        { BIT_PORT+1, IpProtocol::TCP, false },
        { BIT_PORT+2, IpProtocol::TCP, false },
        { BIT_PORT+3, IpProtocol::TCP, false },
        { BIT_PORT+4, IpProtocol::TCP, false },
        { BIT_PORT+5, IpProtocol::TCP, false },
        { BIT_PORT+6, IpProtocol::TCP, false },
        { BIT_PORT+7, IpProtocol::TCP, false },
        { BIT_PORT+8, IpProtocol::TCP, false },
    };

    handler->register_detector(name, this, proto);
}


int BitServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceBITData* ss;
    const uint8_t* data = args.data;
    uint16_t offset;

    if (!args.size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    ss = (ServiceBITData*)data_get(args.asd);
    if (!ss)
    {
        ss = (ServiceBITData*)snort_calloc(sizeof(ServiceBITData));
        data_add(args.asd, ss, &snort_free);
        ss->state = BIT_STATE_BANNER;
    }

    offset = 0;
    while (offset < args.size)
    {
        switch (ss->state)
        {
        case BIT_STATE_BANNER:
            if (data[offset] !=  BIT_BANNER[ss->pos])
                goto fail;
            if (ss->pos == BIT_BANNER_LEN-1)
                ss->state = BIT_STATE_BANNER_DC;
            ss->pos++;
            break;
        case BIT_STATE_BANNER_DC:
            if (ss->pos == LAST_BANNER_OFFSET)
            {
                ss->pos = 0;
                ss->state = BIT_STATE_MESSAGE_LEN;
                break;
            }
            ss->pos++;
            break;
        case BIT_STATE_MESSAGE_LEN:
            ss->l.raw_len[ss->pos] = data[offset];
            ss->pos++;
            if (ss->pos >= offsetof(ServiceBITMsg, code))
            {
                ss->stringlen = ntohl(ss->l.len);
                ss->state = BIT_STATE_MESSAGE_DATA;
                if (!ss->stringlen)
                {
                    if (offset == args.size-1)
                        goto success;
                    goto fail;
                }
                ss->pos = 0;
            }
            break;

        case BIT_STATE_MESSAGE_DATA:
            ss->pos++;
            if (ss->pos == ss->stringlen)
                goto success;
            break;
        default:
            goto fail;
        }
        offset++;
    }

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    return add_service(args.asd, args.pkt, args.dir, APP_ID_BITTORRENT);

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

