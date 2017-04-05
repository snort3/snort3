//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// service_bgp.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_bgp.h"

#include "appid_module.h"

static const unsigned BGP_PORT = 179;

static const unsigned BGP_V1_TYPE_OPEN = 1;
static const unsigned BGP_V1_TYPE_OPEN_CONFIRM = 5;
static const unsigned BGP_TYPE_OPEN = 1;
static const unsigned BGP_TYPE_KEEPALIVE = 4;

static const unsigned BGP_OPEN_LINK_MAX = 3;

static const unsigned BGP_VERSION_MAX = 4;
static const unsigned BGP_VERSION_MIN = 2;

enum BGPState
{
    BGP_STATE_CONNECTION,
    BGP_STATE_OPENSENT
};

#pragma pack(1)

struct ServiceBGPData
{
    BGPState state;
    int v1;
};

union ServiceBGPHeader
{
    struct
    {
        uint16_t marker;
        uint16_t len;
        uint8_t version;
        uint8_t type;
        uint16_t hold;
    } v1;
    struct
    {
        uint32_t marker[4];
        uint16_t len;
        uint8_t type;
    } v;
};

struct ServiceBGPOpen
{
    uint8_t version;
    uint16_t as;
    uint16_t holdtime;
};

struct ServiceBGPV1Open
{
    uint16_t system;
    uint8_t link;
    uint8_t auth;
};

#pragma pack()

static uint8_t BGP_PATTERN[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

BgpServiceDetector::BgpServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "bgp";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (uint8_t*)BGP_PATTERN, sizeof(BGP_PATTERN), 0, 0, 0 },
    };

    appid_registry =
    {
        { APP_ID_BGP, 0 }
    };

    service_ports =
    {
        { BGP_PORT, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}

BgpServiceDetector::~BgpServiceDetector()
{
}

int BgpServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceBGPData* bd;
    const ServiceBGPHeader* bh;
    AppIdSession* asd = args.asd;
    const uint8_t* data = args.data;
    uint16_t size = args.size;
    uint16_t len;

    if (!size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    if (size < sizeof(ServiceBGPHeader))
        goto fail;

    bd = (ServiceBGPData*)data_get(asd);
    if (!bd)
    {
        bd = (ServiceBGPData*)snort_calloc(sizeof(ServiceBGPData));
        data_add(asd, bd, &snort_free);
        bd->state = BGP_STATE_CONNECTION;
    }

    bh = (const ServiceBGPHeader*)data;
    switch (bd->state)
    {
    case BGP_STATE_CONNECTION:
        if (size >= sizeof(bh->v1) + sizeof(ServiceBGPV1Open) &&
            bh->v1.marker == 0xFFFF &&
            bh->v1.version == 0x01 && bh->v1.type == BGP_V1_TYPE_OPEN)
        {
            ServiceBGPV1Open* open;

            len = ntohs(bh->v1.len);
            if (len > 1024)
                goto fail;
            open = (ServiceBGPV1Open*)(data + sizeof(bh->v1));
            if (open->link > BGP_OPEN_LINK_MAX)
                goto fail;
            bd->v1 = 1;
        }
        else if (size >= sizeof(bh->v) + sizeof(ServiceBGPOpen) &&
            bh->v.marker[0] == 0xFFFFFFFF &&
            bh->v.marker[1] == 0xFFFFFFFF &&
            bh->v.marker[2] == 0xFFFFFFFF &&
            bh->v.marker[3] == 0xFFFFFFFF &&
            bh->v.type == BGP_TYPE_OPEN)
        {
            ServiceBGPOpen* open;

            len = ntohs(bh->v.len);
            if (len > 4096)
                goto fail;
            open = (ServiceBGPOpen*)(data + sizeof(bh->v));
            if (open->version > BGP_VERSION_MAX ||
                open->version < BGP_VERSION_MIN)
            {
                goto fail;
            }
            bd->v1 = 0;
        }
        else
            goto fail;
        bd->state = BGP_STATE_OPENSENT;
        break;
    case BGP_STATE_OPENSENT:
        if (bd->v1)
        {
            if (size >= sizeof(bh->v1) && bh->v1.marker == 0xFFFF &&
                bh->v1.version == 0x01 &&
                bh->v1.type == BGP_V1_TYPE_OPEN_CONFIRM)
            {
                len = ntohs(bh->v1.len);
                if (len != sizeof(bh->v1))
                    goto fail;
                goto success;
            }
        }
        else
        {
            if (size >= sizeof(bh->v) &&
                bh->v.type == BGP_TYPE_KEEPALIVE)
            {
                len = ntohs(bh->v.len);
                if (len != sizeof(bh->v))
                    goto fail;
                goto success;
            }
        }
    default:
        goto fail;
    }

inprocess:
    service_inprocess(asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(asd, args.pkt, args.dir);
    return APPID_NOMATCH;

success:
    add_service(asd, args.pkt, args.dir, APP_ID_BGP, nullptr, nullptr, nullptr);
    appid_stats.bgp_flows++;
    return APPID_SUCCESS;
}

