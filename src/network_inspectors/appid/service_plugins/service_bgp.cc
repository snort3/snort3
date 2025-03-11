//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

class ServiceBGPData : public AppIdFlowData
{
public:
    ~ServiceBGPData() override = default;

    BGPState state = BGP_STATE_CONNECTION;
    bool v1 = false;
};

#pragma pack(1)

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


int BgpServiceDetector::validate(AppIdDiscoveryArgs& args)
{

    if (!args.size || args.dir != APP_ID_FROM_RESPONDER)
    {
        service_inprocess(args.asd, args.pkt, args.dir);
        return APPID_INPROCESS;
    }

    if (args.size < sizeof(ServiceBGPHeader))
    {
        fail_service(args.asd, args.pkt, args.dir);
        return APPID_NOMATCH;
    }

    ServiceBGPData* bd = (ServiceBGPData*)data_get(args.asd);
    if (!bd)
    {
        bd = new ServiceBGPData;
        data_add(args.asd, bd);
    }

    const uint8_t* data = args.data;
    const ServiceBGPHeader* bh = (const ServiceBGPHeader*)data;
    switch (bd->state)
    {
    case BGP_STATE_CONNECTION:
        if (args.size >= sizeof(bh->v1) + sizeof(ServiceBGPV1Open) &&
            bh->v1.marker == 0xFFFF &&
            bh->v1.version == 0x01 && bh->v1.type == BGP_V1_TYPE_OPEN)
        {
            uint16_t len = ntohs(bh->v1.len);
            if (len > 1024)
                goto fail;
            const ServiceBGPV1Open* open = (const ServiceBGPV1Open*)(data + sizeof(bh->v1));
            if (open->link > BGP_OPEN_LINK_MAX)
                goto fail;
            bd->v1 = true;
        }
        else if (args.size >= sizeof(bh->v) + sizeof(ServiceBGPOpen) &&
            bh->v.marker[0] == 0xFFFFFFFF &&
            bh->v.marker[1] == 0xFFFFFFFF &&
            bh->v.marker[2] == 0xFFFFFFFF &&
            bh->v.marker[3] == 0xFFFFFFFF &&
            bh->v.type == BGP_TYPE_OPEN)
        {
            uint16_t len = ntohs(bh->v.len);
            if (len > 4096)
                goto fail;
            const ServiceBGPOpen* open = (const ServiceBGPOpen*)(data + sizeof(bh->v));
            if (open->version > BGP_VERSION_MAX ||
                open->version < BGP_VERSION_MIN)
            {
                goto fail;
            }
            bd->v1 = false;
        }
        else
            goto fail;
        bd->state = BGP_STATE_OPENSENT;
        break;
    case BGP_STATE_OPENSENT:
        if (bd->v1)
        {
            if (args.size >= sizeof(bh->v1) && bh->v1.marker == 0xFFFF &&
                bh->v1.version == 0x01 &&
                bh->v1.type == BGP_V1_TYPE_OPEN_CONFIRM)
            {
                uint16_t len = ntohs(bh->v1.len);
                if (len != sizeof(bh->v1))
                    goto fail;
                goto success;
            }
        }
        else
        {
            if (args.size >= sizeof(bh->v) &&
                bh->v.type == BGP_TYPE_KEEPALIVE)
            {
                uint16_t len = ntohs(bh->v.len);
                if (len != sizeof(bh->v))
                    goto fail;
                goto success;
            }
        }
    default:
        goto fail;
    }

    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;

success:
    return add_service(args.change_bits, args.asd, args.pkt, args.dir, APP_ID_BGP);
}

