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

// service_flap.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_flap.h"

#define FLAP_PORT   5190

enum FLAPState
{
    FLAP_STATE_ACK,
    FLAP_STATE_COOKIE
};

#define FNAC_SIGNON 0x0017
#define FNAC_GENERIC 0x0001
#define FNAC_SUB_SIGNON_REPLY 0x0007
#define FNAC_SUB_SERVER_READY 0x0003

struct ServiceFLAPData
{
    FLAPState state;
};

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
    uint8_t type;
    uint16_t seq;
    uint16_t len;
};

#pragma pack()

static uint8_t FLAP_PATTERN[] = { 0x2A, 0x01 };

FlapServiceDetector::FlapServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "flap";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { FLAP_PATTERN, sizeof(FLAP_PATTERN), 0, 0, 0 },
    };

    appid_registry =
    {
        { APP_ID_AOL_INSTANT_MESSENGER, 0 }
    };

    service_ports =
    {
        { 5190, IpProtocol::TCP, false },
        { 9898, IpProtocol::TCP, false },
        { 4443, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


int FlapServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceFLAPData* sf;
    const uint8_t* data = args.data;
    const FLAPHeader* hdr = (const FLAPHeader*)args.data;
    uint16_t size = args.size;
    const FLAPFNAC* ff;
    const FLAPTLV* tlv;
    uint16_t len;

    if (!size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    sf = (ServiceFLAPData*)data_get(args.asd);
    if (!sf)
    {
        sf = (ServiceFLAPData*)snort_calloc(sizeof(ServiceFLAPData));
        data_add(args.asd, sf, &snort_free);
        sf->state = FLAP_STATE_ACK;
    }

    switch (sf->state)
    {
    case FLAP_STATE_ACK:
        sf->state = FLAP_STATE_COOKIE;
        if (size < sizeof(FLAPHeader))
            goto fail;
        if (hdr->start != 0x2A)
            goto fail;
        if (hdr->type != 0x01)
            goto fail;
        if (ntohs(hdr->len) != 4)
            goto fail;
        if (size - sizeof(FLAPHeader) != 4)
            goto fail;
        if (ntohl(*((const uint32_t*)(data + sizeof(FLAPHeader)))) != 0x00000001)
            goto fail;
        goto inprocess;
    case FLAP_STATE_COOKIE:
        if (size < sizeof(FLAPHeader) + sizeof(FLAPFNAC))
            goto fail;
        if (hdr->start != 0x2A)
            goto fail;
        if ((uint16_t)ntohs(hdr->len) != (uint16_t)(size - sizeof(FLAPHeader)))
            goto fail;
        if (hdr->type == 0x02)
        {
            ff = (const FLAPFNAC*)(data + sizeof(FLAPHeader));
            if (ntohs(ff->family) == FNAC_SIGNON)
            {
                const FLAPFNACSignOn* ffs = (const FLAPFNACSignOn*)((const uint8_t*)ff + sizeof(FLAPFNAC));

                if (ntohs(ff->subtype) != FNAC_SUB_SIGNON_REPLY)
                    goto fail;
                if ((uint16_t)ntohs(ffs->len) != (uint16_t)(size -
                    (sizeof(FLAPHeader) +
                    sizeof(FLAPFNAC) +
                    sizeof(FLAPFNACSignOn))))
                    goto fail;
            }
            else if (ntohs(ff->family) == FNAC_GENERIC)
            {
                if (ntohs(ff->subtype) != FNAC_SUB_SERVER_READY)
                    goto fail;
            }
            else
                goto fail;
            goto success;
        }
        if (hdr->type == 0x04)
        {
            data += sizeof(FLAPHeader);
            size -= sizeof(FLAPHeader);
            while (size >= sizeof(FLAPTLV))
            {
                tlv = (const FLAPTLV*)data;
                data += sizeof(FLAPTLV);
                size -= sizeof(FLAPTLV);
                len = ntohs(tlv->len);
                if (size < len)
                    goto fail;
                size -= len;
                data += len;
            }
            if (size)
                goto fail;
            goto success;
        }
        goto fail;
    }

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;

success:
    return add_service(args.asd, args.pkt, args.dir, APP_ID_AOL_INSTANT_MESSENGER);

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;
}

