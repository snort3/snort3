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

// service_rlogin.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_rlogin.h"

#include "appid_module.h"
#include "application_ids.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

#define RLOGIN_PASSWORD "Password: "
enum RLOGINState
{
    RLOGIN_STATE_HANDSHAKE,
    RLOGIN_STATE_PASSWORD,
    RLOGIN_STATE_CRLF,
    RLOGIN_STATE_DATA,
    RLOGIN_STATE_DONE
};

struct ServiceRLOGINData
{
    RLOGINState state;
};

RloginServiceDetector::RloginServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "rlogin";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_RLOGIN, 0 }
    };

    service_ports =
    {
        { 513, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}

RloginServiceDetector::~RloginServiceDetector()
{
}

int RloginServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceRLOGINData* rd;
    AppIdSession* asd = args.asd;
    Packet* pkt = args.pkt;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    rd = (ServiceRLOGINData*)data_get(asd);
    if (!rd)
    {
        rd = (ServiceRLOGINData*)snort_calloc(sizeof(ServiceRLOGINData));
        data_add(asd, rd, &snort_free);
        rd->state = RLOGIN_STATE_HANDSHAKE;
    }

    switch (rd->state)
    {
    case RLOGIN_STATE_HANDSHAKE:
        if (size != 1)
            goto fail;
        if (*data)
            goto fail;
        rd->state = RLOGIN_STATE_PASSWORD;
        break;
    case RLOGIN_STATE_PASSWORD:
        if (pkt->ptrs.tcph->are_flags_set(TH_URG) && size >= pkt->ptrs.tcph->urp())
        {
            if (size != 1)
                goto fail;
            if (*data != 0x80)
                goto fail;
            rd->state = RLOGIN_STATE_DATA;
        }
        else
        {
            if (size != sizeof(RLOGIN_PASSWORD)-1)
                goto fail;
            if (strncmp((char*)data, RLOGIN_PASSWORD, sizeof(RLOGIN_PASSWORD)-1))
                goto fail;
            rd->state = RLOGIN_STATE_CRLF;
        }
        break;
    case RLOGIN_STATE_CRLF:
        if (size != 2)
            goto fail;
        if (*data != 0x0A || *(data+1) != 0x0D)
            goto fail;
        rd->state = RLOGIN_STATE_DATA;
        break;
    case RLOGIN_STATE_DATA:
        rd->state = RLOGIN_STATE_DONE;
        goto success;
    default:
        goto fail;
    }

inprocess:
    service_inprocess(asd, pkt, args.dir);
    return APPID_INPROCESS;

success:
    add_service(asd, pkt, args.dir, APP_ID_RLOGIN, nullptr, nullptr, nullptr);
    appid_stats.rlogin_flows++;
    return APPID_SUCCESS;

fail:
    fail_service(asd, pkt, args.dir);
    return APPID_NOMATCH;
}

