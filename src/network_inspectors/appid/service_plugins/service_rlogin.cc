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

// service_rlogin.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_rlogin.h"

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


int RloginServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceRLOGINData* rd;
    const uint8_t* data = args.data;

    if (!args.size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    rd = (ServiceRLOGINData*)data_get(args.asd);
    if (!rd)
    {
        rd = (ServiceRLOGINData*)snort_calloc(sizeof(ServiceRLOGINData));
        data_add(args.asd, rd, &snort_free);
        rd->state = RLOGIN_STATE_HANDSHAKE;
    }

    switch (rd->state)
    {
    case RLOGIN_STATE_HANDSHAKE:
        if (args.size != 1)
            goto fail;
        if (*data)
            goto fail;
        rd->state = RLOGIN_STATE_PASSWORD;
        break;
    case RLOGIN_STATE_PASSWORD:
        if (args.pkt->ptrs.tcph->are_flags_set(TH_URG) && args.size >= args.pkt->ptrs.tcph->urp())
        {
            if (args.size != 1)
                goto fail;
            if (*data != 0x80)
                goto fail;
            rd->state = RLOGIN_STATE_DATA;
        }
        else
        {
            if (args.size != sizeof(RLOGIN_PASSWORD)-1)
                goto fail;
            if (strncmp((const char*)data, RLOGIN_PASSWORD, sizeof(RLOGIN_PASSWORD)-1))
                goto fail;
            rd->state = RLOGIN_STATE_CRLF;
        }
        break;
    case RLOGIN_STATE_CRLF:
        if (args.size != 2)
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
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    return add_service(args.asd, args.pkt, args.dir, APP_ID_RLOGIN);

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

