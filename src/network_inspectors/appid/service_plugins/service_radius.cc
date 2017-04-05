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

// service_radius.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_radius.h"

#include "appid_module.h"
#include "app_info_table.h"

#define RADIUS_CODE_ACCESS_REQUEST       1
#define RADIUS_CODE_ACCESS_ACCEPT        2
#define RADIUS_CODE_ACCESS_REJECT        3
#define RADIUS_CODE_ACCOUNTING_REQUEST   4
#define RADIUS_CODE_ACCOUNTING_RESPONSE  5
#define RADIUS_CODE_ACCESS_CHALLENGE    11

enum RADIUSState
{
    RADIUS_STATE_REQUEST,
    RADIUS_STATE_RESPONSE
};

struct ServiceRADIUSData
{
    RADIUSState state;
    uint8_t id;
};

#pragma pack(1)

struct RADIUSHeader
{
    uint8_t code;
    uint8_t id;
    uint16_t length;
    uint8_t auth[16];
};

#pragma pack()

RadiusServiceDetector::RadiusServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "radius";
    proto = IpProtocol::UDP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_RADIUS, APPINFO_FLAG_SERVICE_UDP_REVERSED }
    };

    service_ports =
    {
        { 1812, IpProtocol::UDP, false },
        { 1812, IpProtocol::UDP, true }
    };

    handler->register_detector(name, this, proto);
}

RadiusServiceDetector::~RadiusServiceDetector()
{
}

int RadiusServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceRADIUSData* rd;
    const RADIUSHeader* hdr = (const RADIUSHeader*)args.data;
    uint16_t len;
    int new_dir;
    AppIdSession* asd = args.asd;
    const int dir = args.dir;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;
    if (size < sizeof(RADIUSHeader))
        goto fail;

    rd = (ServiceRADIUSData*)data_get(asd);
    if (!rd)
    {
        rd = (ServiceRADIUSData*)snort_calloc(sizeof(ServiceRADIUSData));
        data_add(asd, rd, &snort_free);
        rd->state = RADIUS_STATE_REQUEST;
    }

    new_dir = dir;
    if (rd->state == RADIUS_STATE_REQUEST)
    {
        if (hdr->code == RADIUS_CODE_ACCESS_ACCEPT ||
            hdr->code == RADIUS_CODE_ACCESS_REJECT ||
            hdr->code == RADIUS_CODE_ACCESS_CHALLENGE)
        {
            asd->set_session_flags(APPID_SESSION_UDP_REVERSED);
            rd->state = RADIUS_STATE_RESPONSE;
            new_dir = APP_ID_FROM_RESPONDER;
        }
    }
    else if (asd->get_session_flags(APPID_SESSION_UDP_REVERSED))
    {
        new_dir = (dir == APP_ID_FROM_RESPONDER) ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    }

    switch (rd->state)
    {
    case RADIUS_STATE_REQUEST:
        if (new_dir != APP_ID_FROM_INITIATOR)
            goto inprocess;
        if (hdr->code != RADIUS_CODE_ACCESS_REQUEST)
        {
            goto not_compatible;
        }
        len = ntohs(hdr->length);
        if (len > size)
        {
            goto not_compatible;
        }
        /* Must contain a username attribute */
        if (len < sizeof(RADIUSHeader)+3)
        {
            goto not_compatible;
        }
        rd->id = hdr->id;
        rd->state = RADIUS_STATE_RESPONSE;
        break;
    case RADIUS_STATE_RESPONSE:
        if (new_dir != APP_ID_FROM_RESPONDER)
            goto inprocess;
        if (hdr->code != RADIUS_CODE_ACCESS_ACCEPT &&
            hdr->code != RADIUS_CODE_ACCESS_REJECT &&
            hdr->code != RADIUS_CODE_ACCESS_CHALLENGE)
        {
            goto fail;
        }
        len = ntohs(hdr->length);
        if (len > size)
            goto fail;
        /* Must contain a username attribute */
        if (len < sizeof(RADIUSHeader))
            goto fail;
        if (hdr->id != rd->id)
        {
            rd->state = RADIUS_STATE_REQUEST;
            goto inprocess;
        }
        goto success;
    default:
        goto fail;
    }
inprocess:
    service_inprocess(asd, args.pkt, dir);
    return APPID_INPROCESS;

success:
    add_service(asd, args.pkt, dir, APP_ID_RADIUS, nullptr, nullptr, nullptr);
    appid_stats.radius_flows++;
    return APPID_SUCCESS;

not_compatible:
    incompatible_data(asd, args.pkt, dir);
    return APPID_NOT_COMPATIBLE;

fail:
    fail_service(asd, args.pkt, dir);
    return APPID_NOMATCH;
}

RadiusAcctServiceDetector::RadiusAcctServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "radiusacct";
    proto = IpProtocol::UDP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_RADIUS_ACCT, APPINFO_FLAG_SERVICE_UDP_REVERSED },
    };

    service_ports =
    {
        { 1813, IpProtocol::UDP, false },
        { 1813, IpProtocol::UDP, true }
    };

    handler->register_detector(name, this, proto);
}

RadiusAcctServiceDetector::~RadiusAcctServiceDetector()
{
}

int RadiusAcctServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceRADIUSData* rd;
    const RADIUSHeader* hdr = (const RADIUSHeader*)args.data;
    uint16_t len;
    int new_dir;
    AppIdSession* asd = args.asd;
    const int dir = args.dir;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;
    if (size < sizeof(RADIUSHeader))
        goto fail;

    rd = (ServiceRADIUSData*)data_get(asd);
    if (!rd)
    {
        rd = (ServiceRADIUSData*)snort_calloc(sizeof(ServiceRADIUSData));
        data_add(asd, rd, &snort_free);
        rd->state = RADIUS_STATE_REQUEST;
    }

    new_dir = dir;
    if (rd->state == RADIUS_STATE_REQUEST)
    {
        if (hdr->code == RADIUS_CODE_ACCOUNTING_RESPONSE)
        {
            asd->set_session_flags(APPID_SESSION_UDP_REVERSED);
            rd->state = RADIUS_STATE_RESPONSE;
            new_dir = APP_ID_FROM_RESPONDER;
        }
    }
    else if (asd->get_session_flags(APPID_SESSION_UDP_REVERSED))
    {
        new_dir = (dir == APP_ID_FROM_RESPONDER) ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    }

    switch (rd->state)
    {
    case RADIUS_STATE_REQUEST:
        if (new_dir != APP_ID_FROM_INITIATOR)
            goto inprocess;
        if (hdr->code != RADIUS_CODE_ACCOUNTING_REQUEST)
        {
            goto not_compatible;
        }
        len = ntohs(hdr->length);
        if (len > size)
        {
            goto not_compatible;
        }
        /* Must contain a username attribute */
        if (len < sizeof(RADIUSHeader)+3)
        {
            goto not_compatible;
        }
        rd->id = hdr->id;
        rd->state = RADIUS_STATE_RESPONSE;
        break;
    case RADIUS_STATE_RESPONSE:
        if (new_dir != APP_ID_FROM_RESPONDER)
            goto inprocess;
        if (hdr->code != RADIUS_CODE_ACCOUNTING_RESPONSE)
            goto fail;
        len = ntohs(hdr->length);
        if (len > size)
            goto fail;
        /* Must contain a NAS-IP-Address or NAS-Identifier attribute */
        if (len < sizeof(RADIUSHeader))
            goto fail;
        if (hdr->id != rd->id)
        {
            rd->state = RADIUS_STATE_REQUEST;
            goto inprocess;
        }
        goto success;
    default:
        goto fail;
    }
inprocess:
    service_inprocess(asd, args.pkt, dir);
    return APPID_INPROCESS;

success:
    add_service(asd, args.pkt, dir,
        APP_ID_RADIUS_ACCT, nullptr, nullptr, nullptr);
    appid_stats.radius_flows++;
    return APPID_SUCCESS;

not_compatible:
    incompatible_data(asd, args.pkt, dir);
    return APPID_NOT_COMPATIBLE;

fail:
    fail_service(asd, args.pkt, dir);
    return APPID_NOMATCH;
}

