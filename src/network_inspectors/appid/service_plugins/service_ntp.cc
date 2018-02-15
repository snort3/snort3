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

// service_ntp.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_ntp.h"
#include "application_ids.h"

#pragma pack(1)

struct ServiceNTPTimestamp
{
    uint32_t sec;
    uint32_t frac;
};

struct ServiceNTPHeader
{
    uint8_t LVM;
    uint8_t stratum;
    uint8_t poll;
    int8_t precision;
    uint32_t delay;
    uint32_t dispersion;
    uint32_t id;
    ServiceNTPTimestamp ref;
    ServiceNTPTimestamp orig;
    ServiceNTPTimestamp recv;
    ServiceNTPTimestamp xmit;
};

struct ServiceNTPOptional
{
    uint32_t keyid;
    uint32_t digest[4];
};

#pragma pack()

NtpServiceDetector::NtpServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "ntp";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_NTP, 0 }
    };

    service_ports =
    {
        { 123, IpProtocol::UDP, false },
        { 123, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


int NtpServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    const ServiceNTPHeader* nh;
    uint8_t ver;
    uint8_t mode;

    if (!args.size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    nh = (const ServiceNTPHeader*)args.data;
    mode = nh->LVM & 0x07;
    if (mode == 0 || mode == 7 || mode == 3)
        goto fail;
    ver = nh->LVM & 0x38;
    if (ver > 0x20 || ver < 0x08)
        goto fail;
    if (mode != 6)
    {
        if (ver < 0x18)
        {
            if (args.size != sizeof(ServiceNTPHeader))
                goto fail;
        }
        else if (args.size < sizeof(ServiceNTPHeader) ||
            args.size > sizeof(ServiceNTPHeader)+sizeof(ServiceNTPOptional))
        {
            goto fail;
        }

        if (nh->stratum > 15)
            goto fail;
        if (nh->poll && (nh->poll < 4 || nh->poll > 14))
            goto fail;
        if (nh->precision > -6 || nh->precision < -20)
            goto fail;
    }
    else
    {
        if (args.size < 2)
            goto fail;
        if (!(nh->stratum & 0x80))
            goto fail;
        if (!(nh->stratum & 0x1F))
            goto fail;
    }

    return add_service(args.asd, args.pkt, args.dir, APP_ID_NTP);

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

