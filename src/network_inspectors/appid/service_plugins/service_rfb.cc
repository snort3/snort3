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

// service_rfb.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_rfb.h"

#include "app_info_table.h"

#define RFB_BANNER_SIZE 12
#define RFB_BANNER "RFB "

RfbServiceDetector::RfbServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "rfb";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)RFB_BANNER, sizeof(RFB_BANNER) - 1, 0, 0, 0 },
    };

    appid_registry =
    {
        { APP_ID_VNC, APPINFO_FLAG_SERVICE_ADDITIONAL },
        { APP_ID_VNC_RFB, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { 5900, IpProtocol::TCP, false },
        { 5901, IpProtocol::TCP, false },
        { 5902, IpProtocol::TCP, false },
        { 5903, IpProtocol::TCP, false },
        { 5904, IpProtocol::TCP, false },
        { 5905, IpProtocol::TCP, false },
        { 5906, IpProtocol::TCP, false },
        { 5907, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


int RfbServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    char version[RFB_BANNER_SIZE-4];
    unsigned i;
    char* v;
    const unsigned char* p;
    const uint8_t* data = args.data;

    if (!args.size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    if (args.size != RFB_BANNER_SIZE)
        goto fail;
    if (strncmp(RFB_BANNER, (const char*)data, sizeof(RFB_BANNER)-1))
        goto fail;
    if (data[7] != '.' || data[RFB_BANNER_SIZE-1] != 0x0A)
        goto fail;
    if (!isdigit(data[4]) || !isdigit(data[5]) || !isdigit(data[6]) ||
        !isdigit(data[8]) || !isdigit(data[9]) || !isdigit(data[10]))
    {
        goto fail;
    }
    v = version;
    p = &data[4];
    for (i=4; i<RFB_BANNER_SIZE-1; i++)
    {
        *v = *p;
        v++;
        p++;
    }
    *v = 0;
    return add_service(args.asd, args.pkt, args.dir, APP_ID_VNC_RFB, nullptr, version, nullptr);

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

