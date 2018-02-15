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

// service_mysql.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_mysql.h"

#include "app_info_table.h"

#pragma pack(1)

struct ServiceMYSQLHdr
{
    union
    {
        uint32_t len;
        struct
        {
            uint8_t len[3];
            uint8_t packet;
        } p;
    } l;
    IpProtocol proto;
};

#pragma pack()

MySqlServiceDetector::MySqlServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "mysql";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_MYSQL, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { 3306, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


int MySqlServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    const uint8_t* data = args.data;
    const ServiceMYSQLHdr* hdr = (const ServiceMYSQLHdr*)data;
    uint32_t len;
    const uint8_t* end;
    const uint8_t* p = nullptr;

    if (!args.size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;
    if (args.size < sizeof(ServiceMYSQLHdr))
        goto fail;

    len = hdr->l.p.len[0];
    len |= hdr->l.p.len[1] << 8;
    len |= hdr->l.p.len[2] << 16;
    len += 4;
    if (len > args.size)
        goto fail;
    if (hdr->l.p.packet)
        goto fail;
    if (hdr->proto != (IpProtocol)0x0A)
        goto fail;

    end = data + len;
    data += sizeof(ServiceMYSQLHdr);
    p = data;
    for (; data<end && *data; data++)
    {
        if (!isprint(*data))
            goto fail;
    }
    if (data >= end)
        goto fail;
    if (data == p)
        p = nullptr;
    data += 5;
    if (data >= end)
        goto fail;
    for (; data<end && *data; data++)
    {
        if (!isprint(*data))
            goto fail;
    }
    data += 6;
    if (data >= end)
        goto fail;
    return add_service(args.asd, args.pkt, args.dir, APP_ID_MYSQL, nullptr, (const char*)p, nullptr);

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

