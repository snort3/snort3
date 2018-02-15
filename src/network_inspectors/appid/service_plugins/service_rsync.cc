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

// service_rsync.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_rsync.h"

#include "app_info_table.h"

#define RSYNC_PORT  873
#define RSYNC_BANNER "@RSYNCD: "

enum RSYNCState
{
    RSYNC_STATE_BANNER,
    RSYNC_STATE_MOTD,
    RSYNC_STATE_DONE
};

struct ServiceRSYNCData
{
    RSYNCState state;
};

RsyncServiceDetector::RsyncServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "rsync";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)RSYNC_BANNER, sizeof(RSYNC_BANNER)-1, 0, 0, 0 }
    };

    appid_registry =
    {
        { APP_ID_RSYNC, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { RSYNC_PORT, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


int RsyncServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceRSYNCData* rd;
    int i;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    rd = (ServiceRSYNCData*)data_get(args.asd);
    if (!rd)
    {
        rd = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
        data_add(args.asd, rd, &snort_free);
        rd->state = RSYNC_STATE_BANNER;
    }

    switch (rd->state)
    {
    case RSYNC_STATE_BANNER:
        if (size < sizeof(RSYNC_BANNER)-1)
            goto fail;
        if (data[size-1] != 0x0A)
            goto fail;
        if (strncmp((const char*)data, RSYNC_BANNER, sizeof(RSYNC_BANNER)-1))
            goto fail;
        data += sizeof(RSYNC_BANNER) - 1;
        size -= sizeof(RSYNC_BANNER) - 1;
        for (i=0; i < size - 1; i++)
            if (!isdigit(data[i]) && data[i] != '.')
                goto fail;
        rd->state = RSYNC_STATE_MOTD;
        break;
    case RSYNC_STATE_MOTD:
        if (data[size-1] != 0x0A)
            goto fail;
        for (i=0; i < size - 1; i++)
            if (!isprint(data[i]) && !isspace(data[i]))
                goto fail;
        rd->state = RSYNC_STATE_DONE;
        goto success;
    default:
        goto fail;
    }

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    return add_service(args.asd, args.pkt, args.dir, APP_ID_RSYNC);

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

