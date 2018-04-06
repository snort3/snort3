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

// service_telnet.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_telnet.h"

#include <sys/types.h>
#include <netinet/in.h>

#include <cctype>
#include <cstring>
#include <cstdlib>
#include <cstddef>

#include "appid_session.h"
#include "application_ids.h"
#include "utils/util.h"

#define TELNET_COUNT_THRESHOLD 3

#define TELNET_IAC 255
#define TELNET_MIN_CMD 236
#define TELNET_MIN_DATA_CMD 250
#define TELNET_SUB_NEG_CMD 250
#define TELNET_SUB_NEG_END_CMD 240
#define TELNET_CMD_MAX_OPTION 44

enum TELNET_COMMAND_VALUE
{
    TELNET_CMD_SE = 240,
    TELNET_CMD_NOP,
    TELNET_CMD_DMARK,
    TELNET_CMD_BREAK,
    TELNET_CMD_IP,
    TELNET_CMD_AO,
    TELNET_CMD_AYT,
    TELNET_CMD_EC,
    TELNET_CMD_EL,
    TELNET_CMD_GA,
    TELNET_CMD_SB,
    TELNET_CMD_WILL,
    TELNET_CMD_WONT,
    TELNET_CMD_DO,
    TELNET_CMD_DONT,
    TELNET_CMD_IAC
};

struct ServiceTelnetData
{
    unsigned count;
};

TelnetServiceDetector::TelnetServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "telnet";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_TELNET, 0 }
    };

    service_ports =
    {
        { 23, IpProtocol::TCP, false },
        { 23, IpProtocol::UDP, false }
    };

    handler->register_detector(name, this, proto);
}


int TelnetServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceTelnetData* td;
    const uint8_t* end;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    td = (ServiceTelnetData*)data_get(args.asd);
    if (!td)
    {
        td = (ServiceTelnetData*)snort_calloc(sizeof(ServiceTelnetData));
        data_add(args.asd, td, &snort_free);
    }

    for (end=(data+size); data<end; data++)
    {
        /* Currently we only look for the first packet to contain
           wills, won'ts, dos, and don'ts */
        if (*data != TELNET_CMD_IAC)
            goto fail;
        data++;
        if (data >= end)
            goto fail;
        switch (*data)
        {
        case TELNET_CMD_WILL:
        case TELNET_CMD_WONT:
        case TELNET_CMD_DO:
        case TELNET_CMD_DONT:
            data++;
            if (data >= end)
                goto fail;
            td->count++;
            if (td->count >= TELNET_COUNT_THRESHOLD)
                goto success;
            break;
        default:
            goto fail;
        }
    }
inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    return add_service(args.asd, args.pkt, args.dir, APP_ID_TELNET);

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

