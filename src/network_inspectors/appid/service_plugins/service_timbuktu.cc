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

// service_timbuktu.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_timbuktu.h"

#include "application_ids.h"

static char TIMBUKTU_BANNER[]  = "\001\001";

#define TIMBUKTU_PORT    407

#define TIMBUKTU_BANNER_LEN (sizeof(TIMBUKTU_BANNER)-1)

enum TIMBUKTUState
{
    TIMBUKTU_STATE_BANNER,
    TIMBUKTU_STATE_MESSAGE_LEN,
    TIMBUKTU_STATE_MESSAGE_DATA
};

struct ServiceTIMBUKTUData
{
    TIMBUKTUState state;
    unsigned stringlen;
    unsigned pos;
};

#pragma pack(1)
struct ServiceTIMBUKTUMsg
{
    uint16_t any;
    uint8_t res;
    uint8_t len;
    uint8_t message;
};
#pragma pack()

TimbuktuServiceDetector::TimbuktuServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "timbuktu";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)TIMBUKTU_BANNER, sizeof(TIMBUKTU_BANNER) - 1, 0, 0, 0 }
    };

    appid_registry =
    {
        { APP_ID_TIMBUKTU, 0 }
    };

    service_ports =
    {
        { TIMBUKTU_PORT, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


int TimbuktuServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceTIMBUKTUData* ss;
    const uint8_t* data = args.data;
    uint16_t offset=0;

    if (!args.size)
        goto inprocess;
    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    ss = (ServiceTIMBUKTUData*)data_get(args.asd);
    if (!ss)
    {
        ss = (ServiceTIMBUKTUData*)snort_calloc(sizeof(ServiceTIMBUKTUData));
        data_add(args.asd, ss, &snort_free);
        ss->state = TIMBUKTU_STATE_BANNER;
    }

    offset = 0;
    while (offset < args.size)
    {
        switch (ss->state)
        {
        case TIMBUKTU_STATE_BANNER:
            if (data[offset] !=  TIMBUKTU_BANNER[ss->pos])
                goto fail;
            if (ss->pos >= TIMBUKTU_BANNER_LEN-1)
            {
                ss->pos = 0;
                ss->state = TIMBUKTU_STATE_MESSAGE_LEN;
                break;
            }
            ss->pos++;
            break;
        case TIMBUKTU_STATE_MESSAGE_LEN:
            ss->pos++;
            if ( ss->pos >= offsetof(ServiceTIMBUKTUMsg, message) )
            {
                ss->stringlen = data[offset];
                ss->state = TIMBUKTU_STATE_MESSAGE_DATA;
                if (!ss->stringlen)
                {
                    if ( offset == (args.size - 1) )
                        goto success;
                    goto fail;
                }
                ss->pos = 0;
            }
            break;

        case TIMBUKTU_STATE_MESSAGE_DATA:
            ss->pos++;
            if ( ss->pos == ss->stringlen )
            {
                if ( offset == (args.size - 1) )
                    goto success;
                goto fail;
            }
            break;
        default:
            goto fail;
        }
        offset++;
    }

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    return add_service(args.asd, args.pkt, args.dir, APP_ID_TIMBUKTU);

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

