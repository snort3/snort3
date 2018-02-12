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

// service_battle_field.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_battle_field.h"

#include "protocols/packet.h"

enum CONNECTION_STATES
{
    CONN_STATE_INIT,
    CONN_STATE_HELLO_DETECTED,
    CONN_STATE_SERVICE_DETECTED,
    CONN_STATE_MESSAGE_DETECTED,
    CONN_STATE_MAX
};

static const unsigned MAX_PACKET_INSPECTION_COUNT = 10;

struct ServiceData
{
    uint32_t state;
    uint32_t messageId;
    uint32_t packetCount;
};

static const char PATTERN_HELLO[] = "battlefield2\x00";
static const char PATTERN_2[] = "\xfe\xfd";
static const char PATTERN_3[] = "\x11\x20\x00\x01\x00\x00\x50\xb9\x10\x11";
static const char PATTERN_4[] = "\x11\x20\x00\x01\x00\x00\x30\xb9\x10\x11";
static const char PATTERN_5[] = "\x11\x20\x00\x01\x00\x00\xa0\x98\x00\x11";
static const char PATTERN_6[] = "\xfe\xfd\x09\x00\x00\x00\x00";

BattleFieldServiceDetector::BattleFieldServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "BattleField";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)PATTERN_HELLO, sizeof(PATTERN_HELLO) - 1,  5, 0, 0 },
        { (const uint8_t*)PATTERN_2, sizeof(PATTERN_2) - 1,  0, 0, 0 },
        { (const uint8_t*)PATTERN_3, sizeof(PATTERN_3) - 1,  0, 0, 0 },
        { (const uint8_t*)PATTERN_4, sizeof(PATTERN_4) - 1,  0, 0, 0 },
        { (const uint8_t*)PATTERN_5, sizeof(PATTERN_5) - 1,  0, 0, 0 },
        { (const uint8_t*)PATTERN_6, sizeof(PATTERN_6) - 1,  0, 0, 0 }
    };

    appid_registry =
    {
        { APP_ID_BATTLEFIELD, 0 }
    };

    service_ports =
    {
        { 4711,  IpProtocol::TCP, false },
        { 16567, IpProtocol::UDP, false },
        { 27900, IpProtocol::UDP, false },
        { 27900, IpProtocol::TCP, false },
        { 29900, IpProtocol::UDP, false },
        { 29900, IpProtocol::TCP, false },
        { 27901, IpProtocol::TCP, false },
        { 28910, IpProtocol::UDP, false }
    };

    handler->register_detector(name, this, proto);
}


static inline uint32_t get_message_id(const uint8_t* msg)
{
    return (msg[2] << 8) | msg[3];
}

int BattleFieldServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceData* fd;

    if (!args.size)
        goto inprocess_nofd;

    fd = (ServiceData*)data_get(args.asd);
    if (!fd)
    {
        fd = (ServiceData*)snort_calloc(sizeof(ServiceData));
        data_add(args.asd, fd, &snort_free);
    }

    switch (fd->state)
    {
    case CONN_STATE_INIT:
        if ((args.pkt->ptrs.sp >= 27000 || args.pkt->ptrs.dp >= 27000) && args.size >= 4)
        {
            if (args.data[0] == 0xfe && args.data[1] == 0xfd)
            {
                fd->messageId = get_message_id(args.data);
                fd->state = CONN_STATE_MESSAGE_DETECTED;
                goto inprocess;
            }
        }

        if (args.size == 18 &&
            memcmp(args.data + 5, PATTERN_HELLO, sizeof(PATTERN_HELLO) -1) ==  0)
        {
            fd->state = CONN_STATE_HELLO_DETECTED;
            goto inprocess;
        }
        break;

    case CONN_STATE_MESSAGE_DETECTED:
        if (args.size > 8)
        {
            if ((uint32_t)(args.data[0] << 8 | args.data[1]) == fd->messageId)
            {
                goto success;
            }

            if (args.data[0] == 0xfe && args.data[1] == 0xfd)
            {
                fd->messageId = get_message_id(args.data);
                goto inprocess;
            }
        }

        fd->state = CONN_STATE_INIT;
        goto inprocess;
        break;

    case CONN_STATE_HELLO_DETECTED:
        if ((args.size == 7) && (memcmp(args.data, PATTERN_6, sizeof(PATTERN_6) - 1) == 0))
        {
            goto success;
        }

        if ((args.size > 10)
            && ((memcmp(args.data, PATTERN_3, sizeof(PATTERN_3) - 1) == 0)
            || (memcmp(args.data, PATTERN_4, sizeof(PATTERN_4) - 1) == 0)
            || (memcmp(args.data, PATTERN_5, sizeof(PATTERN_5) - 1) == 0)))
        {
            goto success;
        }
        break;

    case CONN_STATE_SERVICE_DETECTED:
        goto success;
    }

    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;

inprocess:
    fd->packetCount++;
    if (fd->packetCount >= MAX_PACKET_INSPECTION_COUNT)
        goto fail;

inprocess_nofd:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    if (args.dir != APP_ID_FROM_RESPONDER)
    {
        fd->state = CONN_STATE_SERVICE_DETECTED;
        goto inprocess;
    }

    return add_service(args.asd, args.pkt, args.dir, APP_ID_BATTLEFIELD);

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

