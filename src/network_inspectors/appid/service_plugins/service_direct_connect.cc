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

// service_direct_connect.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_direct_connect.h"

using namespace snort;

enum CONNECTION_STATES
{
    CONN_STATE_INIT,
    CONN_STATE_1,
    CONN_STATE_2,
    CONN_STATE_SERVICE_DETECTED,
    CONN_STATE_MAX
};

#define MAX_PACKET_INSPECTION_COUNT      10

struct ServiceData
{
    uint32_t state;
    uint32_t packetCount;
};

#define PATTERN1     "$Lock "
#define PATTERN2     "$MyNick "
#define PATTERN3     "HSUP ADBAS0"
#define PATTERN4     "HSUP ADBASE"
#define PATTERN5     "CSUP ADBAS0"
#define PATTERN6     "CSUP ADBASE"
#define PATTERN7     "$SR "

DirectConnectServiceDetector::DirectConnectServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "DirectConnect";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)PATTERN1, sizeof(PATTERN1) - 1, 0, 0, 0 },
        { (const uint8_t*)PATTERN2, sizeof(PATTERN2) - 1, 0, 0, 0 },
        { (const uint8_t*)PATTERN3, sizeof(PATTERN3) - 1, 0, 0, 0 },
        { (const uint8_t*)PATTERN4, sizeof(PATTERN4) - 1, 0, 0, 0 },
        { (const uint8_t*)PATTERN5, sizeof(PATTERN5) - 1, 0, 0, 0 },
        { (const uint8_t*)PATTERN6, sizeof(PATTERN6) - 1, 0, 0, 0 },
        { (const uint8_t*)PATTERN7, sizeof(PATTERN7) - 1, 0, 0, 0 }
    };

    appid_registry =
    {
        { APP_ID_DIRECT_CONNECT, 0 }
    };

    service_ports =
    {
        { 411, IpProtocol::TCP, false },
        { 411, IpProtocol::UDP, false },
        { 412, IpProtocol::TCP, false },
        { 412, IpProtocol::UDP, false },
        { 413, IpProtocol::TCP, false },
        { 413, IpProtocol::UDP, false },
        { 414, IpProtocol::TCP, false },
        { 414, IpProtocol::UDP, false },
    };

    handler->register_detector(name, this, proto);
}


int DirectConnectServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceData* fd;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    if (!size)
    {
        service_inprocess(args.asd, args.pkt, args.dir);
        return APPID_INPROCESS;
    }

    fd = (ServiceData*)data_get(args.asd);
    if (!fd)
    {
        fd = (ServiceData*)snort_calloc(sizeof(ServiceData));
        data_add(args.asd, fd, &snort_free);
    }

    if (args.asd.protocol == IpProtocol::TCP)
        return tcp_validate(data, size, args.dir, args.asd, args.pkt, fd);
    else
        return udp_validate(data, size, args.dir, args.asd, args.pkt, fd);
}

int DirectConnectServiceDetector::tcp_validate(const uint8_t* data, uint16_t size, const AppidSessionDirection dir,
    AppIdSession& asd, const Packet* pkt, ServiceData* serviceData)
{
    switch (serviceData->state)
    {
    case CONN_STATE_INIT:
        if (size > 6
            && data[size-1] == '|'
            /*&& data[size-1] == '$'*/)
        {
            if (memcmp(data, PATTERN1, sizeof(PATTERN1)-1) == 0)
            {
                printf("maybe first directconnect to hub  detected\n");
                serviceData->state = CONN_STATE_1;
                goto inprocess;
            }

            if (memcmp(data, PATTERN2, sizeof(PATTERN2)-1) == 0)
            {
                printf("maybe first dc connect between peers  detected\n");
                serviceData->state = CONN_STATE_2;
                goto inprocess;
            }
        }

        if (size >= 11)
        {
            if (memcmp(data, PATTERN3, sizeof(PATTERN3)-1) == 0
                || memcmp(data, PATTERN4, sizeof(PATTERN4)-1) == 0
                || memcmp(data, PATTERN5, sizeof(PATTERN5)-1) == 0
                || memcmp(data, PATTERN6, sizeof(PATTERN6)-1) == 0)
            {
                goto success;
            }
        }
        break;

    case CONN_STATE_1:
        printf ("ValidateDirectConnectTcp(): state 1 size %d\n", size);
        if (size >= 11)
        {
            if (memcmp(data, PATTERN3, sizeof(PATTERN3)-1) == 0
                || memcmp(data, PATTERN4, sizeof(PATTERN4)-1) == 0
                || memcmp(data, PATTERN5, sizeof(PATTERN5)-1) == 0
                || memcmp(data, PATTERN6, sizeof(PATTERN6)-1) == 0)
            {
                printf("found directconnect HSUP ADBAS E in second packet\n");
                goto success;
            }
        }

        if (size > 6)
        {
            if ((data[0] == '$' || data[0] == '<')
                && data[size-2] == '|'
                && data[size-1] == '$')
            {
                goto success;
            }
            else
            {
                goto inprocess;
            }
        }
        break;

    case CONN_STATE_2:
        if (size > 6)
        {
            if (data[0] == '$' && data[size-2] == '|' && data[size-1] == '$')
            {
                goto success;
            }
            else
            {
                goto inprocess;
            }
        }
        break;

    case CONN_STATE_SERVICE_DETECTED:
        goto success;
    }

inprocess:
    serviceData->packetCount++;
    if (serviceData->packetCount >= MAX_PACKET_INSPECTION_COUNT)
        goto fail;

    service_inprocess(asd, pkt, dir);
    return APPID_INPROCESS;

success:
    if (dir != APP_ID_FROM_RESPONDER)
    {
        serviceData->state = CONN_STATE_SERVICE_DETECTED;
        goto inprocess;
    }

    return add_service(asd, pkt, dir, APP_ID_DIRECT_CONNECT);

fail:
    fail_service(asd, pkt, dir);
    return APPID_NOMATCH;
}

int DirectConnectServiceDetector::udp_validate(const uint8_t* data, uint16_t size, const AppidSessionDirection dir,
    AppIdSession& asd, const Packet* pkt, ServiceData* serviceData)
{
    if (dir == APP_ID_FROM_RESPONDER && serviceData->state == CONN_STATE_SERVICE_DETECTED)
    {
        goto reportSuccess;
    }

    if (size > 58)
    {
        if (memcmp(data, PATTERN7, sizeof(PATTERN7)-1) == 0
            && data[size-3] == ')'
            && data[size-2] == '|'
            && data[size-1] == '$')
        {
            goto success;
        }
        serviceData->state +=  1;

        if (serviceData->state != CONN_STATE_SERVICE_DETECTED)
            goto inprocess;
        else
            goto fail;
    }

inprocess:
    serviceData->packetCount++;
    if (serviceData->packetCount >= MAX_PACKET_INSPECTION_COUNT)
        goto fail;

    service_inprocess(asd, pkt, dir);
    return APPID_INPROCESS;

success:
    if (dir != APP_ID_FROM_RESPONDER)
    {
        serviceData->state = CONN_STATE_SERVICE_DETECTED;
        goto inprocess;
    }

reportSuccess:
    return add_service(asd, pkt, dir, APP_ID_DIRECT_CONNECT);

fail:
    fail_service(asd, pkt, dir);
    return APPID_NOMATCH;
}

