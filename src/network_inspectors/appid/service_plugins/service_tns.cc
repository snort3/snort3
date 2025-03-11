//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// service_tns.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_tns.h"

#include "app_info_table.h"

// FIXIT-M should we use 'tns' or 'oracle' as the name for this service?
//static const char svc_name[] = "oracle";
static const uint8_t TNS_BANNER[]  = "\000\000";

#define TNS_BANNER_LEN    (sizeof(TNS_BANNER)-1)
#define TNS_PORT    1521

#define TNS_TYPE_CONNECT 1
#define TNS_TYPE_ACCEPT 2
#define TNS_TYPE_ACK 3
#define TNS_TYPE_REFUSE 4
#define TNS_TYPE_REDIRECT 5
#define TNS_TYPE_DATA 6
#define TNS_TYPE_NULL 7
#define TNS_TYPE_ABORT 9
#define TNS_TYPE_RESEND 11
#define TNS_TYPE_MARKER 12
#define TNS_TYPE_ATTENTION 13
#define TNS_TYPE_CONTROL 14
#define TNS_TYPE_MAX 19

enum TNSSvcState
{
    SVC_MSG_LEN = 0,
    SVC_MSG_CHECKSUM,
    SVC_MSG,
    SVC_MSG_RES,
    SVC_MSG_HD_CHECKSUM,
    SVC_MSG_ACCEPT,
    SVC_MSG_DATA
};

#define ACCEPT_VERSION_OFFSET   8
class ServiceTNSData : public AppIdFlowData
{
public:
    ~ServiceTNSData() override = default;

    const char* version = nullptr;
    TNSSvcState state = SVC_MSG_LEN;
    unsigned stringlen = 0;
    unsigned pos = 0;
    unsigned message = 0;
    union
    {
        uint16_t len;
        uint8_t raw_len[2];
    } l = {};
};

#pragma pack(1)
struct ServiceTNSMsg
{
    uint16_t len;
    uint16_t checksum;
    uint8_t msg;
    uint8_t res;
    uint16_t hdchecksum;
    uint8_t data;
};
#pragma pack()

TnsServiceDetector::TnsServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "tns";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)TNS_BANNER, TNS_BANNER_LEN, 2, 0, 0 },
    };

    appid_registry =
    {
        { APP_ID_ORACLE_TNS, APPINFO_FLAG_SERVICE_ADDITIONAL },
    };

    service_ports =
    {
        { TNS_PORT, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


int TnsServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    if (!args.size || args.dir != APP_ID_FROM_RESPONDER)
    {
        service_inprocess(args.asd, args.pkt, args.dir);
        return APPID_INPROCESS;
    }

    ServiceTNSData* ss = (ServiceTNSData*)data_get(args.asd);
    if (!ss)
    {
        ss = new ServiceTNSData();
        data_add(args.asd, ss);
    }

    const uint8_t* data = args.data;
    uint16_t size = args.size;
    uint16_t offset = 0;
    while (offset < size)
    {
        // For some reason, coverity cannot follow the state machine. It does state transitions that are not possible
        // This makes the coverity overrun exceptions necessary
        switch (ss->state)
        {
        case SVC_MSG_LEN:
            // coverity[overrun]
            ss->l.raw_len[ss->pos++] = data[offset];
            if (ss->pos >= offsetof(ServiceTNSMsg, checksum))
            {
                ss->stringlen = ntohs(ss->l.len);
                if (ss->stringlen == 2)
                {
                    if (offset == (size - 1))
                        goto success;
                    goto fail;
                }
                else if (ss->stringlen < 2)
                    goto fail;
                ss->state = SVC_MSG_CHECKSUM;
            }
            break;

        case SVC_MSG_CHECKSUM:
            if (data[offset] != 0)
                goto fail;
            ss->pos++;
            if (ss->pos >= offsetof(ServiceTNSMsg, msg))
                ss->state = SVC_MSG;
            break;

        case SVC_MSG:
            ss->message = data[offset];
            if (ss->message < TNS_TYPE_CONNECT || ss->message > TNS_TYPE_MAX)
                goto fail;
            ss->pos++;
            ss->state = SVC_MSG_RES;
            break;

        case SVC_MSG_RES:
            ss->pos++;
            ss->state = SVC_MSG_HD_CHECKSUM;
            break;

        case SVC_MSG_HD_CHECKSUM:
            ss->pos++;
            if (ss->pos >= offsetof(ServiceTNSMsg, data))
            {
                switch (ss->message)
                {
                case TNS_TYPE_ACCEPT:
                    ss->state = SVC_MSG_ACCEPT;
                    break;
                case TNS_TYPE_ACK:
                case TNS_TYPE_REFUSE:
                case TNS_TYPE_REDIRECT:
                case TNS_TYPE_DATA:
                case TNS_TYPE_NULL:
                case TNS_TYPE_ABORT:
                case TNS_TYPE_MARKER:
                case TNS_TYPE_ATTENTION:
                case TNS_TYPE_CONTROL:
                    if (ss->pos == ss->stringlen)
                    {
                        if (offset == (size - 1))
                            goto success;
                        else
                            goto fail;
                    }
                    ss->state = SVC_MSG_DATA;
                    break;
                case TNS_TYPE_RESEND:
                    if (ss->pos == ss->stringlen)
                    {
                        if (offset == (size - 1))
                        {
                            ss->state = SVC_MSG_LEN;
                            ss->pos = 0;
                            goto inprocess;
                        }
                        else
                            goto fail;
                    }
                    break;
                case TNS_TYPE_CONNECT:
                default:
                    goto fail;
                }
            }
            break;

        case SVC_MSG_ACCEPT:
            // coverity[overrun]
            ss->l.raw_len[ss->pos - ACCEPT_VERSION_OFFSET] = data[offset];
            ss->pos++;
            if (ss->pos == (ACCEPT_VERSION_OFFSET + 2))
            {
                switch (ntohs(ss->l.len))
                {
                case 0x136:
                    ss->version = "8";
                    break;
                case 0x137:
                    ss->version = "9i R1";
                    break;
                case 0x138:
                    ss->version = "9i R2";
                    break;
                case 0x139:
                    ss->version = "10g R1/R2";
                    break;
                case 0x13A:
                    ss->version = "11g R1";
                    break;
                default:
                    break;
                }
                ss->state = SVC_MSG_DATA;
            }
            break;
        case SVC_MSG_DATA:
            ss->pos++;
            if (ss->pos == ss->stringlen)
            {
                if (offset == (size - 1))
                    goto success;
                else
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
    return add_service(args.change_bits, args.asd, args.pkt, args.dir, APP_ID_ORACLE_TNS,
        nullptr, ss->version ? ss->version : nullptr, nullptr);

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

