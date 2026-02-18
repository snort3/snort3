//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

// service_dcerpc.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_dcerpc.h"

#include <arpa/inet.h>

#define DCERPC_THRESHOLD    3
#define DCERPC_PORT 135

#define min(x,y) ((x)<(y) ? (x) : (y))

static int dcerpc_validate(const uint8_t* data, int size)
{
    const DCERPCHeader* hdr;
    uint16_t len;

    if (size < (int)sizeof(DCERPCHeader))
        return -1;
    hdr = (const DCERPCHeader*)data;
    if (hdr->version != 5)
        return -1;
    if (hdr->minor_version > 1)
        return -1;
    if (hdr->type > 19)
        return -1;
    if (hdr->drep[0] & DCERPC_LE_FLAG)
    {
        len = hdr->frag_length;
    }
    else
    {
        len = ntohs(hdr->frag_length);
    }
    if (len < sizeof(DCERPCHeader))
        return -1;
    if (size < len)
        return -1;
    return (int)len;
}

class ServiceDCERPCData : public AppIdFlowData
{
public:
    ~ServiceDCERPCData() override = default;

    unsigned count = 0;
};

DceRpcServiceDetector::DceRpcServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "dcerpc";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_DCE_RPC, 0 }
    };

    service_ports =
    {
        { DCERPC_PORT, IpProtocol::TCP, false },
        { DCERPC_PORT, IpProtocol::UDP, false }
    };

    handler->register_detector(name, this, proto);
}


int DceRpcServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    if (args.asd.protocol == IpProtocol::UDP)
        return udp_validate(args);
    else
        return tcp_validate(args);
}

int DceRpcServiceDetector::tcp_validate(AppIdDiscoveryArgs& args)
{

    if (!args.size || args.dir != APP_ID_FROM_RESPONDER)
    {
        service_inprocess(args.asd, args.pkt, args.dir);
        return APPID_INPROCESS;
    }

    ServiceDCERPCData* dd = (ServiceDCERPCData*)data_get(args.asd);
    if (!dd)
    {
        dd = new ServiceDCERPCData;
        data_add(args.asd, dd);
    }

    int retval = APPID_INPROCESS;
    int length;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    while (size)
    {
        length = dcerpc_validate(data, size);
        if (length < 0)
            goto fail;
        dd->count++;
        if (dd->count >= DCERPC_THRESHOLD)
            retval = APPID_SUCCESS;
        data += length;
        size -= length;
    }
    if (retval == APPID_SUCCESS)
        return add_service(args.change_bits, args.asd, args.pkt, args.dir, APP_ID_DCE_RPC);

    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

int DceRpcServiceDetector::udp_validate(AppIdDiscoveryArgs& args)
{
    if (!args.size || args.dir != APP_ID_FROM_RESPONDER)
    {
        service_inprocess(args.asd, args.pkt, args.dir);
        return APPID_INPROCESS;
    }

    ServiceDCERPCData* dd = (ServiceDCERPCData*)data_get(args.asd);
    if (!dd)
    {
        dd = new ServiceDCERPCData;
        data_add(args.asd, dd);
    }

    int retval = APPID_NOMATCH;
    int length;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    while (size)
    {
        length = dcerpc_validate(data, size);
        if (length < 0)
            goto fail;
        dd->count++;
        if (dd->count >= DCERPC_THRESHOLD)
            retval = APPID_SUCCESS;
        data += length;
        size -= length;
    }
    if (retval == APPID_SUCCESS)
        return add_service(args.change_bits, args.asd, args.pkt, args.dir, APP_ID_DCE_RPC);

    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

