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

// service_dcerpc.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_dcerpc.h"

#include "dcerpc.h"

#define DCERPC_THRESHOLD    3
#define DCERPC_PORT 135

#define min(x,y) ((x)<(y) ? (x) : (y))

struct ServiceDCERPCData
{
    unsigned count;
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
    ServiceDCERPCData* dd;
    int retval = APPID_INPROCESS;
    int length;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;
    if (!size)
        goto inprocess;

    dd = (ServiceDCERPCData*)data_get(args.asd);
    if (!dd)
    {
        dd = (ServiceDCERPCData*)snort_calloc(sizeof(ServiceDCERPCData));
        data_add(args.asd, dd, &snort_free);
    }

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
        return add_service(args.asd, args.pkt, args.dir, APP_ID_DCE_RPC);

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

int DceRpcServiceDetector::udp_validate(AppIdDiscoveryArgs& args)
{
    ServiceDCERPCData* dd;
    int retval = APPID_NOMATCH;
    int length;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;
    if (!size)
        goto inprocess;

    dd = (ServiceDCERPCData*)data_get(args.asd);
    if (!dd)
    {
        dd = (ServiceDCERPCData*)snort_calloc(sizeof(ServiceDCERPCData));
        data_add(args.asd, dd, &snort_free);
    }

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
        return add_service(args.asd, args.pkt, args.dir, APP_ID_DCE_RPC);

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

