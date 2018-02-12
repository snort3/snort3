//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// service_regtest.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_regtest.h"

#include "app_info_table.h"

#ifdef REG_TEST

#define REGTEST_BANNER "REGTEST PORT MATCH "
#define REGTEST1_BANNER "REGTEST1 PATTERN MATCH "
#define REGTEST2_BANNER "REGTEST2 BRUTE FORCE "

RegTestServiceDetector::RegTestServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "regtest";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_REGTEST, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { 1066, IpProtocol::TCP, false },
    };

    handler->register_detector(name, this, proto);
}


int RegTestServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    unsigned v_off = strlen(REGTEST_BANNER);
    char version[4];
    char* v;

    const unsigned char* p;

    if (!args.size || (args.dir != APP_ID_FROM_RESPONDER))
        goto inprocess;

    if (strncmp(REGTEST_BANNER, (const char*)args.data, v_off))
        goto fail;

    if (!isdigit(args.data[v_off]) || !isdigit(args.data[v_off + 1]) || !isdigit(args.data[v_off +
        2]))
        goto fail;

    v = version;
    p = &args.data[v_off];
    for (unsigned i = 0; i < 3; i++)
    {
        *v = *p;
        v++;
        p++;
    }
    *v = 0;
    return add_service(args.asd, args.pkt, args.dir, APP_ID_REGTEST, nullptr, version, nullptr);

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

RegTestServiceDetector1::RegTestServiceDetector1(ServiceDiscovery* sd)
{
    handler = sd;
    name = "regtest1";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)REGTEST1_BANNER, sizeof(REGTEST1_BANNER) - 1, 0, 0, 0 },
    };

    appid_registry =
    {
        { APP_ID_REGTEST1, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    handler->register_detector(name, this, proto);
}


int RegTestServiceDetector1::validate(AppIdDiscoveryArgs& args)
{
    char version[4];
    char* v;
    const unsigned char* p;
    unsigned v_off = strlen(REGTEST1_BANNER);

    if (!args.size || (args.dir != APP_ID_FROM_RESPONDER))
        goto inprocess;

    if (strncmp(REGTEST1_BANNER, (const char*)args.data, v_off))
        goto fail;

    if (!isdigit(args.data[v_off]) || !isdigit(args.data[v_off + 1]) || !isdigit(args.data[v_off +
        2]))
        goto fail;

    v = version;
    p = &args.data[v_off];
    for (unsigned i = 0; i < 3; i++)
    {
        *v = *p;
        v++;
        p++;
    }
    *v = 0;
    return add_service(args.asd, args.pkt, args.dir, APP_ID_REGTEST1, nullptr, version, nullptr);

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

RegTestServiceDetector2::RegTestServiceDetector2(ServiceDiscovery* sd)
{
    handler = sd;
    name = "regtest2";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_REGTEST2, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    handler->register_detector(name, this, proto);
}


int RegTestServiceDetector2::validate(AppIdDiscoveryArgs& args)
{
    char version[4];
    char* v;
    const unsigned char* p;
    unsigned v_off = strlen(REGTEST2_BANNER);

    if (!args.size || (args.dir != APP_ID_FROM_RESPONDER))
        goto inprocess;

    if (strncmp(REGTEST2_BANNER, (const char*)args.data, v_off))
        goto fail;

    if (!isdigit(args.data[v_off]) || !isdigit(args.data[v_off + 1]) || !isdigit(args.data[v_off +
        2]))
        goto fail;

    v = version;
    p = &args.data[v_off];
    for (unsigned i = 0; i < 3; i++)
    {
        *v = *p;
        v++;
        p++;
    }
    *v = 0;
    return add_service(args.asd, args.pkt, args.dir, APP_ID_REGTEST2, nullptr, version, nullptr);

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

#endif

