//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

// detector_sip.h author Sourcefire Inc.

#ifndef DETECTOR_SIP_H
#define DETECTOR_SIP_H

#include "client_plugins/client_detector.h"
#include "service_plugins/service_detector.h"
#include "framework/data_bus.h"
#include "pub_sub/sip_events.h"

#include "appid_module.h"

namespace snort
{
class Flow;
}

class AppIdInspector;
class SipEventHandler;

class SipUdpClientDetector : public ClientDetector
{
public:
    SipUdpClientDetector(ClientDiscovery*);
    ~SipUdpClientDetector() override = default;

    int validate(AppIdDiscoveryArgs&) override;
};

class SipTcpClientDetector : public ClientDetector
{
public:
    SipTcpClientDetector(ClientDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;
};

class SipServiceDetector : public ServiceDetector
{
public:
    SipServiceDetector(ServiceDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;
    void addFutureRtpFlows(SipEvent&, AppIdSession&);

private:
    void createRtpFlow(AppIdSession&, const snort::Packet*, const snort::SfIp* cliIp,
        uint16_t cliPort, const snort::SfIp* srvIp, uint16_t srvPort, IpProtocol);
};

class SipEventHandler : public snort::DataHandler
{
public:
    SipEventHandler(AppIdInspector& inspector) :
        DataHandler(MOD_NAME), inspector(inspector)
    { }

    static void set_client(SipUdpClientDetector* cd) { SipEventHandler::client = cd; }
    static void set_service(SipServiceDetector* sd) { SipEventHandler::service = sd; }

    void handle(snort::DataEvent&, snort::Flow*) override;

private:
    void client_handler(SipEvent&, AppIdSession&, AppidChangeBits&);
    void service_handler(SipEvent&, AppIdSession&, AppidChangeBits&);

    static SipUdpClientDetector* client;
    static SipServiceDetector* service;
    AppIdInspector& inspector;
};
#endif

