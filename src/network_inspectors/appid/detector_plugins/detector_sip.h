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

// detector_sip.h author Sourcefire Inc.

#ifndef DETECTOR_SIP_H
#define DETECTOR_SIP_H

#include "client_plugins/client_detector.h"
#include "service_plugins/service_detector.h"
#include "framework/data_bus.h"
#include "pub_sub/sip_events.h"

namespace snort
{
class Flow;
}

struct SipUaUserData
{
    AppId ClientAppId;
    char* clientVersion;
};

struct DetectorAppSipPattern
{
    tMlpPattern pattern;
    SipUaUserData userData;
    DetectorAppSipPattern* next;
};

class SipEventHandler;

class SipUdpClientDetector : public ClientDetector
{
public:
    SipUdpClientDetector(ClientDiscovery*);
    ~SipUdpClientDetector() override;

    int validate(AppIdDiscoveryArgs&) override;

    void finalize_patterns() override;

    // FIXIT-L revisit init so it's not split between static methods and constructor
    static int sipUaPatternAdd(AppId, const char* clientVersion, const char* uaPattern);
    static int sipServerPatternAdd(AppId, const char* clientVersion, const char* uaPattern);

private:
    static const int PATTERN_PART_MAX = 10;
    tMlmpPattern patterns[PATTERN_PART_MAX];
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
        uint16_t cliPort, const snort::SfIp* srvIp, uint16_t srvPort, IpProtocol, int16_t app_id);
};

class SipEventHandler : public snort::DataHandler
{
public:

    static SipEventHandler* create()
    {
        return new SipEventHandler;
    }

    void set_client(SipUdpClientDetector* cd) { SipEventHandler::client = cd; }
    void set_service(SipServiceDetector* sd) { SipEventHandler::service = sd; }

    void subscribe()
    { snort::DataBus::subscribe(SIP_EVENT_TYPE_SIP_DIALOG_KEY, this); }

    void handle(snort::DataEvent&, snort::Flow*) override;

private:
    SipEventHandler() = default;
    void client_handler(SipEvent&, AppIdSession&);
    void service_handler(SipEvent&, AppIdSession&);

    static SipUdpClientDetector* client;
    static SipServiceDetector* service;
};
#endif

