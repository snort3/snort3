//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// appid_doh_event_handler.h author Shibin K V <shikv@cisco.com>

#ifndef APPID_DNS_PAYLOAD_EVENT_HANDLER_H
#define APPID_DNS_PAYLOAD_EVENT_HANDLER_H

#include "appid_detector.h"
#include "appid_inspector.h"
#include "appid_module.h"

class AppIdDnsPayloadEventHandler : public snort::DataHandler
{
public:
    AppIdDnsPayloadEventHandler(AppIdInspector& inspector) :
        DataHandler(MOD_NAME)
    {
        order = 100; // to make sure appid receives events before DNS inspector
        AppIdDetectors *appid_udp_detectors = nullptr;
        AppIdDetectors *appid_tcp_detectors = nullptr;
        appid_udp_detectors = inspector.get_ctxt().get_odp_ctxt().get_service_disco_mgr().get_udp_detectors();
        appid_tcp_detectors = inspector.get_ctxt().get_odp_ctxt().get_service_disco_mgr().get_tcp_detectors();
        assert(appid_udp_detectors);
        if (!appid_udp_detectors)
            return;
        auto udp_detector = appid_udp_detectors->find("DNS-UDP");
        if (udp_detector != appid_udp_detectors->end())
            dns_udp_detector = udp_detector->second;
        auto tcp_detector = appid_tcp_detectors->find("DNS-TCP");
        if (tcp_detector != appid_tcp_detectors->end())
            dns_tcp_detector = tcp_detector->second;
    }

    void handle(snort::DataEvent& event, snort::Flow* flow) override;

private:
    AppIdDetector *dns_udp_detector = nullptr;
    AppIdDetector *dns_tcp_detector = nullptr;
};

#endif // APPID_DNS_PAYLOAD_EVENT_HANDLER_H

