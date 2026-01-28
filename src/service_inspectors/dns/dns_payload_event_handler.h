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

// dns_payload_event_handler.h author Shibin K V <shikv@cisco.com>

#ifndef DNS_PAYLOAD_EVENT_HANDLER_H
#define DNS_PAYLOAD_EVENT_HANDLER_H

#include "framework/data_bus.h"

#include "dns.h"
#include "dns_module.h"

class DnsPayloadEventHandler : public snort::DataHandler
{
public:
    DnsPayloadEventHandler(snort::Inspector& inspector_) : 
        snort::DataHandler(DNS_NAME), inspector(inspector_)
    {
        order = 200;
    }
    void handle(snort::DataEvent& event, snort::Flow* flow) override;
private:
    snort::Inspector& inspector;
};

#endif // DNS_PAYLOAD_EVENT_HANDLER_H
