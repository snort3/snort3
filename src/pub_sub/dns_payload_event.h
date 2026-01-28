//--------------------------------------------------------------------------
// Copyright (C) 2022-2026 Cisco and/or its affiliates. All rights reserved.
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
// dns_payload_event.h author Shibin k v <shikv@cisco.com>
#ifndef DNS_PAYLOAD_EVENT_H
#define DNS_PAYLOAD_EVENT_H

#include "flow/flow_stash.h"
#include "framework/data_bus.h"

#define STASH_DNS_DATA "dns_data"

class DnsDataStash : public snort::StashGenericObject
{
public:
    DnsDataStash(const uint8_t* data, int32_t length)
        : dns_data(data), dns_data_length(length)
    { }
    DnsDataStash() = delete;
    const uint8_t* get_data(uint32_t& length) const
    {
        length = dns_data_length;
        return dns_data;
    }
    ~DnsDataStash() override = default;

private:
    const uint8_t* dns_data;
    int32_t dns_data_length;
};

class SO_PUBLIC DnsPayloadEvent : public snort::DataEvent
{
public:
    DnsPayloadEvent(const uint8_t* dns_data, const int32_t dns_data_length,
        const bool from_client, const bool is_udp, const bool last_piece)
        : dns_data(dns_data), dns_data_length(dns_data_length),
        from_client(from_client), is_udp(is_udp), last_piece(last_piece)
    { }
    DnsPayloadEvent() = delete;
    const uint8_t* get_payload(int32_t& length) const
    {
        length = dns_data_length;
        return dns_data;
    }
    bool is_from_client() const
    { return from_client; }
    bool is_last_piece() const
    { return last_piece; }
    bool is_dns_udp() const
    { return is_udp; }

private:
    const uint8_t* dns_data;
    const int32_t dns_data_length;
    const bool from_client;
    const bool is_udp;
    const bool last_piece;
};

#endif // DNS_PAYLOAD_EVENT_H
