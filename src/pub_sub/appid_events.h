//--------------------------------------------------------------------------
// Copyright (C) 2017-2025 Cisco and/or its affiliates. All rights reserved.
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
// appid_events.h author Masud Hasan <mashasan@cisco.com>

#ifndef APPID_EVENTS_H
#define APPID_EVENTS_H

// This event conveys data published by the appid module to be consumed by data bus subscribers

#include <bitset>

#include "pub_sub/appid_event_ids.h"

namespace snort
{
    class AppIdSessionApi;
}

// Events are added as needed by subscribers
// Any change here should also change change_bits_to_string()
enum AppidChangeBit
{
    APPID_CREATED_BIT = 0,
    APPID_RESET_BIT,

    // id
    APPID_SERVICE_BIT,
    APPID_CLIENT_BIT,
    APPID_PAYLOAD_BIT,
    APPID_MISC_BIT,
    APPID_REFERRED_BIT,

    // http
    APPID_HOST_BIT,
    APPID_TLSHOST_BIT,
    APPID_URL_BIT,
    APPID_USERAGENT_BIT,
    APPID_RESPONSE_BIT,
    APPID_REFERER_BIT,

    // dns
    APPID_DNS_REQUEST_HOST_BIT,
    APPID_DNS_RESPONSE_HOST_BIT,

    // other
    APPID_SERVICE_INFO_BIT,
    APPID_CLIENT_INFO_BIT,
    APPID_USER_INFO_BIT,
    APPID_NETBIOS_NAME_BIT,
    APPID_NETBIOS_DOMAIN_BIT,
    APPID_DISCOVERY_FINISHED_BIT,
    APPID_TLS_VERSION_BIT,
    APPID_PROTOCOL_ID_BIT,

    APPID_MAX_BIT
};

typedef std::bitset<APPID_MAX_BIT> AppidChangeBits;

inline void change_bits_to_string(const AppidChangeBits& change_bits, std::string& str)
{
    size_t n = change_bits.count();

    if (change_bits.test(APPID_CREATED_BIT))
        --n? str.append("created, ") : str.append("created");
    if (change_bits.test(APPID_RESET_BIT))
        --n? str.append("reset, ") : str.append("reset");
    if (change_bits.test(APPID_SERVICE_BIT))
        --n? str.append("service, ") : str.append("service");
    if (change_bits.test(APPID_CLIENT_BIT))
        --n? str.append("client, ") : str.append("client");
    if (change_bits.test(APPID_PAYLOAD_BIT))
        --n? str.append("payload, ") : str.append("payload");
    if (change_bits.test(APPID_MISC_BIT))
        --n? str.append("misc, ") : str.append("misc");
    if (change_bits.test(APPID_REFERRED_BIT))
        --n? str.append("referred, ") : str.append("referred");
    if (change_bits.test(APPID_HOST_BIT))
        --n? str.append("host, ") : str.append("host");
    if (change_bits.test(APPID_TLSHOST_BIT))
        --n? str.append("tls-host, ") : str.append("tls-host");
    if (change_bits.test(APPID_URL_BIT))
        --n? str.append("url, ") : str.append("url");
    if (change_bits.test(APPID_USERAGENT_BIT))
        --n? str.append("user-agent, ") : str.append("user-agent");
    if (change_bits.test(APPID_RESPONSE_BIT))
        --n? str.append("response, ") : str.append("response");
    if (change_bits.test(APPID_REFERER_BIT))
        --n? str.append("referrer, ") : str.append("referrer");
    if (change_bits.test(APPID_DNS_REQUEST_HOST_BIT))
        --n? str.append("dns-host, ") : str.append("dns-host");
    if (change_bits.test(APPID_DNS_RESPONSE_HOST_BIT))
        --n? str.append("dns-response-host, ") : str.append("dns-response-host");
    if (change_bits.test(APPID_SERVICE_INFO_BIT))
        --n? str.append("service-info, ") : str.append("service-info");
    if (change_bits.test(APPID_CLIENT_INFO_BIT))
        --n? str.append("client-info, ") : str.append("client-info");
    if (change_bits.test(APPID_USER_INFO_BIT))
        --n? str.append("user-info, ") : str.append("user-info");
    if (change_bits.test(APPID_NETBIOS_NAME_BIT))
        --n? str.append("netbios-name, ") : str.append("netbios-name");
    if (change_bits.test(APPID_NETBIOS_DOMAIN_BIT))
        --n? str.append("netbios-domain, ") : str.append("netbios-domain");
    if (change_bits.test(APPID_DISCOVERY_FINISHED_BIT))
        --n? str.append("finished, ") : str.append("finished");
    if (change_bits.test(APPID_TLS_VERSION_BIT))
        --n? str.append("tls-version, ") : str.append("tls-version");
    if (change_bits.test(APPID_PROTOCOL_ID_BIT))
        --n? str.append("protocol-id, ") : str.append("protocol-id");
    if (n != 0) // make sure all bits from AppidChangeBit enum get translated
        str.append("change_bits_to_string error!");
}

class AppidEvent : public snort::DataEvent
{
public:
    AppidEvent(const AppidChangeBits& ac, bool is_httpx, uint32_t httpx_stream_index,
        const snort::AppIdSessionApi& api, const snort::Packet& p) :
        ac_bits(ac), is_httpx(is_httpx), httpx_stream_index(httpx_stream_index), api(api), p(p) {}

    const AppidChangeBits& get_change_bitset() const
    { return ac_bits; }

    bool get_is_httpx() const
    { return is_httpx; }

    uint32_t get_httpx_stream_index() const
    { return httpx_stream_index; }

    const snort::AppIdSessionApi& get_appid_session_api() const
    { return api; }

    const snort::Packet* get_packet() const override
    { return &p; }

private:
    const AppidChangeBits& ac_bits;
    bool is_httpx;
    uint32_t httpx_stream_index;
    const snort::AppIdSessionApi& api;
    const snort::Packet& p;
};

#endif
