//--------------------------------------------------------------------------
// Copyright (C) 2017-2019 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/data_bus.h"

#define APPID_EVENT_ANY_CHANGE "appid_event_any_change"

// Events are added as needed by subscribers
// Any change here should also change change_bits_to_string()
enum AppidChangeBit
{
    // id
    APPID_SERVICE_BIT = 0,
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
    APPID_XFF_BIT,

    // other
    APPID_VERSION_BIT,

    APPID_MAX_BIT
};

typedef std::bitset<APPID_MAX_BIT> AppidChangeBits;

inline void change_bits_to_string(AppidChangeBits& change_bits, std::string& str)
{
    size_t n = change_bits.count();

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
    if (change_bits.test(APPID_XFF_BIT))
        --n? str.append("xff, ") : str.append("xff");
    if (change_bits.test(APPID_VERSION_BIT))
        --n? str.append("client-version, ") : str.append("client-version");
    if (n != 0) // make sure all bits from AppidChangeBit enum get translated
        str.append("change_bits_to_string error!");
}

class AppidEvent : public snort::DataEvent
{
public:
    AppidEvent(const AppidChangeBits& ac) : ac_bits(ac) {}

    const AppidChangeBits& get_change_bitset()
    { return ac_bits; }

private:
    const AppidChangeBits& ac_bits;
};

#endif
