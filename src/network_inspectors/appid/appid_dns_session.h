//--------------------------------------------------------------------------
// Copyright (C) 2017-2026 Cisco and/or its affiliates. All rights reserved.
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

// appid_dns_session.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Sept 25, 2017

#ifndef APPID_DNS_SESSION_H
#define APPID_DNS_SESSION_H

#include <string>
#include "utils/util.h"
#include "pub_sub/appid_events.h"

#define DNS_GOT_QUERY    0x01
#define DNS_GOT_RESPONSE 0x02

class AppIdDnsSession
{
public:
    AppIdDnsSession() { }
    ~AppIdDnsSession()
    {
        if (host)
        {
            snort_free(host);
            host = nullptr;
        }
    }

    void reset()
    {
        if (host)
        {
            snort_free(host);
            host = nullptr;
        }
        state = 0;
        response_type = 0;
        id = 0;
        host_offset = 0;
        record_type = 0;
        ttl = 0;
        options_offset = 0;
        doh = false;
    }

    uint8_t get_state() const
    { return state; }

    void set_state(uint8_t state)
    { this->state = state; }

    uint16_t get_id() const
    { return id; }

    void set_id(uint16_t id)
    { this->id = id; }

    uint16_t get_record_type() const
    { return record_type; }

    void set_record_type(uint16_t recordType)
    { record_type = recordType; }

    uint32_t get_ttl() const
    { return ttl; }

    void set_ttl(uint32_t ttl)
    { this->ttl = ttl; }

    uint8_t get_response_type() const
    { return response_type; }

    void set_response_type(uint8_t responseType)
    { response_type = responseType; }

    const char* get_host() const
    { return host; }

    void set_host(const char* host, AppidChangeBits& change_bits, bool request)
    {
        if (this->host)
        {
            snort_free(this->host);
        }
        this->host = snort::snort_strdup(host);
        if (request)
        {
            change_bits.reset(APPID_DNS_RESPONSE_HOST_BIT);
            change_bits.set(APPID_DNS_REQUEST_HOST_BIT);
        }
        else
        {
            change_bits.reset(APPID_DNS_REQUEST_HOST_BIT);
            change_bits.set(APPID_DNS_RESPONSE_HOST_BIT);
        }
    }

    uint32_t get_host_len() const
    { return host ? strlen(host) : 0; }

    uint16_t get_host_offset() const
    { return host_offset; }

    void set_host_offset(uint16_t hostOffset)
    { host_offset = hostOffset; }

    uint16_t get_options_offset() const
    { return options_offset; }

    void set_options_offset(uint16_t optionsOffset)
    { options_offset = optionsOffset; }

    void set_doh(bool Doh)
    { doh = Doh; }

    bool is_doh() const
    { return doh; }

protected:
    uint8_t state = 0;
    uint8_t response_type = 0;
    uint16_t id = 0;
    uint16_t record_type = 0;
    uint32_t ttl = 0;
    char* host = nullptr;
    uint16_t host_offset = 0;
    uint16_t options_offset = 0;
    bool doh = false;
};
#endif
