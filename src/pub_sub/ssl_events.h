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
// ssl_events.h author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifndef SSL_EVENTS_H
#define SSL_EVENTS_H

// This event allows the SSL service inspector to publish extracted SSL handshake client hello data
// for use by data bus subscribers

#include "framework/data_bus.h"

struct SslEventIds
{
    enum : unsigned
    {
        CHELLO_SERVER_NAME,
        SERVER_COMMON_NAME,
        SSL_TLS_METADATA_EVENT,

        num_ids
    };
};

const snort::PubKey ssl_pub_key { "ssl", SslEventIds::num_ids };

class SslClientHelloEvent : public snort::DataEvent
{
public:
    SslClientHelloEvent(const std::string& ch_server_name, const snort::Packet* packet) :
        ch_server_name(ch_server_name), packet(packet)
        { }

    const snort::Packet* get_packet() const override
    { return packet; }

    const std::string& get_host_name() const
    { return ch_server_name; }

private:
    const std::string ch_server_name;
    const snort::Packet* packet;
};

class SslServerCommonNameEvent : public snort::DataEvent
{
public:
    SslServerCommonNameEvent(const std::string& server_common_name, const snort::Packet* packet) :
        server_common_name(server_common_name), packet(packet)
        { }

    const snort::Packet* get_packet() const override
    { return packet; }

    const std::string& get_common_name() const
    { return server_common_name; }

private:
    const std::string server_common_name;
    const snort::Packet* packet;
};

class SslTlsMetadataBaseEvent : public snort::DataEvent
{
public:
    SslTlsMetadataBaseEvent() = default;
    virtual ~SslTlsMetadataBaseEvent() override = default;

    /* Values expected to be in host machine byte order */
    virtual int32_t get_version() const = 0;
    virtual int32_t get_curve() const = 0;
    virtual int32_t get_cipher() const = 0;
    virtual const std::string& get_server_name_identifier() const = 0;
    virtual const std::string& get_subject() const = 0;
    virtual const std::string& get_issuer() const = 0;
    virtual const std::string& get_validation_status() const = 0;
    virtual const std::string& get_module_identifier() const = 0;
};

#endif
