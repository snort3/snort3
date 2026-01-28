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
// quic_events.h author Brian Morris <bmorris2@cisco.com>

#ifndef QUIC_EVENTS_H
#define QUIC_EVENTS_H

#include <string>
#include "framework/data_bus.h"

namespace snort
{

enum QuicLoggingEventIds : unsigned
{
    QUIC_CLIENT_HELLO_EVENT = 0,
    QUIC_HANDSHAKE_COMPLETE_EVENT,
    QUIC_MAX_EVENT
};
const PubKey quic_logging_pub_key { "quic_logging", QuicLoggingEventIds::QUIC_MAX_EVENT };

class QuicClientHelloEvent : public snort::DataEvent
{
public:
    ~QuicClientHelloEvent() override = default;

    virtual const std::string& get_version() const = 0;
    virtual const std::string& get_client_initial_dcid() const = 0;
    virtual const std::string& get_client_scid() const = 0;
    virtual const std::string& get_server_name() const = 0;
    virtual const std::string& get_client_protocol() const = 0;
};

class QuicHandshakeCompleteEvent : public snort::DataEvent
{
public:
    ~QuicHandshakeCompleteEvent() override = default;

    virtual const std::string& get_server_scid() const = 0;
    virtual const std::string& get_history() const = 0;
};

}
#endif
