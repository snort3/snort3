//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifndef SIDE_CHANNEL_H
#define SIDE_CHANNEL_H

#include <functional>

#include "framework/bits.h"
#include "framework/connector.h"

#define MAXIMUM_SC_MESSAGE_CONTENT 1024
#define DISPATCH_ALL_RECEIVE 0

class SideChannel;

typedef uint16_t SCPort;
typedef uint16_t SCSequence;

typedef std::vector<std::string> SCConnectors;

struct __attribute__((__packed__)) SCMsgHdr
{
    uint16_t port;
    uint16_t sequence;
    uint32_t time_u_seconds;
    uint64_t time_seconds;
};

struct SCMessage
{
    SideChannel* sc;
    snort::Connector* connector;
    snort::ConnectorMsgHandle* handle;
    SCMsgHdr* hdr;
    uint8_t* content;
    uint32_t content_length;
};

typedef std::function<void(SCMessage*)> SCProcessMsgFunc;

// SideChannel is instantiated for each defined SC use.
class SideChannel
{
public:
    SideChannel();

    void register_receive_handler(const SCProcessMsgFunc& handler);
    void unregister_receive_handler();

    bool process(int max_messages);
    SCMessage* alloc_transmit_message(uint32_t content_length);
    bool discard_message(SCMessage* msg);
    bool transmit_message(SCMessage* msg);
    void set_message_port(SCMessage* msg, SCPort port);
    void set_default_port(SCPort port);
    snort::Connector::Direction get_direction();

    snort::Connector* connector_receive;
    snort::Connector* connector_transmit;

private:
    SCSequence sequence;
    SCPort default_port;
    SCProcessMsgFunc receive_handler = nullptr;
};

// SideChannelManager is primary interface with Snort.
class SideChannelManager
{
public:
    // Instantiate new SideChannel configuration
    static void instantiate(const SCConnectors* connectors, const PortBitSet* ports);

    // Main thread, pre-config init
    static void pre_config_init();

    // Per packet-thread startup.  Create all configured SideChannelConnector's.
    static void thread_init();

    // Per packet thread shutdown.
    static void thread_term();

    // Overall shutdown.
    static void term();

    // if configured, returns the SideChannel object associated with the specified port number.
    // Else return nullptr if none is configured.
    static SideChannel* get_side_channel(SCPort);

private:
    SideChannelManager() = delete;
};
#endif

