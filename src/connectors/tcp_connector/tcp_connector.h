//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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

// tcp_connector.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef TCP_CONNECTOR_H
#define TCP_CONNECTOR_H

#include <thread>

#include "framework/connector.h"
#include "helpers/ring.h"

#include "tcp_connector_config.h"

#define TCP_FORMAT_VERSION (1)

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class __attribute__((__packed__)) TcpConnectorMsgHdr
{
public:
    TcpConnectorMsgHdr() {}
    TcpConnectorMsgHdr(uint32_t length)
    { version = TCP_FORMAT_VERSION; connector_msg_length = length; }

    uint8_t version;
    uint16_t connector_msg_length;
};

class TcpConnectorMsgHandle : public ConnectorMsgHandle
{
public:
    TcpConnectorMsgHandle(const uint32_t length);
    ~TcpConnectorMsgHandle();
    ConnectorMsg connector_msg;
};

class TcpConnectorCommon : public ConnectorCommon
{
public:
    TcpConnectorCommon(TcpConnectorConfig::TcpConnectorConfigSet*);
    ~TcpConnectorCommon();
};

class TcpConnector : public Connector
{
public:
    typedef Ring<TcpConnectorMsgHandle*> ReceiveRing;

    TcpConnector(TcpConnectorConfig*, int sock_fd);
    ~TcpConnector();
    ConnectorMsgHandle* alloc_message(const uint32_t, const uint8_t**);
    void discard_message(ConnectorMsgHandle*);
    bool transmit_message(ConnectorMsgHandle*);
    ConnectorMsgHandle* receive_message(bool);

    ConnectorMsg* get_connector_msg(ConnectorMsgHandle* handle)
    { return( &((TcpConnectorMsgHandle*)handle)->connector_msg ); }
    Direction get_connector_direction()
    { return Connector::CONN_DUPLEX; }
    void process_receive();

    int sock_fd;

private:
    bool run_thread;
    std::thread* receive_thread;
    void start_receive_thread();
    void stop_receive_thread();
    void receive_processing_thread();
    ReceiveRing* receive_ring;
};

#endif

