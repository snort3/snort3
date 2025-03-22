//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// unixdomain_connector.h author Umang Sharma <umasharm@cisco.com>

#ifndef UNIXDOMAIN_CONNECTOR_H
#define UNIXDOMAIN_CONNECTOR_H

#include <atomic>
#include <thread>

#include "framework/connector.h"
#include "managers/connector_manager.h"
#include "helpers/ring.h"

#include "unixdomain_connector_config.h"

#define UNIXDOMAIN_FORMAT_VERSION (1)

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class __attribute__((__packed__)) UnixDomainConnectorMsgHdr
{
public:
    UnixDomainConnectorMsgHdr() : version(0), connector_msg_length(0)
    { }
    UnixDomainConnectorMsgHdr(uint32_t length)
    { version = UNIXDOMAIN_FORMAT_VERSION; connector_msg_length = length; }

    uint8_t version;    
    uint16_t connector_msg_length;
};

class UnixDomainConnector :  public snort::Connector 
{
public:
    UnixDomainConnector(const UnixDomainConnectorConfig& config, int sfd, size_t idx);
    ~UnixDomainConnector() override;

    bool transmit_message(const snort::ConnectorMsg&, const ID& = null) override;
    bool transmit_message(const snort::ConnectorMsg&&, const ID& = null) override;

    snort::ConnectorMsg receive_message(bool) override;
    void process_receive();

    int sock_fd;

private:
    typedef Ring<snort::ConnectorMsg*> ReceiveRing;

    void start_receive_thread();
    void stop_receive_thread();
    void receive_processing_thread();

    snort::ConnectorMsg* read_message();
    bool internal_transmit_message(const snort::ConnectorMsg& msg);

    std::atomic<bool> run_thread;
    std::thread* receive_thread;
    ReceiveRing* receive_ring;
    size_t instance_id;
    UnixDomainConnectorConfig cfg;
};

#endif // UNIXDOMAIN_CONNECTOR_H

