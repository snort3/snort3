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

// tcp_connector_config.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef TCP_CONNECTOR_CONFIG_H
#define TCP_CONNECTOR_CONFIG_H

#include <string>
#include <vector>

#include "framework/connector.h"

class TcpConnectorConfig : public snort::ConnectorConfig
{
public:
    enum Setup { CALL, ANSWER };

    TcpConnectorConfig()
    { direction = snort::Connector::CONN_DUPLEX; async_receive = true; }

    std::vector<std::string> ports;
    std::string address;
    Setup setup = {};
    bool async_receive;
};

#endif

