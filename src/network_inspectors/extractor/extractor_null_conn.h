//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// extractor_null_conn.h author Vitalii Horbatov <vhorbato@cisco.com>

#ifndef EXTRACTOR_NULL_CONN_H
#define EXTRACTOR_NULL_CONN_H

#include "framework/connector.h"

class ExtractorNullConnector : public snort::Connector
{
public:
    ExtractorNullConnector() : snort::Connector(conf)
    {
        conf.connector_name = "null";
        conf.direction = snort::Connector::CONN_DUPLEX;
    }

    bool transmit_message(const snort::ConnectorMsg&, const ID& = null) override
    { return true; }

    bool transmit_message(const snort::ConnectorMsg&&, const ID& = null) override
    { return true; }

    snort::ConnectorMsg receive_message(bool) override
    { return snort::ConnectorMsg(); }

private:
    snort::ConnectorConfig conf;
};

#endif
