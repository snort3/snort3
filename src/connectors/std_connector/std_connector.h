//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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

// std_connector.h author Vitalii Horbatov <vhorbato@cisco.com>

#ifndef STD_CONNECTOR_H
#define STD_CONNECTOR_H

#include "framework/connector.h"
#include "framework/module.h"

#define S_NAME "std_connector"
#define S_HELP "implement the stdout/stdin based connector"

struct TextLog;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

class StdConnectorModule : public snort::Module
{
public:
    StdConnectorModule();

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    snort::ConnectorConfig::ConfigSet get_and_clear_config();

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return GLOBAL; }

private:
    snort::ConnectorConfig::ConfigSet config_set;
    std::unique_ptr<snort::ConnectorConfig> config;
};

//-------------------------------------------------------------------------
// connector stuff
//-------------------------------------------------------------------------

class StdConnector : public snort::Connector
{
public:
    StdConnector(const snort::ConnectorConfig& conf);
    ~StdConnector() override;

    bool transmit_message(const snort::ConnectorMsg&, const ID& = null) override;
    bool transmit_message(const snort::ConnectorMsg&&, const ID& = null) override;
    bool flush() override;

    snort::ConnectorMsg receive_message(bool) override;

private:
    bool internal_transmit_message(const snort::ConnectorMsg&);

    TextLog* extr_std_log;
};

#endif
