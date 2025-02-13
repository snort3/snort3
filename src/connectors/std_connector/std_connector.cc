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

// std_connector.cc author Vitalii Horbatov <vhorbato@cisco.com>
// based on work by Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "std_connector.h"

#include <iostream>
#include <string>

#include "profiler/profiler_defs.h"
#include "log/text_log.h"

using namespace snort;

/* Globals ****************************************************************/

struct StdConnectorStats
{
    PegCount messages_received;
    PegCount messages_transmitted;
};

THREAD_LOCAL StdConnectorStats std_connector_stats;
THREAD_LOCAL ProfileStats std_connector_perfstats;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter std_connector_params[] =
{
    { "connector", Parameter::PT_STRING, nullptr, nullptr,
      "connector name" },

    { "direction", Parameter::PT_ENUM, "receive | transmit | duplex", nullptr,
      "usage" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo std_connector_pegs[] =
{
    { CountType::SUM, "messages_received", "total number of messages received" },
    { CountType::SUM, "messages_transmitted", "total number of messages transmitted" },
    { CountType::END, nullptr, nullptr }
};

StdConnectorModule::StdConnectorModule() :
    Module(S_NAME, S_HELP, std_connector_params, true)
{ }

ProfileStats* StdConnectorModule::get_profile() const
{ return &std_connector_perfstats; }

bool StdConnectorModule::begin(const char* mod, int idx, SnortConfig*)
{
    if (idx == 0 and strcmp(mod, "std_connector") == 0)
    {
        auto out_conn = std::make_unique<snort::ConnectorConfig>();
        out_conn->direction = Connector::CONN_TRANSMIT;
        out_conn->connector_name = "stdout";
        config_set.push_back(std::move(out_conn));

        auto in_conn = std::make_unique<snort::ConnectorConfig>();
        in_conn->direction = Connector::CONN_RECEIVE;
        in_conn->connector_name = "stdin";
        config_set.push_back(std::move(in_conn));

        auto io_conn = std::make_unique<snort::ConnectorConfig>();
        io_conn->direction = Connector::CONN_DUPLEX;
        io_conn->connector_name = "stdio";
        config_set.push_back(std::move(io_conn));
    }

    if ( !config )
        config = std::make_unique<snort::ConnectorConfig>();

    return true;
}

bool StdConnectorModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("connector") )
        config->connector_name = v.get_string();

    else if ( v.is("direction") )
    {
        switch ( v.get_uint8() )
        {
        case 0:
            config->direction = Connector::CONN_RECEIVE;
            break;
        case 1:
            config->direction = Connector::CONN_TRANSMIT;
            break;
        case 2:
            config->direction = Connector::CONN_DUPLEX;
            break;
        default:
            return false;
        }
    }
    return true;
}

bool StdConnectorModule::end(const char*, int idx, SnortConfig*)
{
    if (idx != 0)
        config_set.push_back(std::move(config));

    return true;
}

ConnectorConfig::ConfigSet StdConnectorModule::get_and_clear_config()
{ return std::move(config_set); }

const PegInfo* StdConnectorModule::get_pegs() const
{ return std_connector_pegs; }

PegCount* StdConnectorModule::get_counts() const
{ return (PegCount*)&std_connector_stats; }

//-------------------------------------------------------------------------
// connector stuff
//-------------------------------------------------------------------------

StdConnector::StdConnector(const snort::ConnectorConfig& conf) :
    snort::Connector(conf), extr_std_log(TextLog_Init("stdout"))
{ }

StdConnector::~StdConnector()
{ TextLog_Term(extr_std_log); }

bool StdConnector::internal_transmit_message(const ConnectorMsg& msg)
{
    if ( !msg.get_data() or msg.get_length() == 0 )
        return false;

    return TextLog_Print(extr_std_log, "%.*s\n", msg.get_length(), msg.get_data()) &&
        ++(std_connector_stats.messages_transmitted);
}

bool StdConnector::transmit_message(const ConnectorMsg& msg, const ID&)
{ return internal_transmit_message(msg); }

bool StdConnector::transmit_message(const ConnectorMsg&& msg, const ID&)
{ return internal_transmit_message(msg); }

bool StdConnector::flush()
{ return TextLog_Flush(extr_std_log); }

ConnectorMsg StdConnector::receive_message(bool)
{
    std::string data;
    std::getline(std::cin, data);

    uint8_t* data_buf = new uint8_t[data.size()];
    memcpy(data_buf, data.c_str(), data.size());

    std_connector_stats.messages_received++;

    return ConnectorMsg(data_buf, data.size(), true);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new StdConnectorModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Connector* std_connector_tinit(const ConnectorConfig& config)
{ return new StdConnector(config); }

static void std_connector_tterm(Connector* connector)
{ delete connector; }

static ConnectorCommon* std_connector_ctor(Module* m)
{
    StdConnectorModule* mod = (StdConnectorModule*)m;
    ConnectorCommon* std_connector_common = new ConnectorCommon(mod->get_and_clear_config());
    return std_connector_common;
}

static void std_connector_dtor(ConnectorCommon* cc)
{ delete cc; }

const ConnectorApi std_connector_api =
{
    {
        PT_CONNECTOR,
        sizeof(ConnectorApi),
        CONNECTOR_API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        S_HELP,
        mod_ctor,
        mod_dtor
    },
    0,
    nullptr,
    nullptr,
    std_connector_tinit,
    std_connector_tterm,
    std_connector_ctor,
    std_connector_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* std_connector[] =
#endif
{
    &std_connector_api.base,
    nullptr
};

