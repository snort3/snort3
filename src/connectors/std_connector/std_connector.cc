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
    PegCount tx_messages_stalled;
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

    { "buffer_size", Parameter::PT_INT, "0:max32", "0",
     "per-instance buffer size in bytes (0 no buffering, otherwise buffered and synchronized across threads)" },

    { "redirect", Parameter::PT_STRING, nullptr, nullptr,
     "output file name where printout is redirected" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo std_connector_pegs[] =
{
    { CountType::SUM, "messages_received", "total number of messages received" },
    { CountType::SUM, "messages_transmitted", "total number of messages transmitted" },
    { CountType::SUM, "messages_stalled", "total number of messages attempted for transmission but overflowed" },
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
        auto out_conn = std::make_unique<StdConnectorConfig>();
        out_conn->direction = Connector::CONN_TRANSMIT;
        out_conn->connector_name = "stdout";
        out_conn->buffer_size = 0;
        config_set.push_back(std::move(out_conn));

        auto in_conn = std::make_unique<StdConnectorConfig>();
        in_conn->direction = Connector::CONN_RECEIVE;
        in_conn->connector_name = "stdin";
        config_set.push_back(std::move(in_conn));

        auto io_conn = std::make_unique<StdConnectorConfig>();
        io_conn->direction = Connector::CONN_DUPLEX;
        io_conn->connector_name = "stdio";
        io_conn->buffer_size = 0;
        config_set.push_back(std::move(io_conn));
    }

    if ( !config )
        config = std::make_unique<StdConnectorConfig>();

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
    else if ( v.is("buffer_size") )
        config->buffer_size = v.get_uint32();
    else if ( v.is("redirect") )
        config->output = v.get_string();

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

static StdConnectorBuffer fail_safe_buffer(nullptr);
static Ring2 fail_safe_ring(0);

StdConnectorCommon::StdConnectorCommon(snort::ConnectorConfig::ConfigSet&& c_s)
    : ConnectorCommon(std::move(c_s))
{
    for (auto& config : config_set)
    {
        StdConnectorConfig& std_config = (StdConnectorConfig&)*config;

        if (std_config.buffer_size > 0)
            std_config.buffer = &buffers.emplace_back(std_config.output.c_str());
    }
}

StdConnector::StdConnector(const StdConnectorConfig& conf) :
    snort::Connector(conf),
    buffered(conf.buffer and conf.buffer_size != 0),
    text_log(TextLog_Init(conf.output.c_str(), false)),
    writer(buffered ? conf.buffer->acquire(conf.buffer_size) : fail_safe_ring.writer()),
    buffer(conf.buffer ? *conf.buffer : fail_safe_buffer)
{
    buffer.start();
}

StdConnector::~StdConnector()
{
    TextLog_Term(text_log);

    if (buffered)
        buffer.release(writer);
}

bool StdConnector::internal_transmit_message(const ConnectorMsg& msg)
{
    if ( !msg.get_data() or msg.get_length() == 0 )
        return false;

    if (!buffered)
        return TextLog_Print(text_log, "%.*s\n", msg.get_length(), msg.get_data())
            and ++std_connector_stats.messages_transmitted;

#ifdef REG_TEST
    const bool safe = false;
#else
    const bool safe = true;
#endif

    bool success = false;

    do
    {
        writer.retry();
        success = writer.write(msg.get_data(), msg.get_length());
    } while (!success and !safe);

    writer.push();

    if (success)
        ++std_connector_stats.messages_transmitted;
    else
        ++std_connector_stats.tx_messages_stalled;

    return success;
}

bool StdConnector::transmit_message(const ConnectorMsg& msg, const ID&)
{ return internal_transmit_message(msg); }

bool StdConnector::transmit_message(const ConnectorMsg&& msg, const ID&)
{ return internal_transmit_message(msg); }

bool StdConnector::flush()
{
    if (!buffered)
        return TextLog_Flush(text_log);

    writer.push();

    return true;
}

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
{
    const StdConnectorConfig& conf = (const StdConnectorConfig&)config;

    return new StdConnector(conf);
}

static void std_connector_tterm(Connector* connector)
{ delete connector; }

static ConnectorCommon* std_connector_ctor(Module* m)
{
    StdConnectorModule* mod = (StdConnectorModule*)m;
    ConnectorCommon* std_connector_common = new StdConnectorCommon(mod->get_and_clear_config());

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

