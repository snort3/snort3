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

// tcp_connector_module.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_connector_module.h"

using namespace snort;

static const Parameter tcp_connector_params[] =
{
    { "connector", Parameter::PT_STRING, nullptr, nullptr,
      "connector name" },

    { "address", Parameter::PT_STRING, nullptr, nullptr,
      "address" },

    { "base_port", Parameter::PT_PORT, nullptr, nullptr,
      "base port number" },

    { "setup", Parameter::PT_ENUM, "call | answer", nullptr,
      "stream establishment" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo tcp_connector_pegs[] =
{
    { CountType::SUM, "messages", "total messages" },
    { CountType::END, nullptr, nullptr }
};

extern THREAD_LOCAL SimpleStats tcp_connector_stats;
extern THREAD_LOCAL ProfileStats tcp_connector_perfstats;

//-------------------------------------------------------------------------
// tcp_connector module
//-------------------------------------------------------------------------

TcpConnectorModule::TcpConnectorModule() :
    Module(TCP_CONNECTOR_NAME, TCP_CONNECTOR_HELP, tcp_connector_params)
{
    config = nullptr;
    config_set = new TcpConnectorConfig::TcpConnectorConfigSet;
}

TcpConnectorModule::~TcpConnectorModule()
{
    if ( config )
        delete config;
    if ( config_set )
        delete config_set;
}

ProfileStats* TcpConnectorModule::get_profile() const
{ return &tcp_connector_perfstats; }

bool TcpConnectorModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("connector") )
        config->connector_name = v.get_string();

    else if ( v.is("address") )
        config->address = v.get_string();

    else if ( v.is("base_port") )
        config->base_port = v.get_long();

    else if ( v.is("setup") )
        switch ( v.get_long() )
        {
        case 0:
        {
            config->setup = TcpConnectorConfig::CALL;
            break;
        }
        case 1:
        {
            config->setup = TcpConnectorConfig::ANSWER;
            break;
        }
        default:
            return false;
        }

    else
        return false;

    return true;
}

// clear my working config and hand-over the compiled list to the caller
TcpConnectorConfig::TcpConnectorConfigSet* TcpConnectorModule::get_and_clear_config()
{
    TcpConnectorConfig::TcpConnectorConfigSet* temp_config = config_set;
    config = nullptr;
    config_set = nullptr;
    return temp_config;
}

bool TcpConnectorModule::begin(const char*, int, SnortConfig*)
{
    if ( !config )
    {
        config = new TcpConnectorConfig;
    }
    return true;
}

bool TcpConnectorModule::end(const char*, int idx, SnortConfig*)
{
    if (idx != 0)
    {
        config_set->push_back(config);
        config = nullptr;
    }

    return true;
}

const PegInfo* TcpConnectorModule::get_pegs() const
{ return tcp_connector_pegs; }

PegCount* TcpConnectorModule::get_counts() const
{ return (PegCount*)&tcp_connector_stats; }

