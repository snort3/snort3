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

// file_connector_module.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_connector_module.h"

#include "main/snort_debug.h"

static const Parameter file_connector_params[] =
{
    { "connector", Parameter::PT_STRING, nullptr, nullptr,
      "connector name" },

    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "channel name" },

    { "format", Parameter::PT_ENUM, "binary | text", nullptr,
      "file format" },

    { "direction", Parameter::PT_ENUM, "receive | transmit | duplex", nullptr,
      "usage" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo file_connector_pegs[] =
{
    { "messages", "total messages" },
    { nullptr, nullptr }
};

extern THREAD_LOCAL SimpleStats file_connector_stats;
extern THREAD_LOCAL ProfileStats file_connector_perfstats;

//-------------------------------------------------------------------------
// file_connector module
//-------------------------------------------------------------------------

FileConnectorModule::FileConnectorModule() :
    Module(FILE_CONNECTOR_NAME, FILE_CONNECTOR_HELP, file_connector_params)
{
    DebugMessage(DEBUG_CONNECTORS,"FileConnectorModule::FileConnectorModule()\n");
    config = nullptr;
    config_set = new FileConnectorConfig::FileConnectorConfigSet;
}

FileConnectorModule::~FileConnectorModule()
{
    DebugMessage(DEBUG_CONNECTORS,"FileConnectorModule::~FileConnectorModule()\n");
    if ( config )
        delete config;
    if ( config_set )
        delete config_set;
}

ProfileStats* FileConnectorModule::get_profile() const
{ return &file_connector_perfstats; }

bool FileConnectorModule::set(const char* fqn, Value& v, SnortConfig*)
{
#ifdef DEBUG_MSGS
    DebugFormat(DEBUG_CONNECTORS,"FileConnectorModule::set(): %s, %s\n", fqn, v.get_name());
#else
    UNUSED(fqn);
#endif

    if ( v.is("connector") )
        config->connector_name = v.get_string();

    else if ( v.is("name") )
        config->name = v.get_string();

    else if ( v.is("format") )
        config->text_format = ( v.get_long() == 1 );

    else if ( v.is("direction") )
        switch ( v.get_long() )
        {
        case 0:
        {
            config->direction = Connector::CONN_RECEIVE;
            break;
        }
        case 1:
        {
            config->direction = Connector::CONN_TRANSMIT;
            break;
        }
        case 2:
        {
            config->direction = Connector::CONN_DUPLEX;
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
FileConnectorConfig::FileConnectorConfigSet* FileConnectorModule::get_and_clear_config()
{
    DebugMessage(DEBUG_CONNECTORS,"FileConnectorModule::get_and_clear_config()\n");
    FileConnectorConfig::FileConnectorConfigSet* temp_config = config_set;
    config = nullptr;
    config_set = nullptr;
    return temp_config;
}

bool FileConnectorModule::begin(const char* fqn, int idx, SnortConfig*)
{
#ifdef DEBUG_MSGS
    DebugFormat(DEBUG_CONNECTORS,"FileConnectorModule::begin(): %s, %d\n", fqn, idx);
#else
    UNUSED(fqn);
    UNUSED(idx);
#endif
    if ( !config )
    {
        config = new FileConnectorConfig;
    }
    return true;
}

bool FileConnectorModule::end(const char* fqn, int idx, SnortConfig*)
{
#ifdef DEBUG_MSGS
    DebugFormat(DEBUG_CONNECTORS,"FileConnectorModule::end(): %s, %d\n", fqn, idx);
#else
    UNUSED(fqn);
#endif

    if (idx != 0)
    {
        config_set->push_back(config);
        config = nullptr;
    }

    return true;
}

const PegInfo* FileConnectorModule::get_pegs() const
{ return file_connector_pegs; }

PegCount* FileConnectorModule::get_counts() const
{ return (PegCount*)&file_connector_stats; }

