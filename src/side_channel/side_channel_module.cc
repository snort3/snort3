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

// side_channel_module.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "side_channel_module.h"

#include <cassert>

#include "log/messages.h"

#include "side_channel.h"

extern THREAD_LOCAL SimpleStats sc_stats;
extern THREAD_LOCAL ProfileStats sc_perf_stats;

//-------------------------------------------------------------------------
// side_channel module
//-------------------------------------------------------------------------

static const Parameter sc_connectors_params[] =
{
    { "connector", Parameter::PT_STRING, nullptr, nullptr,
      "connector handle" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter sc_params[] =
{
    { "ports", Parameter::PT_BIT_LIST, "65535", nullptr,
      "side channel message port list" },

    { "connectors", Parameter::PT_LIST, sc_connectors_params, nullptr,
      "set of connectors" },

    { "connector", Parameter::PT_STRING, nullptr, nullptr,
      "connector handle" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

// Validate and process the configuration.
// FOR NOW, only permit a single port per connector channel
static bool validate_config(SideChannelConfig* config)
{
    // Also need to have at least one connector
    if ( config->connectors.size() == 0 )
    {
        ParseWarning(WARN_CONF, "Illegal SideChannel configuration: must have connectors");
        return false;
    }

    // Also need to have port list
    if ( config->ports == nullptr )
    {
        ParseWarning(WARN_CONF, "Illegal SideChannel configuration: must have ports");
        return false;
    }

    // FOR NOW (simplicity) we will enforce ONE port per connector channel
    // FIXIT-L expand functionality as necessary
    if ( config->ports->count() > 1 )
    {
        ParseWarning(WARN_CONF, "Illegal SideChannel configuration: one port allowed");
        return false;
    }

    return true;
}

SideChannelModule::SideChannelModule() :
    Module(SIDECHANNEL_NAME, SIDECHANNEL_HELP, sc_params)
{
    DebugMessage(DEBUG_SIDE_CHANNEL,"SideChannelModule::SideChannelModule()\n");
}

SideChannelModule::~SideChannelModule()
{
    DebugMessage(DEBUG_SIDE_CHANNEL,"SideChannelModule::~SideChannelModule()\n");
}

ProfileStats* SideChannelModule::get_profile() const
{ return &sc_perf_stats; }

bool SideChannelModule::set(const char* fqn, Value& v, SnortConfig*)
{
#ifdef DEBUG_MSGS
    DebugFormat(DEBUG_SIDE_CHANNEL,"SideChannelModule::set(): %s %s\n", fqn, v.get_name());
#else
    UNUSED(fqn);
#endif

    assert(config);

    if ( v.is("connector") )
        config->connectors.push_back(std::move(v.get_string()));

    else if ( v.is("ports") )
    {
        if ( !config->ports )
            config->ports = new PortBitSet;
        v.get_bits(*(config->ports) );
    }
    else
        return false;

    return true;
}

bool SideChannelModule::begin(const char* fqn, int idx, SnortConfig*)
{
#ifdef DEBUG_MSGS
    DebugFormat(DEBUG_SIDE_CHANNEL,"SideChannelModule::begin(): %s %d\n", fqn, idx);
#else
    UNUSED(fqn);
    UNUSED(idx);
#endif
    if ( !config )
    {
        config = new SideChannelConfig;
    }

    return true;
}

bool SideChannelModule::end(const char* fqn, int idx, SnortConfig*)
{
#ifdef DEBUG_MSGS
    DebugFormat(DEBUG_SIDE_CHANNEL,"SideChannelModule::end(): %s %d\n", fqn, idx);
#else
    UNUSED(fqn);
#endif

    if ( (idx == 0) || (strcmp(fqn, "side_channel.connectors") == 0 ) )
        return true;

    if ( !validate_config(config) )
    {
        delete config;
        config = nullptr;
        return false;
    }

    // Instantiate the side channel.  The name links
    // to the side channel connector(s).
    SideChannelManager::instantiate(&config->connectors, config->ports);

    delete config->ports;
    delete config;
    config = nullptr;

    return true;
}

PegCount* SideChannelModule::get_counts() const
{ return (PegCount*)&sc_stats; }

