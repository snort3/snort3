//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// ha_module.cc author Ed Borgoyn <eborgoyn@cisco.com>

#include "ha_module.h"

#include "ha.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "main/thread.h"

static const PegInfo ha_pegs[] =
{
    { nullptr, nullptr }
};

extern THREAD_LOCAL SimpleStats ha_stats;
extern THREAD_LOCAL ProfileStats ha_perf_stats;

//-------------------------------------------------------------------------
// ha module
//-------------------------------------------------------------------------

static const Parameter ha_params[] =
{
    { "enable", Parameter::PT_BOOL, nullptr, "false",
      "enable high availability" },

    { "daq_channel", Parameter::PT_BOOL, nullptr, "false",
      "enable use of daq data plane channel" },

    { "ports", Parameter::PT_BIT_LIST, "65535", nullptr,
      "side channel message port list" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

HighAvailabilityModule::HighAvailabilityModule() :
    Module(HA_NAME, HA_HELP, ha_params)
{
    DebugMessage(DEBUG_HA,"HighAvailabilityModule::HighAvailabilityModule()\n");
    config.enabled = false;
    config.daq_channel = false;
    config.ports = nullptr;
}

HighAvailabilityModule::~HighAvailabilityModule()
{
    DebugMessage(DEBUG_HA,"HighAvailabilityModule::~HighAvailabilityModule()\n");
    delete config.ports;
}

ProfileStats* HighAvailabilityModule::get_profile() const
{ return &ha_perf_stats; }

bool HighAvailabilityModule::set(const char* fqn, Value& v, SnortConfig*)
{
#ifdef DEBUG_MSGS
    DebugFormat(DEBUG_HA,"HighAvailabilityModule::set(): %s %s\n", fqn, v.get_name());
#else
    UNUSED(fqn);
#endif

    if ( v.is("enable") )
        config.enabled = v.get_bool();

    else if ( v.is("daq_channel") )
        config.daq_channel = v.get_bool();

    else if ( v.is("ports") )
    {
        if ( !config.ports )
            config.ports = new PortBitSet;
        v.get_bits(*(config.ports) );
    }

    else
        return false;

    return true;
}

bool HighAvailabilityModule::begin(const char* fqn, int idx, SnortConfig*)
{
#ifdef DEBUG_MSGS
    DebugFormat(DEBUG_HA,"HighAvailabilityModule::begin(): %s %d\n", fqn, idx);
#else
    UNUSED(fqn);
    UNUSED(idx);
#endif

    return true;
}

bool HighAvailabilityModule::end(const char* fqn, int idx, SnortConfig*)
{
#ifdef DEBUG_MSGS
    DebugFormat(DEBUG_HA,"HighAvailabilityModule::end(): %s %d\n", fqn, idx);
#else
    UNUSED(fqn);
#endif

    if ( config.enabled && !HighAvailabilityManager::instantiate(config.ports,config.daq_channel) )
    {
        ParseWarning(WARN_CONF, "Illegal HighAvailability configuration");
        return false;
    }

    return true;
}

const PegInfo* HighAvailabilityModule::get_pegs() const
{ return ha_pegs; }

PegCount* HighAvailabilityModule::get_counts() const
{ return (PegCount*)&ha_stats; }

