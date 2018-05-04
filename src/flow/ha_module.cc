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

// ha_module.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ha_module.h"

#include <cmath>

#include "log/messages.h"

#include "ha.h"

using namespace snort;

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

    { "min_age", Parameter::PT_REAL, "0.0:100.0", "1.0",
      "minimum session life before HA updates" },

    { "min_sync", Parameter::PT_REAL, "0.0:100.0", "1.0",
      "minimum interval between HA updates" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static void convert_real_seconds_to_timeval(double seconds, struct timeval* tv)
{
    double whole = trunc(seconds);
    double fraction = (seconds - whole);
    tv->tv_sec = (time_t)whole;
    tv->tv_usec = (long int)(fraction * 1.0E6);
}

HighAvailabilityModule::HighAvailabilityModule() :
    Module(HA_NAME, HA_HELP, ha_params)
{
    config.enabled = false;
    config.daq_channel = false;
    config.ports = nullptr;
    convert_real_seconds_to_timeval(1.0, &config.min_session_lifetime);
    convert_real_seconds_to_timeval(0.1, &config.min_sync_interval);
}

HighAvailabilityModule::~HighAvailabilityModule()
{
    delete config.ports;
}

ProfileStats* HighAvailabilityModule::get_profile() const
{ return &ha_perf_stats; }

bool HighAvailabilityModule::set(const char*, Value& v, SnortConfig*)
{
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
    else if ( v.is("min_age") )
    {
        convert_real_seconds_to_timeval(v.get_real(), &config.min_session_lifetime);
    }
    else if ( v.is("min_sync") )
    {
        convert_real_seconds_to_timeval(v.get_real(), &config.min_sync_interval);
    }
    else
        return false;

    return true;
}

bool HighAvailabilityModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool HighAvailabilityModule::end(const char*, int, SnortConfig*)
{
    if ( config.enabled &&
        !HighAvailabilityManager::instantiate(config.ports, config.daq_channel,
                        &config.min_session_lifetime, &config.min_sync_interval) )
    {
        ParseWarning(WARN_CONF, "Illegal HighAvailability configuration");
        return false;
    }

    return true;
}

