//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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
#include "main/snort_config.h"
#include "profiler/profiler_defs.h"

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

    { "min_age", Parameter::PT_INT, "0:max32", "0",
      "minimum session life in milliseconds before HA updates" },

    { "min_sync", Parameter::PT_INT, "0:max32", "0",
      "minimum interval in milliseconds between HA updates" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo ha_pegs[] =
{
    { CountType::SUM, "msgs_recv", "total messages received" },
    { CountType::SUM, "update_msgs_recv", "update messages received" },
    { CountType::SUM, "update_msgs_recv_no_flow", "update messages received without a local flow" },
    { CountType::SUM, "update_msgs_consumed", "update messages fully consumed" },
    { CountType::SUM, "delete_msgs_consumed", "deletion messages consumed" },
    { CountType::SUM, "daq_stores", "states stored via daq" },
    { CountType::SUM, "daq_imports", "states imported via daq" },
    { CountType::SUM, "key_mismatch", "messages received with a flow key mismatch" },
    { CountType::SUM, "msg_version_mismatch", "messages received with a version mismatch" },
    { CountType::SUM, "msg_length_mismatch", "messages received with an inconsistent total length" },
    { CountType::SUM, "truncated_msgs", "truncated messages received" },
    { CountType::SUM, "unknown_key_type", "messages received with an unknown flow key type" },
    { CountType::SUM, "unknown_client_idx", "messages received with an unknown client index" },
    { CountType::SUM, "client_consume_errors", "client data consume failure count" },
    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL HAStats ha_stats;
THREAD_LOCAL ProfileStats ha_perf_stats;

//-------------------------------------------------------------------------

static void convert_milliseconds_to_timeval(uint32_t milliseconds, struct timeval* tv)
{
    tv->tv_sec = (milliseconds / 1000);
    tv->tv_usec = (milliseconds % 1000) * 1000;
}

HighAvailabilityModule::HighAvailabilityModule() :
    Module(HA_NAME, HA_HELP, ha_params)
{
    config = nullptr;
}

HighAvailabilityModule::~HighAvailabilityModule()
{
    if (config)
        delete config;
}

const PegInfo* HighAvailabilityModule::get_pegs() const
{
    return ha_pegs;
}

PegCount* HighAvailabilityModule::get_counts() const
{
    return (PegCount*) &ha_stats;
}

ProfileStats* HighAvailabilityModule::get_profile() const
{
    return &ha_perf_stats;
}

bool HighAvailabilityModule::begin(const char*, int, SnortConfig*)
{
    assert(!config);
    config = new HighAvailabilityConfig();

    return true;
}

bool HighAvailabilityModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("enable") )
    {
        config->enabled = v.get_bool();
    }
    else if ( v.is("daq_channel") )
    {
        config->daq_channel = v.get_bool();
    }
    else if ( v.is("ports") )
    {
        if ( !config->ports )
            config->ports = new PortBitSet;
        v.get_bits(*(config->ports));
    }
    else if ( v.is("min_age") )
    {
        convert_milliseconds_to_timeval(v.get_uint32(), &config->min_session_lifetime);
    }
    else if ( v.is("min_sync") )
    {
        convert_milliseconds_to_timeval(v.get_uint32(), &config->min_sync_interval);
    }

    return true;
}

bool HighAvailabilityModule::end(const char*, int, SnortConfig* sc)
{
    if ( config->enabled )
        sc->ha_config = config;
    else
        delete config;
    config = nullptr;

    return true;
}

