//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

// udp_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "udp_module.h"

#include "trace/trace.h"

#include "stream_udp.h"

using namespace snort;
using namespace std;

THREAD_LOCAL const Trace* stream_udp_trace = nullptr;

static const TraceOption stream_udp_trace_options[] =
{
    { "state", TRACE_UDP_STATE, "enable stream UDP state trace logging" },
    { nullptr, 0, nullptr }
};

//-------------------------------------------------------------------------
// stream_udp module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "session_timeout", Parameter::PT_INT, "1:max31", "30",
      "session tracking timeout" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

StreamUdpModule::StreamUdpModule() : Module(MOD_NAME, MOD_HELP, s_params)
{ }

ProfileStats* StreamUdpModule::get_profile() const
{
    return &udp_perf_stats;
}

StreamUdpConfig* StreamUdpModule::get_data()
{
    StreamUdpConfig* temp = config;
    config = nullptr;
    return temp;
}

bool StreamUdpModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("session_timeout"));
    config->session_timeout = v.get_uint32();
    return true;
}

bool StreamUdpModule::begin(const char*, int, SnortConfig*)
{
    if ( !config )
        config = new StreamUdpConfig;

    return true;
}

bool StreamUdpModule::end(const char*, int, SnortConfig*)
{
    return true;
}

const PegInfo* StreamUdpModule::get_pegs() const
{ return udp_pegs; }

PegCount* StreamUdpModule::get_counts() const
{ return reinterpret_cast<PegCount*>(&udpStats); }

void StreamUdpModule::set_trace(const Trace* trace) const
{ stream_udp_trace = trace; }

const TraceOption* StreamUdpModule::get_trace_options() const
{ return stream_udp_trace_options; }
