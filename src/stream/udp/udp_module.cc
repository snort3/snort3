//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "stream_udp.h"

using namespace std;

//-------------------------------------------------------------------------
// stream_udp module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "session_timeout", Parameter::PT_INT, "1:86400", "30",
      "session tracking timeout" },

    { "ignore_any_rules", Parameter::PT_BOOL, nullptr, "false",
      "process udp content rules w/o ports only if rules with ports are present" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

StreamUdpModule::StreamUdpModule() :
    Module(MOD_NAME, MOD_HELP, s_params)
{
    config = nullptr;
}

ProfileStats* StreamUdpModule::get_profile(
    unsigned index, const char*& name, const char*& parent) const
{
    if ( index )
        return nullptr;

    name = MOD_NAME;
    parent = "stream";
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
    if ( v.is("session_timeout") )
        config->session_timeout = v.get_long();

    else if ( v.is("ignore_any_rules") )
        config->ignore_any = v.get_bool();

    else
        return false;

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
{ return (PegCount*)&udpStats; }
