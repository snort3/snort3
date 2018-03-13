//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// icmp_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "icmp_module.h"

#include "stream_icmp.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// stream_icmp module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "session_timeout", Parameter::PT_INT, "1:86400", "30",
      "session tracking timeout" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

StreamIcmpModule::StreamIcmpModule() :
    Module(MOD_NAME, MOD_HELP, s_params)
{
    config = nullptr;
}

ProfileStats* StreamIcmpModule::get_profile() const
{
    return &icmp_perf_stats;
}

StreamIcmpConfig* StreamIcmpModule::get_data()
{
    StreamIcmpConfig* temp = config;
    config = nullptr;
    return temp;
}

bool StreamIcmpModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("session_timeout") )
        config->session_timeout = v.get_long();

    else
        return false;

    return true;
}

bool StreamIcmpModule::begin(const char*, int, SnortConfig*)
{
    if ( !config )
        config = new StreamIcmpConfig;

    return true;
}

bool StreamIcmpModule::end(const char*, int, SnortConfig*)
{
    return true;
}

const PegInfo* StreamIcmpModule::get_pegs() const
{ return icmp_pegs; }

PegCount* StreamIcmpModule::get_counts() const
{ return (PegCount*)&icmpStats; }

