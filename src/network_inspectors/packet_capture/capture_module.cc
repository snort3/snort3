//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

// capture_module.cc author Carter Waxman <cwaxman@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "capture_module.h"

#include <lua.hpp>

#include "profiler/profiler.h"

#include "packet_capture.h"

using namespace std;

static int enable(lua_State*);
static int disable(lua_State*);

const PegInfo cap_names[] =
{
    { "processed", "packets processed against filter" },
    { "captured", "packets matching dumped after matching filter" },
    { nullptr, nullptr }
};

static const Parameter s_capture[] =
{
    { "enable", Parameter::PT_BOOL, nullptr, "false",
      "initially enable packet dumping" },

    { "filter", Parameter::PT_STRING, nullptr, nullptr,
      "bpf filter to use for packet dump" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Command cap_cmds[] =
{
    { "enable", enable, &s_capture[1], "dump raw packets"},
    { "disable", disable, nullptr, "stop packet dump"},
    { nullptr, nullptr, nullptr, nullptr }
};

THREAD_LOCAL CaptureStats cap_count_stats;
THREAD_LOCAL ProfileStats cap_prof_stats;

static int enable(lua_State* L)
{
    packet_capture_enable(lua_tostring(L, 1));
    return 0;
}

static int disable(lua_State*)
{
    packet_capture_disable();
    return 0;
}

CaptureModule::CaptureModule() :
    Module(CAPTURE_NAME, CAPTURE_HELP, s_capture)
{ config.enabled = false; }

bool CaptureModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("enable") )
        config.enabled = v.get_bool();

    else if ( v.is("filter") )
        config.filter = v.get_string();

    else
        return false;

    return true;
}

const Command* CaptureModule::get_commands() const
{ return cap_cmds; }

ProfileStats* CaptureModule::get_profile() const
{ return &cap_prof_stats; }

void CaptureModule::get_config(CaptureConfig& cfg)
{ cfg = config; }

const PegInfo* CaptureModule::get_pegs() const
{ return cap_names; }

PegCount* CaptureModule::get_counts() const
{ return (PegCount*)&cap_count_stats; }

