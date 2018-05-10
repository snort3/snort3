//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "main/analyzer_command.h"
#include "profiler/profiler.h"

#include "packet_capture.h"

using namespace snort;
using namespace std;

static int enable(lua_State*);
static int disable(lua_State*);

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

static const PegInfo cap_names[] =
{
    { CountType::SUM, "processed", "packets processed against filter" },
    { CountType::SUM, "captured", "packets matching dumped after matching filter" },
    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL CaptureStats cap_count_stats;
THREAD_LOCAL ProfileStats cap_prof_stats;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------
class PacketCaptureDebug : public AnalyzerCommand
{
public:
    PacketCaptureDebug(const char* f);
    void execute(Analyzer&) override;
    const char* stringify() override { return "PACKET_CAPTURE_DEBUG"; }
private:
    bool enable = false;
    std::string filter;
};

// -----------------------------------------------------------------------------
// static functions
// -----------------------------------------------------------------------------
static int enable(lua_State* L)
{
    main_broadcast_command(new PacketCaptureDebug(lua_tostring(L, 1)), true);
    return 0;
}

static int disable(lua_State*)
{
    main_broadcast_command(new PacketCaptureDebug(nullptr), true);
    return 0;
}

// -----------------------------------------------------------------------------
// non-static functions
// -----------------------------------------------------------------------------

PacketCaptureDebug::PacketCaptureDebug(const char* f)
{
    if (f)
    {
        filter = f;
        enable = true;
    } 
}

void PacketCaptureDebug::execute(Analyzer&)
{
    if (enable)
        packet_capture_enable(filter);
    else
        packet_capture_disable();
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

