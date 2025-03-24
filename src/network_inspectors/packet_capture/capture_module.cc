//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "control/control.h"
#include "main/analyzer_command.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "utils/util.h"

#include "packet_capture.h"

using namespace snort;
using namespace std;

static int enable(lua_State*);
static int disable(lua_State*);
bool is_path_valid(const std::string& path);

static const Parameter s_capture[] =
{
    { "enable", Parameter::PT_BOOL, nullptr, "false",
      "state of packet capturing" },

    { "filter", Parameter::PT_STRING, nullptr, nullptr,
      "bpf filter to use for packet capturing" },

    { "group", Parameter::PT_INT, "-1:32767", "-1",
      "group filter to use for packet capturing" },

    { "tenants", Parameter::PT_STRING, nullptr, nullptr,
      "comma-separated tenants filter to use for packet capturing" },

    { "check_inner_pkt", Parameter::PT_BOOL, nullptr, "true",
      "apply filter on inner packet headers" },
    
    { "capture_path", Parameter::PT_STRING, nullptr, nullptr,
      "directory path to capture pcaps" },
    
    { "max_packet_count", Parameter::PT_INT, "0:max32", "1000000",
      "cap the number of packets per thread" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter capture_params[] =
{
    { "filter", Parameter::PT_STRING, nullptr, nullptr,
      "bpf filter to use for packet capturing" },

    { "group", Parameter::PT_INT, "-1:32767", "-1",
      "group filter to use for packet capturing" },

    { "tenants", Parameter::PT_STRING, nullptr, nullptr,
      "comma-separated tenants filter to use for packet capturing" },

    { "check_inner_pkt", Parameter::PT_BOOL, nullptr, "true",
      "apply filter on inner packet headers" },

    { "capture_path", Parameter::PT_STRING, nullptr, nullptr,
      "directory path to capture pcaps" },
    
    { "max_packet_count", Parameter::PT_INT, "0:max32", "1000000",
      "cap the number of packets per thread" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Command cap_cmds[] =
{
    { "enable", enable, capture_params, "capture raw packets"},
    { "disable", disable, nullptr, "stop packet capturing"},
    { nullptr, nullptr, nullptr, nullptr }
};

static const PegInfo cap_names[] =
{
    { CountType::SUM, "processed", "packets processed against filter" },
    { CountType::SUM, "captured", "packets captured after matching filter" },
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
    PacketCaptureDebug(const char* f, const int16_t g, const char* t, const bool ci, 
                       const char* p, const unsigned max);
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "PACKET_CAPTURE_DEBUG"; }
private:
    bool enable = false;
    std::string filter;
    int16_t group = -1;
    std::string tenants;
    bool check_inner_pkt = true;
    std::string capture_path;
    unsigned max_packet_count = 0;
};

// -----------------------------------------------------------------------------
// static functions
// -----------------------------------------------------------------------------
static int enable(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    auto log_response = [ctrlcon](const char* response)
    {
      if (ctrlcon)
        ctrlcon->respond("%s", response);
      else
        LogMessage("%s", response);
    };
    
    std::string path = luaL_optstring(L, 5, "");
    if ( !path.empty() && !is_path_valid(path) )
    {
      log_response("== Capture path invalid\n"); 
      return 0;
    }

    auto max_limit = luaL_optint(L, 6, 0);
    if ( max_limit < 0)
    {
      log_response("== Max packet count invalid\n"); 
      return 0;
    }
    main_broadcast_command(new PacketCaptureDebug(luaL_optstring(L, 1, ""),
        luaL_optint(L, 2, 0), luaL_optstring(L, 3, ""), luaL_opt(L, lua_toboolean, 4, true), 
        path.c_str(), max_limit), ctrlcon);
    return 0;
}

static int disable(lua_State* L)
{
    main_broadcast_command(new PacketCaptureDebug(nullptr, -1, nullptr, true, nullptr, 0), 
        ControlConn::query_from_lua(L));
    return 0;
}

// -----------------------------------------------------------------------------
// non-static functions
// -----------------------------------------------------------------------------

PacketCaptureDebug::PacketCaptureDebug(const char* f, const int16_t g, const char* t, const bool ci, \
                                       const char* p, const unsigned max)
{
    if (f)
    {
        filter = f;
        group = g;
        enable = true;
        tenants = t == nullptr ? "" : t;
        check_inner_pkt = ci;
        capture_path = p;
        max_packet_count = max;
    }
}

bool PacketCaptureDebug::execute(Analyzer&, void**)
{
    if (enable)
        packet_capture_enable(filter, group, tenants, check_inner_pkt, capture_path, max_packet_count);
    else
        packet_capture_disable();

    return true;
}

CaptureModule::CaptureModule() :
    Module(CAPTURE_NAME, CAPTURE_HELP, s_capture)
{
    config.enabled = false;
    config.group = -1;
    config.tenants.clear();
}

bool CaptureModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("enable") )
        config.enabled = v.get_bool();

    else if ( v.is("filter") )
        config.filter = v.get_string();

    else if ( v.is("group") )
        config.group = v.get_int16();

    else if ( v.is("tenants") )
        str_to_int_vector(v.get_string(), ',', config.tenants);

    else if ( v.is("check_inner_pkt") )
        config.check_inner_pkt = v.get_bool();
    
    else if ( v.is("capture_path") )
    {
        if ( !is_path_valid(v.get_string()) )
        {
          return false;
        }
        config.capture_path = v.get_string();
    }
    
    else if ( v.is("max_packet_count") )
        config.max_packet_count = v.get_uint32();

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

bool is_path_valid(const std::string& path)
{
  if ( !is_directory_path(path) )
  {
    WarningMessage("Cannot create pcap at %s; directory does not exist\n", path.c_str());
    return false;
  }
  return true;
}
