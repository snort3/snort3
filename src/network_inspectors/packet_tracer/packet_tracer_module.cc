//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

// packet_tracer_module.cc author Shashikant Lad <shaslad@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <lua.hpp>

#include "packet_tracer_module.h"

#include "main/snort_config.h"
#include "profiler/profiler.h"
#include "main/analyzer_command.h"
#include "log/messages.h"
#include "sfip/sf_ip.h"

#include "packet_tracer.h"

using namespace snort;

static int enable(lua_State*);
static int disable(lua_State*);

static const Parameter s_params[] =
{
    {"enable", Parameter::PT_BOOL, nullptr, "false",
    "enable summary output of state that determined packet verdict"},

    {"output", Parameter::PT_ENUM, "console | file", "console",
    "select where to send packet trace"},

    {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}
};

static const Parameter enable_packet_tracer_params[] =
{
    {"proto", Parameter::PT_INT, nullptr, nullptr, "numerical IP protocol ID filter"},
    {"src_ip", Parameter::PT_STRING, nullptr, nullptr, "source IP address filter"},
    {"src_port", Parameter::PT_INT, nullptr, nullptr, "source port filter"},
    {"dst_ip", Parameter::PT_STRING, nullptr, nullptr, "destination IP address filter"},
    {"dst_port", Parameter::PT_INT, nullptr, nullptr, "destination port filter"},
    {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}
};

static const Command packet_tracer_cmds[] =
{
    {"enable", enable, enable_packet_tracer_params, "enable packet tracer debugging"},
    {"disable", disable, nullptr, "disable packet tracer"},
    {nullptr, nullptr, nullptr, nullptr}
};

class PacketTracerDebug : public AnalyzerCommand
{
  public:
    PacketTracerDebug(PTSessionConstraints *cs);
    void execute(Analyzer &) override;
    const char *stringify() override { return "PACKET_TRACER_DEBUG"; }

  private:
    PTSessionConstraints constraints = {};
    bool enable = false;
};

PacketTracerDebug::PacketTracerDebug(PTSessionConstraints *cs)
{
    if (cs)
    {
        memcpy(&constraints, cs, sizeof(constraints));
        enable = true;
    }
}

void PacketTracerDebug::execute(Analyzer &)
{
    if (enable)
        PacketTracer::set_constraints(&constraints);
    else 
        PacketTracer::set_constraints(nullptr);
}

static int enable(lua_State* L)
{
    int proto = luaL_optint(L, 1, 0);
    const char *sipstr = luaL_optstring(L, 2, nullptr);
    int sport = luaL_optint(L, 3, 0);
    const char *dipstr = luaL_optstring(L, 4, nullptr);
    int dport = luaL_optint(L, 5, 0);

    SfIp sip, dip;
    if (sipstr)
    {
        if (sip.set(sipstr) != SFIP_SUCCESS)
            LogMessage("Invalid source IP address provided: %s\n", sipstr);
    }

    if (dipstr)
    {
        if (dip.set(dipstr) != SFIP_SUCCESS)
            LogMessage("Invalid destination IP address provided: %s\n", dipstr);
    }

    PTSessionConstraints constraints = {};

    if (proto)
        constraints.protocol = (IpProtocol)proto;

    if (sip.is_set())
    {
        memcpy(&constraints.sip, sip.get_ip6_ptr(), sizeof(constraints.sip));
        constraints.sip_flag = true;
    }

    if (dip.is_set())
    {
        memcpy(&constraints.dip, dip.get_ip6_ptr(), sizeof(constraints.dip));
        constraints.dip_flag = true;
    }

    constraints.sport = sport;
    constraints.dport = dport;

    main_broadcast_command(new PacketTracerDebug(&constraints), true);
    return 0;
}

static int disable(lua_State*)
{
    main_broadcast_command(new PacketTracerDebug(nullptr), true);
    return 0;
}

PacketTracerModule::PacketTracerModule() :
    Module(PACKET_TRACER_NAME, PACKET_TRACER_HELP, s_params)
{}

bool PacketTracerModule::set(const char *, Value &v, SnortConfig*)
{
    if ( v.is("enable") )
        config->enabled = v.get_bool();

    else if ( v.is("output") )
    {
        switch ( v.get_long() )
        {
            case PACKET_TRACE_CONSOLE:
                config->file = "-";
                break;

            case PACKET_TRACE_FILE:
                config->file = "packet_trace.txt";
                break;

            default:
                return false;
        }
    }
    else
        return false;

    return true;
}

const Command *PacketTracerModule::get_commands() const
{
    return packet_tracer_cmds;
}

bool PacketTracerModule::begin(const char*, int, SnortConfig*)
{
    assert(!config);
    config = new PacketTracerConfig;
    return true;
}
bool PacketTracerModule::end(const char*, int, SnortConfig*)
{
    if (config != nullptr) 
    {
        PacketTracer::configure(config->enabled, config->file);
        delete config;
        config = nullptr;
    }
    return true;
}
