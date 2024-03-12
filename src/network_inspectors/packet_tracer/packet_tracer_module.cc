//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "packet_tracer_module.h"

#include <lua.hpp>

#include "control/control.h"
#include "log/messages.h"
#include "main/analyzer_command.h"
#include "main/snort_config.h"
#include "profiler/profiler.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"

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
    {"proto", Parameter::PT_INT, "0:255", nullptr, "numerical IP protocol ID filter"},
    {"src_ip", Parameter::PT_STRING, nullptr, nullptr, "source IP address filter"},
    {"src_port", Parameter::PT_INT, "0:65535", nullptr, "source port filter"},
    {"dst_ip", Parameter::PT_STRING, nullptr, nullptr, "destination IP address filter"},
    {"dst_port", Parameter::PT_INT, "0:65535", nullptr, "destination port filter"},
    {"tenants", Parameter::PT_STRING, nullptr, nullptr, "tenants filter"},
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
    PacketTracerDebug(const PacketConstraints* cs);
    bool execute(Analyzer&, void**) override;
    const char *stringify() override { return "PACKET_TRACER_DEBUG"; }

  private:
    PacketConstraints constraints;
    bool enable = false;
};

PacketTracerDebug::PacketTracerDebug(const PacketConstraints* cs)
{
    if (cs)
    {
        constraints = *cs;
        enable = true;
    }
}

bool PacketTracerDebug::execute(Analyzer&, void**)
{
    if (enable)
        PacketTracer::set_constraints(&constraints);
    else
        PacketTracer::set_constraints(nullptr);

    return true;
}

static int enable(lua_State* L)
{
    int proto = luaL_optint(L, 1, 0);
    const char *sipstr = luaL_optstring(L, 2, nullptr);
    int sport = luaL_optint(L, 3, 0);
    const char *dipstr = luaL_optstring(L, 4, nullptr);
    int dport = luaL_optint(L, 5, 0);

    const char *tenantsstr = luaL_optstring(L, 6, nullptr);

    SfIp sip, dip;
    sip.clear();
    dip.clear();

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

    PacketConstraints constraints = {};

    if (tenantsstr)
    {
        str_to_int_vector(tenantsstr, ',', constraints.tenants);
        constraints.set_bits |= PacketConstraints::SetBits::TENANT;
    }

    if (proto and (IpProtocol)proto < IpProtocol::PROTO_NOT_SET)
    {
        constraints.ip_proto = (IpProtocol)proto;
        constraints.set_bits |= PacketConstraints::SetBits::IP_PROTO;
    }

    if (sip.is_set())
    {
        constraints.src_ip = sip;
        constraints.set_bits |= PacketConstraints::SetBits::SRC_IP;
    }

    if (dip.is_set())
    {
        constraints.dst_ip = dip;
        constraints.set_bits |= PacketConstraints::SetBits::DST_IP;
    }

    constraints.src_port = sport;
    constraints.dst_port = dport;
    if ( sport )
        constraints.set_bits |= PacketConstraints::SetBits::SRC_PORT;
    if ( dport )
        constraints.set_bits |= PacketConstraints::SetBits::DST_PORT;
    main_broadcast_command(new PacketTracerDebug(&constraints), ControlConn::query_from_lua(L));
    return 0;
}

static int disable(lua_State* L)
{
    main_broadcast_command(new PacketTracerDebug(nullptr), ControlConn::query_from_lua(L));
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
        switch ( v.get_uint8() )
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
