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

// dce_udp_module.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_udp_module.h"

#include "log/messages.h"

#include "dce_udp.h"

using namespace std;

static const Parameter s_params[] =
{
    { "disable_defrag", Parameter::PT_BOOL, nullptr, "false",
      " Disable DCE/RPC defragmentation" },
    { "max_frag_len", Parameter::PT_INT, "1514:65535", "65535",
      " Maximum fragment size for defragmentation" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap dce2_udp_rules[] =
{
    { DCE2_CL_BAD_MAJOR_VERSION, DCE2_CL_BAD_MAJOR_VERSION_STR },
    { DCE2_CL_BAD_PDU_TYPE, DCE2_CL_BAD_PDU_TYPE_STR },
    { DCE2_CL_DATA_LT_HDR, DCE2_CL_DATA_LT_HDR_STR },
    { DCE2_CL_BAD_SEQ_NUM, DCE2_CL_BAD_SEQ_NUM_STR },
    { 0, nullptr }
};

static const PegInfo dce2_udp_pegs[] =
{
    { "events", "total events" },
    { "udp_sessions", "total udp sessions" },
    { "udp_packets", "total udp packets" },
    { "requests", "total connection-less requests" },
    { "acks", "total connection-less acks" },
    { "cancels", "total connection-less cancels" },
    { "client_facks", "total connection-less client facks" },
    { "ping", "total connection-less ping" },
    { "responses", "total connection-less responses" },
    { "rejects", "total connection-less rejects" },
    { "cancel_acks", "total connection-less cancel acks" },
    { "server_facks", "total connection-less server facks" },
    { "faults", "total connection-less faults" },
    { "no_calls", "total connection-less no calls" },
    { "working", "total connection-less working" },
    { "other_requests", "total connection-less other requests" },
    { "other_responses", "total connection-less other responses" },
    { "fragments", "total connection-less fragments" },
    { "max_fragment_size", "connection-less maximum fragment size" },
    { "frags_reassembled", "total connection-less fragments reassembled" },
    { "max_seqnum", "max connection-less seqnum" },
    { nullptr, nullptr }
};

Dce2UdpModule::Dce2UdpModule() : Module(DCE2_UDP_NAME, DCE2_UDP_HELP, s_params)
{
}

const RuleMap* Dce2UdpModule::get_rules() const
{
    return dce2_udp_rules;
}

const PegInfo* Dce2UdpModule::get_pegs() const
{
    return dce2_udp_pegs;
}

PegCount* Dce2UdpModule::get_counts() const
{
    return (PegCount*)&dce2_udp_stats;
}

ProfileStats* Dce2UdpModule::get_profile(
    unsigned index, const char*& name, const char*& parent) const
{
    switch ( index )
    {
    case 0:
        name = "dce_udp_main";
        parent = nullptr;
        return &dce2_udp_pstat_main;

    case 1:
        name = "dce_udp_session";
        parent = "dce_udp_main";
        return &dce2_udp_pstat_session;

    case 2:
        name = "dce_udp_new_session";
        parent = "dce_udp_session";
        return &dce2_udp_pstat_new_session;

    case 3:
        name = "dce_udp_detect";
        parent = "dce_udp_main";
        return &dce2_udp_pstat_detect;

    case 4:
        name = "dce_udp_log";
        parent = "dce_udp_main";
        return &dce2_udp_pstat_log;

    case 5:
        name = "dce_udp_cl_acts";
        parent = "dce_udp_main";
        return &dce2_udp_pstat_cl_acts;

    case 6:
        name = "dce_udp_cl_frag";
        parent = "dce_udp_main";
        return &dce2_udp_pstat_cl_frag;

    case 7:
        name = "dce_udp_cl_reass";
        parent = "dce_udp_main";
        return &dce2_udp_pstat_cl_reass;
    }
    return nullptr;
}

bool Dce2UdpModule::set(const char*, Value& v, SnortConfig*)
{
    if (dce2_set_common_config(v,config.common))
        return true;
    else
        return false;
}

void Dce2UdpModule::get_data(dce2UdpProtoConf& dce2_udp_config)
{
    dce2_udp_config = config;
}

void print_dce2_udp_conf(dce2UdpProtoConf& config)
{
    LogMessage("DCE UDP config: \n");
    print_dce2_common_config(config.common);
}

