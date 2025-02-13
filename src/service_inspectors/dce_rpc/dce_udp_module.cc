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

// dce_udp_module.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_udp_module.h"

#include "log/messages.h"
#include "trace/trace.h"

#include "dce_udp.h"

using namespace snort;
using namespace std;

THREAD_LOCAL const Trace* dce_udp_trace = nullptr;

static const Parameter s_params[] =
{
    { "limit_alerts", Parameter::PT_BOOL, nullptr, "true",
      "limit DCE alert to at most one per signature per flow" },

    { "disable_defrag", Parameter::PT_BOOL, nullptr, "false",
      "disable DCE/RPC defragmentation" },

    { "max_frag_len", Parameter::PT_INT, "1514:65535", "65535",
      "maximum fragment size for defragmentation" },

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
    { CountType::SUM, "events", "total events" },
    { CountType::SUM, "udp_sessions", "total udp sessions" },
    { CountType::SUM, "udp_packets", "total udp packets" },
    { CountType::SUM, "requests", "total connection-less requests" },
    { CountType::SUM, "acks", "total connection-less acks" },
    { CountType::SUM, "cancels", "total connection-less cancels" },
    { CountType::SUM, "client_facks", "total connection-less client facks" },
    { CountType::SUM, "ping", "total connection-less ping" },
    { CountType::SUM, "responses", "total connection-less responses" },
    { CountType::SUM, "rejects", "total connection-less rejects" },
    { CountType::SUM, "cancel_acks", "total connection-less cancel acks" },
    { CountType::SUM, "server_facks", "total connection-less server facks" },
    { CountType::SUM, "faults", "total connection-less faults" },
    { CountType::SUM, "no_calls", "total connection-less no calls" },
    { CountType::SUM, "working", "total connection-less working" },
    { CountType::SUM, "other_requests", "total connection-less other requests" },
    { CountType::SUM, "other_responses", "total connection-less other responses" },
    { CountType::SUM, "fragments", "total connection-less fragments" },
    { CountType::MAX, "max_fragment_size", "connection-less maximum fragment size" },
    { CountType::SUM, "frags_reassembled", "total connection-less fragments reassembled" },
    { CountType::SUM, "max_seqnum", "max connection-less seqnum" },
    { CountType::NOW, "concurrent_sessions", "total concurrent sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent sessions" },
    { CountType::END, nullptr, nullptr }
};

Dce2UdpModule::Dce2UdpModule() : Module(DCE2_UDP_NAME, DCE2_UDP_HELP, s_params), config {}
{ }

void Dce2UdpModule::set_trace(const Trace* trace) const
{ dce_udp_trace = trace; }

const TraceOption* Dce2UdpModule::get_trace_options() const
{
#ifndef DEBUG_MSGS
    return nullptr;
#else
    static const TraceOption dce_udp_trace_options(nullptr, 0, nullptr);
    return &dce_udp_trace_options;
#endif
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

ProfileStats* Dce2UdpModule::get_profile() const
{
    return &dce2_udp_pstat_main;
}

bool Dce2UdpModule::set(const char*, Value& v, SnortConfig*)
{
    return dce2_set_common_config(v,config.common);
}

void Dce2UdpModule::get_data(dce2UdpProtoConf& dce2_udp_config)
{
    dce2_udp_config = config;
}

void print_dce2_udp_conf(const dce2UdpProtoConf& config)
{
    print_dce2_common_config(config.common);
}

