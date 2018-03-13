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

// rpc_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rpc_module.h"

using namespace snort;

#define RPC_FRAG_TRAFFIC_STR \
    "fragmented RPC records"
#define RPC_MULTIPLE_RECORD_STR \
    "multiple RPC records"
#define RPC_LARGE_FRAGSIZE_STR  \
    "large RPC record fragment"
#define RPC_INCOMPLETE_SEGMENT_STR \
    "incomplete RPC segment"
#define RPC_ZERO_LENGTH_FRAGMENT_STR \
    "zero-length RPC fragment"

static const Parameter s_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap rpc_rules[] =
{
    { RPC_FRAG_TRAFFIC, RPC_FRAG_TRAFFIC_STR },
    { RPC_MULTIPLE_RECORD, RPC_MULTIPLE_RECORD_STR },
    { RPC_LARGE_FRAGSIZE, RPC_LARGE_FRAGSIZE_STR },
    { RPC_INCOMPLETE_SEGMENT, RPC_INCOMPLETE_SEGMENT_STR },
    { RPC_ZERO_LENGTH_FRAGMENT, RPC_ZERO_LENGTH_FRAGMENT_STR },

    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

#define s_name "rpc_decode"
#define s_help "RPC inspector"

static const PegInfo rpc_pegs[] =
{
    { CountType::SUM, "total_packets", "total packets" },
    { CountType::NOW, "concurrent_sessions", "total concurrent rpc sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent rpc sessions" },

    { CountType::END, nullptr, nullptr }
};

RpcDecodeModule::RpcDecodeModule() : Module(s_name, s_help, s_params)
{ }

const RuleMap* RpcDecodeModule::get_rules() const
{ return rpc_rules; }

const PegInfo* RpcDecodeModule::get_pegs() const
{ return rpc_pegs; }

PegCount* RpcDecodeModule::get_counts() const
{ return (PegCount*)&rdstats; }

ProfileStats* RpcDecodeModule::get_profile() const
{ return &rpcdecodePerfStats; }

