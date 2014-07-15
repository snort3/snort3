/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

// rpc_module.cc author Russ Combs <rucombs@cisco.com>

#include "rpc_module.h"
#include <assert.h>

#define RPC_FRAG_TRAFFIC_STR \
    "(rpc_decode) Fragmented RPC Records"
#define RPC_MULTIPLE_RECORD_STR \
    "(rpc_decode) Multiple RPC Records"
#define RPC_LARGE_FRAGSIZE_STR  \
    "(rpc_decode) Large RPC Record Fragment"
#define RPC_INCOMPLETE_SEGMENT_STR \
    "(rpc_decode) Incomplete RPC segment"
#define RPC_ZERO_LENGTH_FRAGMENT_STR \
    "(rpc_decode) Zero-length RPC Fragment"

static const Parameter rpc_params[] =
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

RpcModule::RpcModule() : Module("rpc_decode", rpc_params)
{ }

const RuleMap* RpcModule::get_rules() const
{ return rpc_rules; }

const char** RpcModule::get_pegs() const
{ return simple_pegs; }

PegCount* RpcModule::get_counts() const
{ return (PegCount*)&rdstats; }

ProfileStats* RpcModule::get_profile() const
{ return &rpcdecodePerfStats; }

