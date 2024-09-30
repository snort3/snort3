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

// s7comm_module.cc author Yarin Peretz <yarinp123@gmail.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "s7comm_module.h"

#include "profiler/profiler.h"

#include "s7comm.h"

using namespace snort;

THREAD_LOCAL ProfileStats s7comm_prof;

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

const PegInfo peg_names[] =
{
    { CountType::SUM, "sessions", "total sessions processed" },
    { CountType::SUM, "frames", "total S7comm messages" },
    { CountType::NOW, "concurrent_sessions", "total concurrent s7comm sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent s7comm sessions" },

    { CountType::END, nullptr, nullptr }
};

const PegInfo* S7commModule::get_pegs() const
{ return peg_names; }

PegCount* S7commModule::get_counts() const
{ return (PegCount*)&s7comm_stats; }

//-------------------------------------------------------------------------
// rules
//-------------------------------------------------------------------------

#define S7COMM_BAD_LENGTH_STR \
    "length in S7comm MBAP header does not match the length needed for the given S7comm function"

#define S7COMM_BAD_PROTO_ID_STR      "S7comm protocol ID is non-zero"
#define S7COMM_RESERVED_FUNCTION_STR "reserved S7comm function code in use"

static const RuleMap S7comm_rules[] =
{
    { S7COMM_BAD_LENGTH, S7COMM_BAD_LENGTH_STR },
    { S7COMM_BAD_PROTO_ID, S7COMM_BAD_PROTO_ID_STR },
    { S7COMM_RESERVED_FUNCTION, S7COMM_RESERVED_FUNCTION_STR },

    { 0, nullptr }
};

const RuleMap* S7commModule::get_rules() const
{ return S7comm_rules; }

//-------------------------------------------------------------------------
// params
//-------------------------------------------------------------------------

S7commModule::S7commModule() :
    Module(S7COMM_NAME, S7COMM_HELP)
{ }
