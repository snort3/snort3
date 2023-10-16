//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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

// s7comm_module.cc author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "s7comm_module.h"

#include "profiler/profiler.h"

#include "s7comm.h"

using namespace snort;

THREAD_LOCAL ProfileStats s7commplus_prof;

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

const PegInfo peg_names[] =
{
    { CountType::SUM, "sessions", "total sessions processed" },
    { CountType::SUM, "frames", "total S7commplus messages" },
    { CountType::NOW, "concurrent_sessions", "total concurrent s7commplus sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent s7commplus sessions" },

    { CountType::END, nullptr, nullptr }
};

const PegInfo* S7commplusModule::get_pegs() const
{ return peg_names; }

PegCount* S7commplusModule::get_counts() const
{ return (PegCount*)&s7commplus_stats; }

//-------------------------------------------------------------------------
// rules
//-------------------------------------------------------------------------

#define S7COMMPLUS_BAD_LENGTH_STR \
    "length in S7commplus MBAP header does not match the length needed for the given S7commplus function"

#define S7COMMPLUS_BAD_PROTO_ID_STR      "S7commplus protocol ID is non-zero"
#define S7COMMPLUS_RESERVED_FUNCTION_STR "reserved S7commplus function code in use"

static const RuleMap S7commplus_rules[] =
{
    { S7COMMPLUS_BAD_LENGTH, S7COMMPLUS_BAD_LENGTH_STR },
    { S7COMMPLUS_BAD_PROTO_ID, S7COMMPLUS_BAD_PROTO_ID_STR },
    { S7COMMPLUS_RESERVED_FUNCTION, S7COMMPLUS_RESERVED_FUNCTION_STR },

    { 0, nullptr }
};

const RuleMap* S7commplusModule::get_rules() const
{ return S7commplus_rules; }

//-------------------------------------------------------------------------
// params
//-------------------------------------------------------------------------

S7commplusModule::S7commplusModule() :
    Module(S7COMMPLUS_NAME, S7COMMPLUS_HELP)
{ }

