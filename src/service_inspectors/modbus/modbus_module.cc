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

// modbus_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "modbus_module.h"

#include "profiler/profiler.h"

#include "modbus.h"

using namespace snort;

THREAD_LOCAL ProfileStats modbus_prof;

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

const PegInfo peg_names[] =
{
    { CountType::SUM, "sessions", "total sessions processed" },
    { CountType::SUM, "frames", "total Modbus messages" },
    { CountType::NOW, "concurrent_sessions", "total concurrent modbus sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent modbus sessions" },

    { CountType::END, nullptr, nullptr }
};

const PegInfo* ModbusModule::get_pegs() const
{ return peg_names; }

PegCount* ModbusModule::get_counts() const
{ return (PegCount*)&modbus_stats; }

//-------------------------------------------------------------------------
// rules
//-------------------------------------------------------------------------

#define MODBUS_BAD_LENGTH_STR \
    "length in Modbus MBAP header does not match the length needed for the given function"

#define MODBUS_BAD_PROTO_ID_STR      "Modbus protocol ID is non-zero"
#define MODBUS_RESERVED_FUNCTION_STR "reserved Modbus function code in use"

static const RuleMap modbus_rules[] =
{
    { MODBUS_BAD_LENGTH, MODBUS_BAD_LENGTH_STR  },
    { MODBUS_BAD_PROTO_ID, MODBUS_BAD_PROTO_ID_STR },
    { MODBUS_RESERVED_FUNCTION, MODBUS_RESERVED_FUNCTION_STR },

    { 0, nullptr }
};

const RuleMap* ModbusModule::get_rules() const
{ return modbus_rules; }

//-------------------------------------------------------------------------
// params
//-------------------------------------------------------------------------

ModbusModule::ModbusModule() :
    Module(MODBUS_NAME, MODBUS_HELP)
{ }

