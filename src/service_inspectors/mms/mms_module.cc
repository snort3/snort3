//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

// mms_module.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus_module.c (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm_module.c (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mms_module.h"

#include "profiler/profiler.h"

#include "mms.h"

using namespace snort;

THREAD_LOCAL ProfileStats mms_prof;

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

const PegInfo peg_names[] =
{
    { CountType::SUM, "sessions",                "total sessions processed" },
    { CountType::SUM, "frames",                  "total MMS messages" },
    { CountType::NOW, "concurrent_sessions",     "total concurrent MMS sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent MMS sessions" },

    { CountType::END, nullptr,                   nullptr }
};

const PegInfo* MmsModule::get_pegs() const
{
    return peg_names;
}

PegCount* MmsModule::get_counts() const
{
    return (PegCount*)&mms_stats;
}

//-------------------------------------------------------------------------
// rules
//-------------------------------------------------------------------------

static const RuleMap Mms_rules[] =
{
    { 0, nullptr }
};

const RuleMap* MmsModule::get_rules() const
{
    return Mms_rules;
}

//-------------------------------------------------------------------------
// params
//-------------------------------------------------------------------------

MmsModule::MmsModule() :
    Module(MMS_NAME, MMS_HELP)
{
}

