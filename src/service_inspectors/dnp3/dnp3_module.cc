//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// dnp3_module.cc author Rashmi Pitre <rrp@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dnp3_module.h"

#include "log/messages.h"

#include "dnp3.h"

using namespace snort;
using namespace std;

static const Parameter s_params[] =
{
    { "check_crc", Parameter::PT_BOOL, nullptr, "false",
      "validate checksums in DNP3 link layer frames" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap dnp3_rules[] =
{
    { DNP3_BAD_CRC, DNP3_BAD_CRC_STR },
    { DNP3_DROPPED_FRAME, DNP3_DROPPED_FRAME_STR },
    { DNP3_DROPPED_SEGMENT, DNP3_DROPPED_SEGMENT_STR },
    { DNP3_REASSEMBLY_BUFFER_CLEARED, DNP3_REASSEMBLY_BUFFER_CLEARED_STR },
    { DNP3_RESERVED_ADDRESS, DNP3_RESERVED_ADDRESS_STR },
    { DNP3_RESERVED_FUNCTION, DNP3_RESERVED_FUNCTION_STR },
    { 0, nullptr }
};

static const PegInfo dnp3_pegs[] =
{
    { CountType::SUM, "total_packets", "total packets" },
    { CountType::SUM, "udp_packets", "total udp packets" },
    { CountType::SUM, "tcp_pdus", "total tcp pdus" },
    { CountType::SUM, "dnp3_link_layer_frames", "total dnp3 link layer frames" },
    { CountType::SUM, "dnp3_application_pdus", "total dnp3 application pdus" },
    { CountType::NOW, "concurrent_sessions", "total concurrent dnp3 sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent dnp3 sessions" },
    { CountType::END, nullptr, nullptr }
};

Dnp3Module::Dnp3Module() : Module(DNP3_NAME, DNP3_HELP, s_params)
{
}

const RuleMap* Dnp3Module::get_rules() const
{
    return dnp3_rules;
}

const PegInfo* Dnp3Module::get_pegs() const
{
    return dnp3_pegs;
}

PegCount* Dnp3Module::get_counts() const
{
    return (PegCount*)&dnp3_stats;
}

ProfileStats* Dnp3Module::get_profile() const
{
    return &dnp3_perf_stats;
}

bool Dnp3Module::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("check_crc") )
        config.check_crc = v.get_bool();

    else
        return false;

    return true;
}

void Dnp3Module::get_data(dnp3ProtoConf& dnp3_config)
{
    dnp3_config.check_crc = config.check_crc;
}

void print_dnp3_conf(dnp3ProtoConf& config)
{
    LogMessage("DNP3 config: \n");
    LogMessage("    Check CRC: %s\n",
        config.check_crc ?
        "ENABLED" : "DISABLED");
}

