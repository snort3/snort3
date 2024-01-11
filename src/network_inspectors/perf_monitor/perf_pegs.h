//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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

// perf_pegs.h author Michael Matirko <mmatirko@cisco.com>


#ifndef PERF_PEGS_H
#define PERF_PEGS_H

#include "framework/counts.h"
#include "main/snort_types.h"

static const PegInfo perf_module_pegs[] =
{
    { CountType::SUM, "packets", "total packets processed by performance monitor" },
    { CountType::SUM, "flow_tracker_creates", "total number of flow trackers created" },
    { CountType::SUM, "flow_tracker_total_deletes", "flow trackers deleted to stay below memcap limit" },
    { CountType::SUM, "flow_tracker_reload_deletes", "flow trackers deleted due to memcap change on config reload" },
    { CountType::SUM, "flow_tracker_prunes", "flow trackers pruned for reuse by new flows" },
    { CountType::END, nullptr, nullptr },
};

struct PerfPegStats
{
    PegCount total_packets;
    PegCount flow_tracker_creates;
    PegCount flow_tracker_total_deletes;
    PegCount flow_tracker_reload_deletes;
    PegCount flow_tracker_prunes;
};

#endif

