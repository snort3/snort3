//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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
    { CountType::SUM, "total_frees", "total flows pruned or freed by performance monitor" },
    { CountType::SUM, "reload_frees", "flows freed on reload with changed memcap" },
    { CountType::SUM, "alloc_prunes", "flows pruned on allocation of IP flows" },
    { CountType::END, nullptr, nullptr },
};

struct PerfPegStats
{
    PegCount total_packets;
    PegCount total_frees;
    PegCount reload_frees;
    PegCount alloc_prunes;
};

#endif

