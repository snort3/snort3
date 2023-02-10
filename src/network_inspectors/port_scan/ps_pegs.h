//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

// ps_pegs.h author Masud Hasan <mashasan@cisco.com>

#ifndef PS_PEGS_H
#define PS_PEGS_H

#include "framework/counts.h"
#include "main/snort_types.h"

static const PegInfo ps_module_pegs[] =
{
    { CountType::SUM, "packets", "number of packets processed by port scan" },
    { CountType::SUM, "trackers", "number of trackers allocated by port scan" },
    { CountType::SUM, "alloc_prunes", "number of trackers pruned on allocation of new tracking" },
    { CountType::SUM, "reload_prunes", "number of trackers pruned on reload due to reduced memcap" },
    { CountType::NOW, "bytes_in_use", "number of bytes currently used by portscan" },
    { CountType::END, nullptr, nullptr },
};

struct PsPegStats
{
    PegCount packets;
    PegCount trackers;
    PegCount alloc_prunes;
    PegCount reload_prunes;
    PegCount bytes_in_use;
};

#endif
