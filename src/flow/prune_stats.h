//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// prune_stats.h author Joel Cornett <jocornet@cisco.com>

#ifndef PRUNE_STATS_H
#define PRUNE_STATS_H

#include <cstdint>
#include <type_traits>

#include "framework/counts.h"

enum class PruneReason : uint8_t
{
    IDLE,
    EXCESS,
    UNI,
    PREEMPTIVE,
    MEMCAP,
    HA,
    NONE,
    MAX
};

struct PruneStats
{
    using reason_t = std::underlying_type<PruneReason>::type;

    PegCount prunes[static_cast<reason_t>(PruneReason::MAX)] { };

    PegCount get_total() const;

    PegCount& get(PruneReason reason)
    { return prunes[static_cast<reason_t>(reason)]; }

    const PegCount& get(PruneReason reason) const
    { return prunes[static_cast<reason_t>(reason)]; }

    void update(PruneReason reason)
    { ++get(reason); }
};

inline PegCount PruneStats::get_total() const
{
    PegCount total = 0;
    for ( reason_t i = 0; i < static_cast<reason_t>(PruneReason::NONE); ++i )
        total += prunes[i];

    return total;
}

#endif

