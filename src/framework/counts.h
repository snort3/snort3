//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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
// counts.h author Russ Combs <rucombs@cisco.com>

#ifndef COUNTS_H
#define COUNTS_H

// basic stats support - note that where these are used, the number of
// elements in stats must be the same as the number of elements in the peg
// info (and in the same sequence).

#include "main/snort_types.h"

typedef uint64_t PegCount;

enum CountType
{
    END,   // sentinel value
    SUM,   // tracks cumulative total number of items seen (eg #events)
    NOW,   // gives snapshot of current number of items (eg current #sessions)
    MAX,   // tracks maximum value seen (eg max #sessions)
};

struct SimpleStats
{
    PegCount total_packets;
};

struct PegInfo
{
    CountType type;
    const char* name;
    const char* help;
};


namespace snort
{
SO_PUBLIC extern const struct PegInfo simple_pegs[];
} // namespace snort

#define array_size(a) (sizeof(a)/sizeof((a)[0]))

#endif

