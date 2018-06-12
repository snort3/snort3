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

#ifndef PAT_STATS_H
#define PAT_STATS_H

#include "framework/counts.h"
#include "main/snort_types.h"
#include "main/thread.h"

// pattern matcher queue statistics

struct PatMatQStat
{
    PegCount max_inq;
    PegCount tot_inq_flush;
    PegCount tot_inq_inserts;
    PegCount tot_inq_uinserts;
    PegCount non_qualified_events;
    PegCount qualified_events;
    PegCount matched_bytes;
};

namespace snort
{
SO_PUBLIC extern THREAD_LOCAL PatMatQStat pmqs;
}
#endif

