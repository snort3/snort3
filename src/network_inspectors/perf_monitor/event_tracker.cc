//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// event_tracker.cc author Carter Waxman <cwaxman@cisco.com>

#include "event_tracker.h"

#include "utils/stats.h"
#include "utils/util.h"

THREAD_LOCAL EventTracker* perf_event;

void EventTracker::reset()
{
    event_counts.NQEvents = 0;
    event_counts.QEvents  = 0;
}

void EventTracker::process(bool summarize)
{
    if (summarize & !summary)
        return;

    if (config->perf_flags & SFPERF_CONSOLE)
    {
        LogLabel("Snort Setwise Event Stats");
        LogCount("Total Events", event_counts.TotalEvents);
        LogStat("Qualified Events", event_counts.QEvents, event_counts.TotalEvents);
        LogStat("Non-Qualified Events", event_counts.NQEvents, event_counts.TotalEvents);

        event_counts.NQEvents    = 0;
        event_counts.QEvents     = 0;
        event_counts.TotalEvents = 0;
    }
}

void EventTracker::UpdateNQEvents()
{
    if ((perfmon_config) &&
        (perfmon_config->perf_flags & SFPERF_EVENT))
    {
        event_counts.NQEvents++;
        event_counts.TotalEvents++;
    }
}

void EventTracker::UpdateQEvents()
{
    if ((perfmon_config) &&
        (perfmon_config->perf_flags & SFPERF_EVENT))
    {
        event_counts.QEvents++;
        event_counts.TotalEvents++;
    }
}

