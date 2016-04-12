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

#define EVENT_FILE (PERF_NAME "_event.csv")

THREAD_LOCAL EventTracker* perf_event;

EventTracker::EventTracker(PerfConfig *perf) :
    PerfTracker(perf, perf->output == PERF_FILE ? EVENT_FILE : nullptr)
{
    formatter->register_section("event_stats");
    formatter->register_field("qualified", &qualified_events);
    formatter->register_field("non_qualified", &non_qualified_events);
}

void EventTracker::reset()
{
    non_qualified_events = 0;
    qualified_events  = 0;
    
    formatter->finalize_fields(fh);   
}

void EventTracker::process(bool)
{
    formatter->write(fh, cur_time);

    non_qualified_events = 0;
    qualified_events = 0;
}

void EventTracker::update_non_qualified_events()
{
    if ((perfmon_config) &&
        (perfmon_config->perf_flags & PERF_EVENT))
    {
        non_qualified_events++;
    }
}

void EventTracker::update_qualified_events()
{
    if ((perfmon_config) &&
        (perfmon_config->perf_flags & PERF_EVENT))
    {
        qualified_events++;
    }
}

