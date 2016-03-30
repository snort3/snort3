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

// event_tracker.h author Carter Waxman <cwaxman@cisco.com>

#ifndef EVENT_TRACKER_H
#define EVENT_TRACKER_H

#include "perf_module.h"
#include "perf_tracker.h"

/* Raw event counters */
struct PerfEventCounts
{
    uint64_t NQEvents;
    uint64_t QEvents;

    uint64_t TotalEvents;
};

class EventTracker : public PerfTracker
{
public:
    EventTracker(PerfConfig* perf) :
        PerfTracker(perf, perf->output == PERF_FILE ? EVENT_FILE : nullptr) { }
    void reset() override;
    void process(bool) override;

    void UpdateNQEvents();
    void UpdateQEvents();

private:
    PerfEventCounts event_counts;
};

extern THREAD_LOCAL EventTracker* perf_event;
#endif

