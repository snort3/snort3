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

// perf_tracker.h author Carter Waxman <cwaxman@cisco.com>

#ifndef PERF_TRACKER_H
#define PERF_TRACKER_H

#include <cstdio>
#include "perf_monitor.h"

class PerfTracker
{
public:
    virtual void reset() { }
    virtual void show() { }         // FIXIT-L would it be better to let perfmon do this if it knows
                                    // the names of fields?

    virtual void update(Packet*) { }
    virtual void update_time(time_t time) { cur_time = time; }
    virtual void process(bool /*summary*/) { } //FIXIT-M get rid of this step.

    virtual void open(bool append) final;
    virtual void close() final;
    virtual void rotate() final;
    virtual void auto_rotate() final;

    virtual ~PerfTracker();

protected:
    SFPERF* config;
    bool summary;
    FILE* fh = nullptr;
    std::string fname;
    time_t cur_time;

    PerfTracker(SFPERF*, bool summary, const char* tracker_fname);
};
#endif

