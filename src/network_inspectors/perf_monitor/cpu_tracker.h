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

// cpu_tracker.h author Carter Waxman <cwaxman@cisco.com>

#ifndef CPU_TRACKER_H
#define CPU_TRACKER_H

#include "perf_tracker.h"

class CPUTracker : public PerfTracker
{
public:
    CPUTracker(PerfConfig*);
    void reset() override;
    void process(bool) override;

protected:
    virtual void get_clocks(struct timeval& user_time,
        struct timeval& sys_time, struct timeval& wall_time);

private:
    //19 bits for microseconds
    //45 bits for seconds (out to year 1116918)
    uint64_t last_wt;
    uint64_t last_ut;
    uint64_t last_st;

    PegCount user_stat;
    PegCount system_stat;
    PegCount wall_stat;

    void get_times(uint64_t& user, uint64_t& system, uint64_t& wall);
};

#endif

