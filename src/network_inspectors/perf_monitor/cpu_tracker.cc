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

// cpu_tracker.cc author Carter Waxman <cwaxman@cisco.com>

#include "cpu_tracker.h"

#include "utils/stats.h"
#include "utils/util.h"

#include <sys/resource.h>

#define CPU_FILE (PERF_NAME "_cpu.csv")

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

static const std::string csv_header =
    "#timestamp,user,system,idle\n";

static inline uint64_t get_microseconds(struct timeval t)
{
    return (uint64_t)t.tv_sec * 1000000 + t.tv_usec;
}


CPUTracker::CPUTracker(PerfConfig *perf) :
    PerfTracker(perf, perf->output == PERF_FILE ? CPU_FILE : nullptr){}

void CPUTracker::get_clocks(struct rusage& usage, struct timeval& wall_time)
{
    getrusage(RUSAGE_THREAD, &usage);
    gettimeofday(&wall_time, nullptr);
}

void CPUTracker::get_times(uint64_t& user, uint64_t& system, uint64_t& wall)
{
    struct rusage usage;
    struct timeval wall_time;

    get_clocks(usage, wall_time);
    
    user = get_microseconds(usage.ru_utime);
    system = get_microseconds(usage.ru_stime);
    wall = get_microseconds(wall_time);
}

void CPUTracker::reset()
{
    get_times(last_ut, last_st, last_wt);
    if (config->format == PERF_CSV)
    {
        fwrite(csv_header.c_str(), csv_header.length(), 1, fh);
        fflush(fh);
    }
}

void CPUTracker::process(bool)
{
    uint64_t user, system, wall, idle;

    get_times(user, system, wall);

    idle = wall - user - system;
    user -= last_ut;
    system -= last_st;
    wall -= last_wt;

    last_ut = user;
    last_st = system;
    last_wt = wall;

    double d_user = (double) user / wall * 100;
    double d_system = (double) system / wall * 100;
    double d_idle = (double) idle / wall * 100;
    if ( config->format == PERF_TEXT )
    {
        LogLabel("cpu usage", fh);
        LogStat("User", d_user, fh);
        LogStat("System", d_system, fh);
        LogStat("Idle", d_idle, fh);
    }
    else if ( config->format == PERF_CSV )
    {
        fprintf(fh, CSVu64 "%g,%g,%g\n",
            cur_time, d_user, d_system, d_idle);
    }
    fflush(fh);
}

#ifdef UNIT_TEST

class TestCPUTracker : public CPUTracker
{
public:
    struct rusage usage;
    struct timeval wall;

    TestCPUTracker(PerfConfig* perf, FILE* fh): CPUTracker(perf)
    {
        this->fh = fh;       
        cur_time = 1234567890;
        memset(&usage, 0, sizeof(usage));
        memset(&wall, 0, sizeof(wall));
    }

protected:
    void get_clocks(struct rusage& usage, struct timeval& wall) override
    {
        usage = this->usage;
        wall = this->wall;
    }

};

TEST_CASE("Timeval to scalar", "[cpu_tracker]")
{
    struct timeval t, t2;

    t.tv_sec = 1459523272;
    t.tv_usec = 123456;
    CHECK(get_microseconds(t) == 1459523272123456 );

    t.tv_sec = 0;
    t.tv_usec = 0;
    CHECK(get_microseconds(t) == 0);

    //integer overflow
    t.tv_sec = 0xFFFFFFFF;
    t.tv_usec = 999999;
    auto ms = get_microseconds(t);
    t2.tv_sec = ms / 1000000;
    t2.tv_usec = ms % 1000000;
    CHECK(t2.tv_sec == t.tv_sec);
    CHECK(t2.tv_usec == t.tv_usec);
}

TEST_CASE("csv", "[cpu_tracker]")
{
    char* fake_file;
    size_t size;
    const char* cooked =
    "#timestamp,user,system,idle\n"
    "1234567890,23.0769,38.4615,38.4615\n";

    FILE *f = open_memstream(&fake_file, &size);

    PerfConfig config;
    config.format = PERF_CSV;
    TestCPUTracker tracker(&config, f);

    tracker.reset();
    tracker.usage.ru_utime.tv_sec = 2;
    tracker.usage.ru_utime.tv_usec = 1000000;
    tracker.usage.ru_stime.tv_sec = 3;
    tracker.usage.ru_stime.tv_usec = 2000000;
    tracker.wall.tv_sec = 8;
    tracker.wall.tv_usec = 5000000;
    tracker.process(false);

    CHECK(!strcmp(cooked, fake_file));

    //tracker destructor closes fh if not null
}

TEST_CASE("text", "[cpu_tracker]")
{
    char* fake_file;
    size_t size;
    const char* cooked =
    "--------------------------------------------------\n"
    "cpu usage\n"
    "                     User: 23.0769\n"
    "                   System: 38.4615\n"
    "                     Idle: 38.4615\n";

    FILE *f = open_memstream(&fake_file, &size);

    PerfConfig config;
    config.format = PERF_TEXT;
    TestCPUTracker tracker(&config, f);

    tracker.reset();
    tracker.usage.ru_utime.tv_sec = 2;
    tracker.usage.ru_utime.tv_usec = 1000000;
    tracker.usage.ru_stime.tv_sec = 3;
    tracker.usage.ru_stime.tv_usec = 2000000;
    tracker.wall.tv_sec = 8;
    tracker.wall.tv_usec = 5000000;
    tracker.process(false);

    CHECK(!strcmp(cooked, fake_file));

    //tracker destructor closes fh if not null
}
#endif
