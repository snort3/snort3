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

#ifdef __APPLE__
#include <mach/mach_host.h>
#include <mach/thread_act.h>
#endif

#define CPU_FILE (PERF_NAME "_cpu.csv")

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

static inline uint64_t get_microseconds(struct timeval t)
{
    return (uint64_t)t.tv_sec * 1000000 + t.tv_usec;
}

CPUTracker::CPUTracker(PerfConfig *perf) :
    PerfTracker(perf, perf->output == PERF_FILE ? CPU_FILE : nullptr)
{
    formatter->register_section("cpu");
    formatter->register_field("user", &user_stat);
    formatter->register_field("system", &system_stat);
    formatter->register_field("wall", &wall_stat);
}

void CPUTracker::get_clocks(struct timeval& user_time,
    struct timeval& sys_time, struct timeval& wall_time)
{
#ifdef __APPLE__
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    thread_basic_info_t thi;
    thread_basic_info_data_t thi_data;

    thi = &thi_data;
    thread_info(mach_thread_self(), THREAD_BASIC_INFO, (thread_info_t)thi, &count);
    user_time.tv_sec = thi->user_time.seconds;
    user_time.tv_usec = thi->user_time.microseconds;
    sys_time.tv_sec = thi->system_time.seconds;
    sys_time.tv_usec = thi->system_time.microseconds;
#else
    struct rusage usage;
    getrusage(RUSAGE_THREAD, &usage);
    user_time = usage.ru_utime;
    sys_time = usage.ru_stime;
#endif
    gettimeofday(&wall_time, nullptr);
}

void CPUTracker::get_times(uint64_t& user, uint64_t& system, uint64_t& wall)
{
    struct timeval user_tv, sys_tv, wall_tv;

    get_clocks(user_tv, sys_tv, wall_tv);
    
    user = get_microseconds(user_tv);
    system = get_microseconds(sys_tv);
    wall = get_microseconds(wall_tv);
}

void CPUTracker::reset()
{
    get_times(last_ut, last_st, last_wt);
    formatter->finalize_fields(fh);
}

void CPUTracker::process(bool)
{
    uint64_t user, system, wall, idle;

    get_times(user, system, wall);

    user_stat = user - last_ut;
    system_stat = system - last_st;
    wall_stat = wall - last_wt;

    last_ut = user;
    last_st = system;
    last_wt = wall;

    formatter->write(fh, cur_time);
}

#ifdef UNIT_TEST

class TestCPUTracker : public CPUTracker
{
public:
    struct timeval user, sys, wall;

    TestCPUTracker(PerfConfig* perf, FILE* fh): CPUTracker(perf)
    {
        this->fh = fh;       
        cur_time = 1234567890;
        memset(&user, 0, sizeof(wall));
        memset(&sys, 0, sizeof(wall));
        memset(&wall, 0, sizeof(wall));
    }

protected:
    void get_clocks(struct timeval& user_time,
        struct timeval& sys_time, struct timeval& wall_time)
    {
        user_time = user;
        sys_time = sys;
        wall_time = wall;
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
    const char* cooked =
    "#timestamp,cpu.user,cpu.system,cpu.wall\n"
    "1234567890,2100000,3200000,8500000\n"
    "1234567890,0,0,500000\n"
    "1234567890,2100000,3200000,8500000\n";

    FILE* f = tmpfile();

    PerfConfig config;
    config.format = PERF_CSV;
    TestCPUTracker tracker(&config, f);

    tracker.reset();
    tracker.user.tv_sec = 2;
    tracker.user.tv_usec = 100000;
    tracker.sys.tv_sec = 3;
    tracker.sys.tv_usec = 200000;
    tracker.wall.tv_sec = 8;
    tracker.wall.tv_usec = 500000;
    tracker.process(false);
    tracker.wall.tv_sec = 9;
    tracker.wall.tv_usec = 0;
    tracker.process(false);
    tracker.user.tv_sec = 4;
    tracker.user.tv_usec = 200000;
    tracker.sys.tv_sec = 6;
    tracker.sys.tv_usec = 400000;
    tracker.wall.tv_sec = 17;
    tracker.wall.tv_usec = 500000;
    tracker.process(false);

    long int size = ftell(f);
    char* fake_file = (char*) malloc(size + 1);
    rewind(f);
    fread(fake_file, size, 1, f);
    fake_file[size] = '\0';

    CHECK(!strcmp(cooked, fake_file));

    free(fake_file);
    //tracker destructor closes fh if not null
}

TEST_CASE("text", "[cpu_tracker]")
{
    const char* cooked =
    "--------------------------------------------------\n"
    "cpu\n"
    "                     user: 2100000\n"
    "                   system: 3200000\n"
    "                     wall: 8500000\n";

    FILE* f = tmpfile();

    PerfConfig config;
    config.format = PERF_TEXT;
    TestCPUTracker tracker(&config, f);

    tracker.reset();
    tracker.user.tv_sec = 2;
    tracker.user.tv_usec = 100000;
    tracker.sys.tv_sec = 3;
    tracker.sys.tv_usec = 200000;
    tracker.wall.tv_sec = 8;
    tracker.wall.tv_usec = 500000;
    tracker.process(false);

    auto size = ftell(f);
    char* fake_file = (char*) malloc(size + 1);
    rewind(f);
    fread(fake_file, size, 1, f);
    fake_file[size] = '\0';

    CHECK(!strcmp(cooked, fake_file));
    
    free(fake_file);
    //tracker destructor closes fh if not null
}
#endif
