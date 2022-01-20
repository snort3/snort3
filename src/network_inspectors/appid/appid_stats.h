//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// appid_stats.h author davmcphe@cisco.com

#ifndef APPID_STATS_H
#define APPID_STATS_H

#include <cstdio>
#include <ctime>
#include <map>

#include "utils/sflsq.h"
#include "utils/util.h"

#include "application_ids.h"

class AppIdSession;
class AppIdConfig;

struct AppIdStatRecord
{
    std::string app_name;
    uint64_t initiator_bytes = 0;
    uint64_t responder_bytes = 0;

    AppIdStatRecord(const char* app_name, uint64_t initiator_bytes, uint64_t responder_bytes) :
        app_name(app_name), initiator_bytes(initiator_bytes), responder_bytes(responder_bytes)
    { }
};

struct StatsBucket
{
    uint32_t start_time = 0;
    std::map<AppId, AppIdStatRecord> apps_tree;
    struct
    {
        size_t tx_byte_cnt = 0;
        size_t rx_byte_cnt = 0;
    } totalStats;
    uint32_t app_record_cnt = 0;
};

class AppIdStatistics
{
public:
    ~AppIdStatistics();

    static AppIdStatistics* initialize_manager(const AppIdConfig&);
    static AppIdStatistics* get_stats_manager();
    static void cleanup();
    void update(const AppIdSession&);
    void flush();

private:
    AppIdStatistics(const AppIdConfig&);

    time_t get_time()
    {
        auto now = time(nullptr);
        return now - (now % bucket_interval);
    }

    void start_stats_period(time_t start_time)
    {
        bucket_start = start_time;
        bucket_end = bucket_start + bucket_interval;
    }

    void end_stats_period();
    StatsBucket* get_stats_bucket(time_t);
    void open_stats_log_file();
    void dump_statistics();

    bool enabled = false;
    SF_LIST* curr_buckets = nullptr;
    SF_LIST* log_buckets = nullptr;
    struct TextLog* log = nullptr;
    time_t bucket_start = 0;
    time_t bucket_interval = 0;
    time_t bucket_end = 0;
    size_t roll_size = 0;
};

#endif
