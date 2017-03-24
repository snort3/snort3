//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// appid_stats.h author Sourcefire Inc.

#ifndef APPID_STATS_H
#define APPID_STATS_H

#include <stdio.h>
#include <time.h>

#include "appid_utils/fw_avltree.h"
#include "utils/sflsq.h"

class AppIdSession;
class AppIdModuleConfig;

struct StatsBucket
{
    uint32_t startTime;
    FwAvlTree* appsTree;
    struct
    {
        size_t txByteCnt;
        size_t rxByteCnt;
    } totalStats;
    uint32_t appRecordCnt;
};

class AppIdStatistics
{
public:
    ~AppIdStatistics();

    static AppIdStatistics* initialize_manager(const AppIdModuleConfig&);
    void update(AppIdSession*);
    void flush();

private:
    AppIdStatistics(const AppIdModuleConfig&);

    time_t get_time()
    {
        auto now = time(nullptr);
        return now - (now % bucketInterval);
    }

    void start_stats_period(time_t startTime)
    {
        bucketStart = startTime;
        bucketEnd = bucketStart + bucketInterval;
    }

    void end_stats_period(void);
    StatsBucket* get_stats_bucket(time_t);
    FILE* open_stats_log_file(const char* const filename, time_t);
    void dump_statistics();

    bool enabled = false;
    SF_LIST* currBuckets = nullptr;
    SF_LIST* logBuckets = nullptr;
    FILE* appfp = nullptr;
    size_t appSize = 0;
    time_t appTime = 0;
    time_t bucketStart = 0;
    time_t bucketInterval = 0;
    time_t bucketEnd = 0;
    size_t rollSize = 0;
    time_t rollPeriod = 0;
    const char* appid_stats_filename = nullptr;
};

#endif

