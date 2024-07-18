//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// app_cpu_profile_table.h author Umang Sharma <umasharm@cisco.com>

#ifndef APP_CPU_PROFILE_TABLE_H
#define APP_CPU_PROFILE_TABLE_H

#include <unordered_map>
#include <vector>
#include <mutex>

#include "main/thread.h"
#include "utils/util.h"
#include "application_ids.h"
#include "application_ids.h"
#include "app_info_table.h"

class AppIdSession;
class OdpContext;
class ControlConn;

enum AppidCPUProfilerOutputType
{
    OUPUT_LOGFILE = 0,
    OUTPUT_CONSOLE
};

#define APPID_CPU_PROFILER_DEFAULT_DISPLAY_ROWS 100
#define APPID_CPU_PROFILER_MAX_DISPLAY_ROWS 2000

enum AppidCpuTableDisplayStatus {
    DISPLAY_SUCCESS = 0,
    DISPLAY_ERROR_TABLE_EMPTY,
    DISPLAY_ERROR_APPID_PROFILER_RUNNING
};

struct AppidCPUProfilerStats {
    std::string app_name;
    uint64_t processing_time    = 0;
    uint64_t processed_packets  = 0;
    uint32_t per_appid_sessions = 0;
    uint64_t max_processing_time_per_session = 0;
    uint64_t max_processed_pkts_per_session = 0;

    AppidCPUProfilerStats(const char* app_name, uint64_t processing_time, uint64_t processed_packets, uint32_t per_appid_sessions) :
        app_name(app_name), processing_time(processing_time), processed_packets(processed_packets), per_appid_sessions(per_appid_sessions),
        max_processing_time_per_session(processing_time), max_processed_pkts_per_session(processed_packets)
    { }
};

class AppidCPUProfilingManager {
private:
    using AppidCPUProfilingTable = std::unordered_map<AppId, AppidCPUProfilerStats>;
    AppidCPUProfilingTable appid_cpu_profiling_table;
    std::mutex appid_cpu_profiler_mutex;
    uint64_t total_processing_time = 0;
    uint64_t total_processed_packets = 0;
    uint32_t total_per_appid_sessions = 0;
    uint64_t max_processing_time_per_session = 0;
    uint64_t max_processed_pkts_per_session = 0;

public:
    AppidCPUProfilingManager() = default;

    void stats_bucket_insert(AppId appid, const char* app_name, uint64_t processing_time, uint64_t processed_packets);
    void insert_appid_cpu_profiler_record(AppId appId, const AppidCPUProfilerStats& stats);
    void check_appid_cpu_profiler_table_entry(const AppIdSession* asd, AppId service_id, AppId client_id, AppId payload_id, AppId misc_id);
    void check_appid_cpu_profiler_table_entry(const AppIdSession* asd, AppId payload_id);
    void update_totals(const AppidCPUProfilerStats& stats);

    AppidCpuTableDisplayStatus display_appid_cpu_profiler_table(OdpContext&, uint32_t display_rows_limit = APPID_CPU_PROFILER_DEFAULT_DISPLAY_ROWS,
                                                                bool override_running_flag = false, ControlConn* control_conn = nullptr);
    AppidCpuTableDisplayStatus display_appid_cpu_profiler_table(AppId, OdpContext&, ControlConn* control_conn = nullptr);

    void cleanup_appid_cpu_profiler_table();
};
#endif
