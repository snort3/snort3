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

#include "main/thread.h"
#include "utils/util.h"
#include "application_ids.h"
#include "application_ids.h"
#include "app_info_table.h"

class AppIdSession;
class OdpContext;

struct AppidCPUProfilerStats {
    std::string app_name;
    uint64_t processing_time    = 0;
    uint64_t processed_packets  = 0;
    uint32_t per_appid_sessions = 0;

    AppidCPUProfilerStats(const char* app_name, uint64_t processing_time, uint64_t processed_packets, uint32_t per_appid_sessions) :
        app_name(app_name), processing_time(processing_time), processed_packets(processed_packets), per_appid_sessions (per_appid_sessions)
    { }
};

class AppidCPUProfilingManager {
private:
    typedef std::unordered_map<AppId, AppidCPUProfilerStats> AppidCPUProfilingTable;
    AppidCPUProfilingTable appid_cpu_profiling_table;
        
public:
    AppidCPUProfilingManager();
    
    void stats_bucket_insert(AppId appid, const char* app_name, uint64_t processing_time, uint64_t processed_packets);
    void insert_appid_cpu_profiler_record(AppId appId, const AppidCPUProfilerStats& stats);
    void check_appid_cpu_profiler_table_entry(const AppIdSession* asd, AppId service_id, AppId client_id, AppId payload_id, AppId misc_id);
    void check_appid_cpu_profiler_table_entry(const AppIdSession* asd, AppId payload_id);

    void display_appid_cpu_profiler_table();
    void display_appid_cpu_profiler_table(AppId appid);
    
    void cleanup_appid_cpu_profiler_table();
};
#endif
