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

// app_cpu_profiling_table.cc author Umang Sharma <umasharm@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "log/text_log.h"
#include "time/packet_time.h"
#include <iomanip>
#include <sstream>
#include <queue>
#include <algorithm>

#include "appid_session.h"
#include "appid_cpu_profile_table.h"

using namespace snort;

#define TABLE_HEADER(num_rows) "AppId Performance Statistics (top %d appids)\n===================================================================================================================================================\n", num_rows
static const char* columns = " AppId   App Name                   Usecs       Pkts     AvgUsecs/Pkt     Sessions     AvgUsecs/Sess     MaxPkts/Sess     MaxUsecs/Sess     %%/Total\n";
static const char* partition = "---------------------------------------------------------------------------------------------------------------------------------------------------\n";

static std::string FormatWithCommas(uint64_t value)
{
    std::string numStr = std::to_string(value);
    int insertPosition = numStr.length() - 3;
    while (insertPosition > 0) 
    {
        numStr.insert(insertPosition, ",");
        insertPosition -= 3;
    }
    return numStr;
}

// Comparator for priority queue based on avg_processing_time/session
struct CompareByAvgProcessingTime {
    bool operator()(const std::pair<AppId, AppidCPUProfilerStats>& a, const std::pair<AppId, AppidCPUProfilerStats>& b) const {
        if (!a.second.per_appid_sessions or !b.second.per_appid_sessions)
            return false;

        return a.second.processing_time/a.second.per_appid_sessions < b.second.processing_time/b.second.per_appid_sessions;
    }
};

AppidCpuTableDisplayStatus AppidCPUProfilingManager::display_appid_cpu_profiler_table(AppId appid, OdpContext& odp_ctxt)
{
    if (odp_ctxt.is_appid_cpu_profiler_running())
        return DISPLAY_ERROR_APPID_PROFILER_RUNNING;
    else if (appid_cpu_profiling_table.empty())
        return DISPLAY_ERROR_TABLE_EMPTY;

    auto bucket = appid_cpu_profiling_table.find(appid);

    if (bucket != appid_cpu_profiling_table.end())
    {
        appid_log(nullptr, TRACE_INFO_LEVEL, TABLE_HEADER(1));
        appid_log(nullptr, TRACE_INFO_LEVEL, columns);
        appid_log(nullptr, TRACE_INFO_LEVEL, partition);

        appid_log(nullptr, TRACE_INFO_LEVEL, " %5d   %-15.15s   %14.14s %10.10s  %15.14s  %11.11s  %16.14s  %15.14s   %15.14s  %10.2f\n",
                appid, bucket->second.app_name.c_str(), FormatWithCommas(bucket->second.processing_time).c_str(), FormatWithCommas(bucket->second.processed_packets).c_str(), 
                FormatWithCommas(bucket->second.processing_time/bucket->second.processed_packets).c_str(), FormatWithCommas(bucket->second.per_appid_sessions).c_str(), 
                FormatWithCommas(bucket->second.processing_time/bucket->second.per_appid_sessions).c_str(), FormatWithCommas(bucket->second.max_processed_pkts_per_session).c_str(), 
                FormatWithCommas(bucket->second.max_processing_time_per_session).c_str(), (static_cast<float>(bucket->second.processing_time)/total_processing_time)*100);
    }
    else
    {
        appid_log(nullptr, TRACE_INFO_LEVEL,"Appid %d not found in the table\n", appid);
    }
    return DISPLAY_SUCCESS;
}

AppidCpuTableDisplayStatus AppidCPUProfilingManager::display_appid_cpu_profiler_table(OdpContext& odp_ctxt, uint32_t display_rows_limit, bool override_running_flag)
{
    if (odp_ctxt.is_appid_cpu_profiler_running() and !override_running_flag)
        return DISPLAY_ERROR_APPID_PROFILER_RUNNING;
    else if (appid_cpu_profiling_table.empty())
        return DISPLAY_ERROR_TABLE_EMPTY;

    std::priority_queue<std::pair<AppId, AppidCPUProfilerStats>, std::vector<std::pair<AppId, AppidCPUProfilerStats>>, CompareByAvgProcessingTime> sorted_appid_cpu_profiler_table;

    for (const auto& entry : appid_cpu_profiling_table) 
        sorted_appid_cpu_profiler_table.push(entry);

    display_rows_limit = static_cast<uint32_t>(std::min({static_cast<size_t>(display_rows_limit), sorted_appid_cpu_profiler_table.size(), static_cast<size_t>(APPID_CPU_PROFILER_MAX_DISPLAY_ROWS)}));
    appid_log(nullptr, TRACE_INFO_LEVEL, TABLE_HEADER(display_rows_limit));
    appid_log(nullptr, TRACE_INFO_LEVEL, columns);
    appid_log(nullptr, TRACE_INFO_LEVEL, partition);
    
    uint32_t rows_displayed = 0;

    while (!sorted_appid_cpu_profiler_table.empty() and rows_displayed < display_rows_limit)
    {
        auto entry = sorted_appid_cpu_profiler_table.top();
        sorted_appid_cpu_profiler_table.pop();
        if (!entry.second.processed_packets or !entry.second.per_appid_sessions)
            continue;
            
        appid_log(nullptr, TRACE_INFO_LEVEL, " %5d   %-15.15s   %14.14s %10.10s  %15.14s  %11.11s  %16.14s  %15.14s   %15.14s  %10.2f\n",
                entry.first, entry.second.app_name.c_str(), FormatWithCommas(entry.second.processing_time).c_str(), FormatWithCommas(entry.second.processed_packets).c_str(), 
                FormatWithCommas(entry.second.processing_time/entry.second.processed_packets).c_str(), FormatWithCommas(entry.second.per_appid_sessions).c_str(), 
                FormatWithCommas(entry.second.processing_time/entry.second.per_appid_sessions).c_str(), FormatWithCommas(entry.second.max_processed_pkts_per_session).c_str(),
                FormatWithCommas(entry.second.max_processing_time_per_session).c_str(), (static_cast<float>(entry.second.processing_time)/total_processing_time)*100);

        rows_displayed += 1;
    } 

    appid_log(nullptr, TRACE_INFO_LEVEL, partition);

    appid_log(nullptr, TRACE_INFO_LEVEL, "Totals(all_sessions)    : %15.15s %10.10s  %15.14s   %10.10s   %15.15s  %15.14s  %16.15s   %9d\n",
            FormatWithCommas(total_processing_time).c_str(), FormatWithCommas(total_processed_packets).c_str(),  FormatWithCommas(total_processing_time/total_processed_packets).c_str(),
            FormatWithCommas(total_per_appid_sessions).c_str(), FormatWithCommas(total_processing_time/total_per_appid_sessions).c_str(),
            FormatWithCommas(max_processed_pkts_per_session).c_str(), FormatWithCommas(max_processing_time_per_session).c_str(), 100);

    return DISPLAY_SUCCESS;
}

void AppidCPUProfilingManager::cleanup_appid_cpu_profiler_table()
{ 
    std::lock_guard<std::mutex> lock(appid_cpu_profiler_mutex);
    appid_cpu_profiling_table.clear();
    total_processing_time = 0;
    total_processed_packets = 0;
    total_per_appid_sessions = 0;
    max_processing_time_per_session = 0;
    max_processed_pkts_per_session = 0;
}

void AppidCPUProfilingManager::update_totals(const AppidCPUProfilerStats& stats)
{
    total_processing_time += stats.processing_time;
    total_processed_packets += stats.processed_packets;
    total_per_appid_sessions += stats.per_appid_sessions;
    if (stats.max_processed_pkts_per_session >= max_processed_pkts_per_session)
        max_processed_pkts_per_session = stats.max_processed_pkts_per_session;
    if (stats.max_processing_time_per_session >= max_processing_time_per_session)
        max_processing_time_per_session = stats.max_processing_time_per_session;
}

void AppidCPUProfilingManager::insert_appid_cpu_profiler_record(AppId appId, const AppidCPUProfilerStats& stats)
{
    std::lock_guard<std::mutex> lock(appid_cpu_profiler_mutex);

    auto it = appid_cpu_profiling_table.find(appId);
    if (it == appid_cpu_profiling_table.end()) 
    {
        appid_cpu_profiling_table.emplace(appId, stats);
    }
    else 
    {
        it->second.processing_time += stats.processing_time;
        it->second.processed_packets += stats.processed_packets;
        it->second.per_appid_sessions += 1;
        if (stats.processed_packets > it->second.max_processed_pkts_per_session)
            it->second.max_processed_pkts_per_session = stats.processed_packets;

        if (stats.processing_time > it->second.max_processing_time_per_session)
            it->second.max_processing_time_per_session = stats.processing_time;
    }
    update_totals(stats);
}

void AppidCPUProfilingManager::check_appid_cpu_profiler_table_entry(const AppIdSession* asd, AppId payload_id)
{
    if (payload_id > APP_ID_NONE)
    {
        const char* app_name = asd->get_odp_ctxt().get_app_info_mgr().get_app_name(payload_id);
        if (app_name == nullptr) 
            app_name = "unknown";

        stats_bucket_insert(payload_id, app_name, asd->stats.prev_payload_processing_time, asd->stats.prev_payload_processing_packets);
    }
}

void AppidCPUProfilingManager::stats_bucket_insert(AppId appid, const char* app_name, uint64_t processing_time, uint64_t processed_packets)
{
    if (!processed_packets or !processing_time)
    {
        appid_log(nullptr, TRACE_INFO_LEVEL, "appid: processed packets/time are NULL for appid : %d , app_name : %s , processing time :%lu \n", appid, app_name, processing_time);
        return;
    }
        
    AppidCPUProfilerStats stats(app_name, processing_time, processed_packets, 1);
    insert_appid_cpu_profiler_record(appid, stats);
}

void AppidCPUProfilingManager::check_appid_cpu_profiler_table_entry(const AppIdSession* asd,AppId service_id, AppId client_id, AppId payload_id, AppId misc_id)
{
    if (!asd->stats.processing_time or !asd->stats.cpu_profiler_pkt_count)
        return;

    if (service_id > APP_ID_NONE)
    {
        const char* app_name = asd->get_odp_ctxt().get_app_info_mgr().get_app_name(service_id);
        if (app_name == nullptr)
            app_name = "unknown";

        stats_bucket_insert(service_id, app_name, asd->stats.processing_time, asd->stats.cpu_profiler_pkt_count);
    }
    if (client_id > APP_ID_NONE and client_id != service_id){
        const char* app_name = asd->get_odp_ctxt().get_app_info_mgr().get_app_name(client_id);
        if (app_name == nullptr)
            app_name = "unknown";

        stats_bucket_insert(client_id, app_name, asd->stats.processing_time, asd->stats.cpu_profiler_pkt_count);
    }
    if (payload_id > APP_ID_NONE and payload_id != service_id and payload_id != client_id)
    {
        const char* app_name = asd->get_odp_ctxt().get_app_info_mgr().get_app_name(payload_id);
        if (app_name == nullptr)
            app_name = "unknown";

        stats_bucket_insert(payload_id, app_name, asd->stats.processing_time - asd->stats.prev_payload_processing_time, asd->stats.cpu_profiler_pkt_count - asd->stats.prev_payload_processing_packets);
    }
    if (misc_id > APP_ID_NONE and misc_id != service_id and misc_id != client_id and misc_id != payload_id) 
    {
        const char* app_name = asd->get_odp_ctxt().get_app_info_mgr().get_app_name(misc_id);
        if (app_name == nullptr)
            app_name = "unknown";

        stats_bucket_insert(misc_id, app_name, asd->stats.processing_time, asd->stats.cpu_profiler_pkt_count);
    }
}
