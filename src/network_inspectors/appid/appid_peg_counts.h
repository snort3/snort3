//--------------------------------------------------------------------------
// Copyright (C) 2017-2022 Cisco and/or its affiliates. All rights reserved.
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

// appid_peg_counts.h author davis mcpherson <davmcphe@cisco.com>

#ifndef APPID_PEG_COUNTS_H
#define APPID_PEG_COUNTS_H

// The AppIdPegCounts class provides an API to manage the dynamic peg counts maintained by AppId.
// AppId defines peg counts that are known at compile time in appid_module.h. The counts here are
// for each application that it can detect.  This list of applications is not known until the
// appMapping.data configuration file is loaded so methods are provided to dynamically
// initialize the PegCount array when that file is loaded.
// Functions for incrementing the peg counts are also provided.
// The AppId can be a very large number so using it as the array index is not practical.
// Packet threads are using dynamic pegs, and std::map that is used to translate the AppId to its
// array index.
// Only the main thread is using a static array.

#include <unordered_map>
#include <vector>

#include "application_ids.h"
#include "app_info_table.h"
#include "framework/counts.h"
#include "log/messages.h"
#include "main/thread.h"
#include "utils/util.h"

struct AppIdStats
{
    PegCount packets;
    PegCount processed_packets;
    PegCount ignored_packets;
    PegCount total_sessions;
    PegCount service_cache_prunes;
    PegCount service_cache_adds;
    PegCount service_cache_removes;
    PegCount odp_reload_ignored_pkts;
    PegCount tp_reload_ignored_pkts;
    PegCount bytes_in_use;
    PegCount items_in_use;
};

class AppIdPegCounts
{
public:
    enum DetectorPegs
    {
        SERVICE_DETECTS = 0,
        CLIENT_DETECTS,
        USER_DETECTS,
        PAYLOAD_DETECTS,
        MISC_DETECTS,
        REFERRED_DETECTS,
        NUM_APPID_DETECTOR_PEGS
    };

    class AppIdDynamicPeg
    {
    public:
        PegCount stats[DetectorPegs::NUM_APPID_DETECTOR_PEGS] = { };

        bool all_zeros()
        {
            return !memcmp(stats, &all_zeroed_peg, sizeof(stats));
        }

        void print(const char* app, char* buf, int buf_size)
        {
            snprintf(buf, buf_size, "%25.25s: " FMTu64("-10") " " FMTu64("-10") " " FMTu64("-10")
                " " FMTu64("-10") " " FMTu64("-10") " " FMTu64("-10"), app,
                stats[SERVICE_DETECTS], stats[CLIENT_DETECTS], stats[USER_DETECTS],
                stats[PAYLOAD_DETECTS], stats[MISC_DETECTS], stats[REFERRED_DETECTS]);
        }
    };

    static void add_app_peg_info(std::string app_name, AppId);
    static void init_pegs();
    static void cleanup_pegs();
    static void cleanup_peg_info();
    static void cleanup_dynamic_sum();

    static void inc_service_count(AppId id);
    static void inc_client_count(AppId id);
    static void inc_payload_count(AppId id);
    static void inc_user_count(AppId id);
    static void inc_misc_count(AppId id);
    static void inc_referred_count(AppId id);

    static void sum_stats();
    static void print();

private:
    static std::unordered_map<AppId, uint32_t> appid_detector_pegs_idx;
    static std::vector<std::string> appid_detectors_info;
    static AppIdDynamicPeg appid_dynamic_sum[SF_APPID_MAX+1];
    static THREAD_LOCAL std::vector<AppIdDynamicPeg>* appid_peg_counts;
    static uint32_t get_stats_index(AppId id);
    static AppIdDynamicPeg zeroed_peg;
    static PegCount all_zeroed_peg[DetectorPegs::NUM_APPID_DETECTOR_PEGS];
};
#endif

