//--------------------------------------------------------------------------
// Copyright (C) 2017-2024 Cisco and/or its affiliates. All rights reserved.
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

#include <string>

#include "application_ids.h"
#include "framework/counts.h"

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
    static void add_app_peg_info(std::string app_name, AppId);
    static void init_pegs();
    static void cleanup_pegs();
    static void init_peg_info();
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
};
#endif

