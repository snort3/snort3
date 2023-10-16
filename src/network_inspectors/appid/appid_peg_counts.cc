//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// appid_peg_counts.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_peg_counts.h"

#include <algorithm>
#include <string>

#include "framework/inspector.h"
#include "main/thread_config.h"
#include "utils/stats.h"

using namespace snort;

THREAD_LOCAL AppIdPegCounts::AppIdDynamicPeg* AppIdPegCounts::unknown_appids_peg;
THREAD_LOCAL std::unordered_map<AppId, AppIdPegCounts::AppIdDynamicPeg>* AppIdPegCounts::appid_peg_counts;
std::unordered_map<AppId, std::pair<std::string, uint32_t>> AppIdPegCounts::appid_peg_ids;
AppIdPegCounts::AppIdDynamicPeg AppIdPegCounts::appid_dynamic_sum[SF_APPID_MAX + 1];
AppIdPegCounts::AppIdDynamicPeg AppIdPegCounts::zeroed_peg;
PegCount AppIdPegCounts::all_zeroed_peg[DetectorPegs::NUM_APPID_DETECTOR_PEGS] = {};

static std::mutex dynamic_stats_mutex;

void AppIdPegCounts::init_pegs()
{
    assert(!appid_peg_counts);
    appid_peg_counts = new std::unordered_map<AppId, AppIdPegCounts::AppIdDynamicPeg>();

    for (auto& appid : appid_peg_ids)
    {
        appid_peg_counts->emplace(appid.first, zeroed_peg);
    }
    unknown_appids_peg = new AppIdDynamicPeg(zeroed_peg);
}

void AppIdPegCounts::cleanup_pegs()
{
    delete appid_peg_counts;
    appid_peg_counts = nullptr;
    delete unknown_appids_peg;
    unknown_appids_peg = nullptr;
}

void AppIdPegCounts::cleanup_peg_info()
{
    appid_peg_ids.clear();
}

void AppIdPegCounts::cleanup_dynamic_sum()
{
    const std::lock_guard<std::mutex> _lock(dynamic_stats_mutex);

    for (unsigned app_num = 0; app_num < SF_APPID_MAX; app_num++)
    {
        memset(appid_dynamic_sum[app_num].stats, 0, sizeof(PegCount) *
            DetectorPegs::NUM_APPID_DETECTOR_PEGS);
    }

    if (appid_peg_counts)
    {
        for (auto& peg : (*appid_peg_counts))
        {
            memset(&peg.second.stats, 0, sizeof(PegCount) * DetectorPegs::NUM_APPID_DETECTOR_PEGS);
        }
    }

    // reset unknown_app stats
    memset(appid_dynamic_sum[SF_APPID_MAX].stats, 0, sizeof(PegCount) *
        DetectorPegs::NUM_APPID_DETECTOR_PEGS);
    if (unknown_appids_peg)
        memset(&unknown_appids_peg->stats, 0, sizeof(PegCount) * DetectorPegs::NUM_APPID_DETECTOR_PEGS);

}

void AppIdPegCounts::add_app_peg_info(std::string app_name, AppId app_id)
{
    std::replace(app_name.begin(), app_name.end(), ' ', '_');

    appid_peg_ids.emplace(app_id, std::make_pair(app_name, appid_peg_ids.size()));
}

void AppIdPegCounts::sum_stats()
{
    if (!appid_peg_counts or !unknown_appids_peg)
        return;

    const std::lock_guard<std::mutex> _lock(dynamic_stats_mutex);

    for (auto& peg : (*appid_peg_counts))
    {
        auto dyn_indx = appid_peg_ids[peg.first].second;
        for (unsigned j = 0; j < DetectorPegs::NUM_APPID_DETECTOR_PEGS; ++j)
            appid_dynamic_sum[dyn_indx].stats[j] += peg.second.stats[j];

        peg.second.zero_out();
    }

    // unknown_app stats
    for (unsigned j = 0; j < DetectorPegs::NUM_APPID_DETECTOR_PEGS; ++j)
        appid_dynamic_sum[SF_APPID_MAX].stats[j] += unknown_appids_peg->stats[j];

    unknown_appids_peg->zero_out();
}

void AppIdPegCounts::inc_service_count(AppId id)
{
    auto peg = appid_peg_counts->find(id);
    if (peg != appid_peg_counts->end())
        peg->second.stats[DetectorPegs::SERVICE_DETECTS]++;
    else
        unknown_appids_peg->stats[DetectorPegs::SERVICE_DETECTS]++;
}

void AppIdPegCounts::inc_client_count(AppId id)
{
    auto peg = appid_peg_counts->find(id);
    if (peg != appid_peg_counts->end())
        peg->second.stats[DetectorPegs::CLIENT_DETECTS]++;
    else
        unknown_appids_peg->stats[DetectorPegs::CLIENT_DETECTS]++;
}

void AppIdPegCounts::inc_payload_count(AppId id)
{
    auto peg = appid_peg_counts->find(id);
    if (peg != appid_peg_counts->end())
        peg->second.stats[DetectorPegs::PAYLOAD_DETECTS]++;
    else
        unknown_appids_peg->stats[DetectorPegs::PAYLOAD_DETECTS]++;
}

void AppIdPegCounts::inc_user_count(AppId id)
{
    auto peg = appid_peg_counts->find(id);
    if (peg != appid_peg_counts->end())
        peg->second.stats[DetectorPegs::USER_DETECTS]++;
    else
        unknown_appids_peg->stats[DetectorPegs::USER_DETECTS]++;
}

void AppIdPegCounts::inc_misc_count(AppId id)
{
    auto peg = appid_peg_counts->find(id);
    if (peg != appid_peg_counts->end())
        peg->second.stats[DetectorPegs::MISC_DETECTS]++;
    else
        unknown_appids_peg->stats[DetectorPegs::MISC_DETECTS]++;
}

void AppIdPegCounts::inc_referred_count(AppId id)
{
    auto peg = appid_peg_counts->find(id);
    if (peg != appid_peg_counts->end())
        peg->second.stats[DetectorPegs::REFERRED_DETECTS]++;
    else
        unknown_appids_peg->stats[DetectorPegs::REFERRED_DETECTS]++;
}

void AppIdPegCounts::print()
{
    bool print = false;
    unsigned app_num = AppIdPegCounts::appid_peg_ids.size();

    std::unordered_map<uint32_t, std::string*> tmp_sorting_map;

    for (auto& det_info : AppIdPegCounts::appid_peg_ids)
    {
        AppIdDynamicPeg* pegs = &appid_dynamic_sum[det_info.second.second];
        if (!pegs->all_zeros())
        {
            print |= true;
        }
        tmp_sorting_map.emplace(det_info.second.second, &det_info.second.first);
    }

    AppIdDynamicPeg* unknown_pegs = &appid_dynamic_sum[SF_APPID_MAX];
    if (!print && unknown_pegs->all_zeros())
        return;

    LogLabel("Appid Statistics");
    LogLabel("detected apps and services");

    char buff[120];
    snprintf(buff, sizeof(buff), "%25.25s: %-10s %-10s %-10s %-10s %-10s %-10s",
        "Application", "Services", "Clients", "Users", "Payloads", "Misc", "Referred");
    LogText(buff);

    for (uint32_t i = 0; i < app_num; i++)
    {
        AppIdDynamicPeg* pegs = &appid_dynamic_sum[i];
        if (pegs->all_zeros())
            continue;

        pegs->print(tmp_sorting_map[i]->c_str(), buff, sizeof(buff));
        LogText(buff);
    }

    if (!unknown_pegs->all_zeros())
    {
        unknown_pegs->print("unknown", buff, sizeof(buff));
        LogText(buff);
    }
}
