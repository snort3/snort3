//--------------------------------------------------------------------------
// Copyright (C) 2022 Cisco and/or its affiliates. All rights reserved.
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

// alpn_patterns.cc author Pranav Bhalerao <prbhaler@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "alpn_patterns.h"

#include <algorithm>

#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "utils/util.h"
#include "appid_debug.h"
#include "appid_inspector.h"

using namespace snort;
using namespace std;

void AlpnPatternMatchers::add_alpn_pattern(AppId app_id, const string& pattern_str,
    const string& detector)
{
    auto match = find_if(alpn_load_list.begin(), alpn_load_list.end(),
        [pattern_str] (AlpnPattern* alpn) { return alpn->pattern == pattern_str; });
    if (match != alpn_load_list.end())
    {
        if ((*match)->app_id != app_id)
            WarningMessage("appid: detector %s - alpn '%s' for service app %d is already "
                "mapped to service app %d\n", detector.c_str(), (*match)->pattern.c_str(), app_id,
                (*match)->app_id);
    }
    else
    {
        AlpnPattern* new_alpn_pattern = new AlpnPattern(app_id, pattern_str);
        alpn_load_list.push_back(new_alpn_pattern);
    }
}

static int alpn_pattern_match(void* id, void*, int, void* data, void*)
{
    AlpnPatternList* alpn_match_list = (AlpnPatternList *)data;
    alpn_match_list->push_back((AlpnPattern *)id);
    return 0;
}

AppId AlpnPatternMatchers::match_alpn_pattern(const string& pattern)
{
    AlpnPatternList* alpn_match_list = new AlpnPatternList();
    AlpnPattern* best_match = nullptr;

    alpn_pattern_matcher.find_all(pattern.data(), pattern.size(), alpn_pattern_match,
        false, alpn_match_list);

    for (auto &mp : *alpn_match_list)
    {
        if (mp->pattern.size() == pattern.size())
        {
            best_match = mp;
        }
        else if (!best_match or (mp->pattern.size() > best_match->pattern.size()))
        {
            best_match = mp;
            continue;
        }
    }

    AppId ret_app_id = APP_ID_NONE;
    if (best_match)
        ret_app_id = best_match->app_id;

    delete alpn_match_list;

    return ret_app_id;
}

AlpnPatternMatchers::~AlpnPatternMatchers()
{
    for (auto& p : alpn_load_list)
        delete p;
    alpn_load_list.clear();
}

void AlpnPatternMatchers::finalize_patterns()
{
    for (auto& p : alpn_load_list)
    {
        alpn_pattern_matcher.add(p->pattern.data(), p->pattern.size(), p, true);

        #ifdef REG_TEST
        AppIdInspector* inspector = 
            (AppIdInspector*) InspectorManager::get_inspector(MOD_NAME, true);
        if (inspector and inspector->get_ctxt().config.log_alpn_service_mappings)
            LogMessage("Adding ALPN service App pattern %d %s\n",
                p->app_id, p->pattern.c_str());
        #endif
    }
    alpn_pattern_matcher.prep();
}

void AlpnPatternMatchers::reload_patterns()
{
    alpn_pattern_matcher.reload();
}

