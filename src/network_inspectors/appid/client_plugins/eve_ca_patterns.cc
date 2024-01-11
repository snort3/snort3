//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

// eve_ca_patterns.cc author Cliff Judge <cljudge@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eve_ca_patterns.h"

#include <algorithm>

#include "managers/inspector_manager.h"
#include "utils/util.h"
#include "appid_debug.h"
#include "appid_inspector.h"

using namespace snort;
using namespace std;

void EveCaPatternMatchers::add_eve_ca_pattern(AppId app_id, const string& pattern_str,
    uint8_t confidence, const string& detector)
{
    auto match = find_if(eve_ca_load_list.begin(), eve_ca_load_list.end(),
        [pattern_str] (EveCaPattern* eve_ca) { return eve_ca->pattern == pattern_str; });
    if (match != eve_ca_load_list.end())
    {
        if ((*match)->app_id != app_id)
            appid_log(nullptr, TRACE_WARNING_LEVEL, "appid: detector %s - process name '%s' for client app %d is already "
                "mapped to client app %d\n", detector.c_str(), (*match)->pattern.c_str(), app_id,
                (*match)->app_id);
    }
    else
    {
        EveCaPattern* new_eve_ca_pattern = new EveCaPattern(app_id, pattern_str, confidence);
        eve_ca_load_list.push_back(new_eve_ca_pattern);
    }
}

static int eve_ca_pattern_match(void* id, void*, int, void* data, void*)
{
    EveCaPatternList* eve_ca_match_list = (EveCaPatternList *)data;
    eve_ca_match_list->push_back((EveCaPattern *)id);
    return 0;
}

AppId EveCaPatternMatchers::match_eve_ca_pattern(const string& pattern,
    uint8_t reported_confidence)
{
    EveCaPatternList* eve_ca_match_list = new EveCaPatternList();
    EveCaPattern* best_match = nullptr;

    eve_ca_pattern_matcher.find_all(pattern.data(), pattern.size(), eve_ca_pattern_match,
        false, eve_ca_match_list);

    for (auto &mp : *eve_ca_match_list)
    {
        if (mp->pattern.size() == pattern.size())
        {
            if (reported_confidence >= mp->confidence)
                best_match = mp;
            else if (best_match)
                best_match = nullptr;
            break;
        }
        else if ((reported_confidence >= mp->confidence) and
            (!best_match or (mp->pattern.size() > best_match->pattern.size())))
        {
            best_match = mp;
            continue;
        }
    }
    AppId ret_app_id = APP_ID_NONE;
    if (best_match)
        ret_app_id = best_match->app_id;

    delete eve_ca_match_list;

    return ret_app_id;
}

EveCaPatternMatchers::~EveCaPatternMatchers()
{
    for (auto& p : eve_ca_load_list)
        delete p;
    eve_ca_load_list.clear();
}

void EveCaPatternMatchers::finalize_patterns()
{
    for (auto& p : eve_ca_load_list)
    {
        eve_ca_pattern_matcher.add(p->pattern.data(), p->pattern.size(), p, true);

        #ifdef REG_TEST
        AppIdInspector* inspector =
            (AppIdInspector*) InspectorManager::get_inspector(MOD_NAME, true);
        if (inspector and inspector->get_ctxt().config.log_eve_process_client_mappings)
            appid_log(nullptr, TRACE_INFO_LEVEL, "Adding EVE Client App pattern %d %s %d\n",
                p->app_id, p->pattern.c_str(), p->confidence);
        #endif
    }
    eve_ca_pattern_matcher.prep();
}

void EveCaPatternMatchers::reload_patterns()
{
    eve_ca_pattern_matcher.reload();
}

unsigned EveCaPatternMatchers::get_pattern_count()
{
    return eve_ca_load_list.size();
}
