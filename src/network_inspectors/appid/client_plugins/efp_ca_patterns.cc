//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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

// efp_ca_patterns.cc author Cliff Judge <cljudge@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "efp_ca_patterns.h"

#include "log/messages.h"
#include "utils/util.h"
#include "appid_debug.h"

using namespace snort;

void EfpCaPatternMatchers::add_efp_ca_pattern(AppId app_id, const std::string& pattern_str,
    uint8_t confidence)
{
    EfpCaPattern* new_efp_ca_pattern = new EfpCaPattern(app_id, pattern_str, confidence);
    efp_ca_load_list.push_back(new_efp_ca_pattern);
}

static int efp_ca_pattern_match(void* id, void*, int, void* data, void*)
{
    EfpCaPatternList* efp_ca_match_list = (EfpCaPatternList *)data;
    efp_ca_match_list->push_back((EfpCaPattern *)id);
    return 0;
}

AppId EfpCaPatternMatchers::match_efp_ca_pattern(const std::string& pattern,
    uint8_t reported_confidence)
{
    EfpCaPatternList* efp_ca_match_list = new EfpCaPatternList();
    EfpCaPattern* best_match = nullptr;

    efp_ca_pattern_matcher.find_all(pattern.data(), pattern.size(), efp_ca_pattern_match,
        false, efp_ca_match_list);

    for (auto &mp : *efp_ca_match_list)
    {
        if (reported_confidence >= mp->confidence)
        {
            if (!best_match or (mp->pattern.size() > best_match->pattern.size() or
                (mp->pattern.size() == best_match->pattern.size() and
                mp->confidence > best_match->confidence)))
            {
                best_match = mp;
            }
        }
    }
    AppId ret_app_id = APP_ID_NONE;
    if (best_match)
        ret_app_id = best_match->app_id;

    delete efp_ca_match_list;

    return ret_app_id;
}

EfpCaPatternMatchers::~EfpCaPatternMatchers()
{
    for (auto& p : efp_ca_load_list)
        delete p;
    efp_ca_load_list.clear();
}

void EfpCaPatternMatchers::finalize_patterns()
{
    for (auto& p : efp_ca_load_list)
    {
        efp_ca_pattern_matcher.add(p->pattern.data(), p->pattern.size(), p, true);

        #ifdef REG_TEST
            LogMessage("Adding EFP Client App pattern %d %s %d\n",
                p->app_id, p->pattern.c_str(), p->confidence);
        #endif
    }
    efp_ca_pattern_matcher.prep();
}

void EfpCaPatternMatchers::reload_patterns()
{
    efp_ca_pattern_matcher.reload();
}

