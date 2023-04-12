//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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

// eve_ca_patterns.h author Cliff Judge <cljudge@cisco.com>

#ifndef EVE_CA_PATTERNS_H
#define EVE_CA_PATTERNS_H

#include <vector>

#include "search_engines/search_tool.h"
#include "application_ids.h"

struct EveCaPattern
{
    const AppId app_id;
    const std::string pattern;
    const uint8_t confidence;

    EveCaPattern(AppId id, const std::string& name, uint8_t conf) : app_id(id), pattern(name),
        confidence(conf) {}

    ~EveCaPattern() {}
};

typedef std::vector<EveCaPattern*> EveCaPatternList;

class EveCaPatternMatchers
{
public:
    ~EveCaPatternMatchers();
    AppId match_eve_ca_pattern(const std::string&, uint8_t);
    void add_eve_ca_pattern(AppId, const std::string&, uint8_t, const std::string&);
    void finalize_patterns();
    void reload_patterns();
    unsigned get_pattern_count();

    const EveCaPatternList& get_eve_ca_load_list() const { return eve_ca_load_list; }

private:
    snort::SearchTool eve_ca_pattern_matcher = snort::SearchTool();
    EveCaPatternList eve_ca_load_list;
};

#endif

