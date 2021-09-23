//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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

// efp_ca_patterns.h author Cliff Judge <cljudge@cisco.com>

#ifndef EFP_CA_PATTERNS_H
#define EFP_CA_PATTERNS_H

#include <vector>

#include "search_engines/search_tool.h"
#include "application_ids.h"

struct EfpCaPattern
{
    const AppId app_id;
    const std::string pattern;
    const uint8_t confidence;

    EfpCaPattern(AppId id, const std::string& name, uint8_t conf) : app_id(id), pattern(name),
        confidence(conf) {}

    ~EfpCaPattern() {}
};

typedef std::vector<EfpCaPattern*> EfpCaPatternList;

class EfpCaPatternMatchers
{
public:
    ~EfpCaPatternMatchers();
    AppId match_efp_ca_pattern(const std::string&, uint8_t);
    void add_efp_ca_pattern(AppId, const std::string&, uint8_t);
    void finalize_patterns();
    void reload_patterns();

private:
    snort::SearchTool efp_ca_pattern_matcher = snort::SearchTool();
    EfpCaPatternList efp_ca_load_list;
};

#endif

