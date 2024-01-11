//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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

// alpn_patterns.h author Pranav Bhalerao <prbhaler@cisco.com>

#ifndef ALPN_PATTERNS_H
#define ALPN_PATTERNS_H

#include <vector>

#include "search_engines/search_tool.h"
#include "application_ids.h"

struct AlpnPattern
{
    const AppId app_id;
    const std::string pattern;

    AlpnPattern(AppId id, const std::string& name) : app_id(id), pattern(name){}

    ~AlpnPattern() {}
};

typedef std::vector<AlpnPattern*> AlpnPatternList;

class AlpnPatternMatchers
{
public:
    ~AlpnPatternMatchers();
    AppId match_alpn_pattern(const std::string&);
    void add_alpn_pattern(AppId, const std::string&, const std::string&);
    void finalize_patterns();
    void reload_patterns();
    unsigned get_pattern_count();

    const AlpnPatternList& get_alpn_load_list() const { return alpn_load_list; }

private:
    snort::SearchTool alpn_pattern_matcher = snort::SearchTool();
    AlpnPatternList alpn_load_list;
};

#endif

