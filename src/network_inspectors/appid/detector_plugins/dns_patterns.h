//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

// dns_patterns.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef DNS_PATTERNS_H
#define DNS_PATTERNS_H

#include "search_engines/search_tool.h"
#include "application_ids.h"

struct DnsHostPattern
{
    uint8_t type;
    AppId app_id;
    uint8_t* pattern;
    int pattern_size;
};

struct DnsHostPatternList
{
    DnsHostPattern* dpattern;
    DnsHostPatternList* next;
};

struct MatchedDnsPatterns
{
    DnsHostPattern* mpattern;
    MatchedDnsPatterns* next;
};

class DnsPatternMatchers
{
public:
    ~DnsPatternMatchers();
    void add_host_pattern(uint8_t*, size_t, uint8_t, AppId);
    void finalize_patterns();
    void reload_patterns();
    unsigned get_pattern_count();
    int scan_hostname(const uint8_t*, size_t, AppId&, AppId&);

private:
    DnsHostPatternList* dns_host_pattern_list = nullptr;
    snort::SearchTool dns_host_matcher = snort::SearchTool();
    unsigned pattern_count = 0;
};

#endif
