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

// ssl_patterns.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef SSL_PATTERNS_H
#define SSL_PATTERNS_H

#include <cstring>
#include <unordered_set>
#include "search_engines/search_tool.h"
#include "application_ids.h"

struct SslPattern
{
    uint8_t type;
    AppId app_id;
    uint8_t* pattern;
    int pattern_size;
    bool is_cname;

    bool operator==(const SslPattern& v) const
    {
        return this->type == v.type and pattern_size == v.pattern_size
            and (memcmp(pattern, v.pattern, (size_t)pattern_size) == 0); 
    }
};

struct SslCacheKeyHasher
{
    size_t operator()(const SslPattern& key) const
    {
        return std::hash<std::string>{}(std::string((char*)key.pattern, key.pattern_size));
    }
};

typedef std::unordered_set<SslPattern, SslCacheKeyHasher> CnameCache;

struct MatchedSslPatterns
{
    SslPattern* mpattern;
    int match_start_pos;
    struct MatchedSslPatterns* next;
};

struct SslPatternList
{
    SslPattern* dpattern;
    SslPatternList* next;
};

class SslPatternMatchers
{
public:
    ~SslPatternMatchers();
    void add_cert_pattern(uint8_t*, size_t, uint8_t, AppId, bool);
    void finalize_patterns();
    void reload_patterns();
    bool scan_hostname(const uint8_t*, size_t, AppId&, AppId&);
    bool scan_cname(const uint8_t*, size_t, AppId&, AppId&);

private:
    SslPatternList* cert_pattern_list = nullptr;
    CnameCache cert_pattern_set;
    snort::SearchTool ssl_host_matcher = snort::SearchTool();
};

#endif
