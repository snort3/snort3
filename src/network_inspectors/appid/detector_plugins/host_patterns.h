//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

// host_patterns.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef HOST_PATTERNS_H
#define HOST_PATTERNS_H

#include <cstring>
#include <unordered_map>
#include "search_engines/search_tool.h"
#include "application_ids.h"

enum HostPatternType : uint8_t
{
    HOST_PATTERN_TYPE_UNDEFINED = 0,
    HOST_PATTERN_TYPE_SNI = (1 << 1),
    HOST_PATTERN_TYPE_CNAME = (1 << 2),
    HOST_PATTERN_TYPE_URL = (1 << 3)
};

struct HostPattern
{
    uint8_t type;
    AppId client_id;
    AppId payload_id;
    uint8_t* pattern;
    uint32_t pattern_size;
    uint8_t pattern_type;
    bool is_literal; // is not regex pattern
    bool is_referred;

    bool operator==(const HostPattern& v) const
    {
        return this->type == v.type and pattern_size == v.pattern_size and this->pattern_type == v.pattern_type
            and (memcmp(pattern, v.pattern, (size_t)pattern_size) == 0);
    }
};

struct HostTmpCacheKey
{
    const uint8_t* pattern;
    size_t pattern_len;
    AppId cl_id;
    AppId pl_id;

    inline bool operator==(const HostTmpCacheKey& rhs) const
    {
        return (this->pattern_len == rhs.pattern_len) and (this->cl_id == rhs.cl_id) and 
               (this->pl_id == rhs.pl_id) and
               (memcmp(this->pattern, rhs.pattern, this->pattern_len) == 0);
    }
};

struct HostTmpCacheKeyHasher
{
    size_t operator()(const HostTmpCacheKey& key) const
    {
        return std::hash<std::string>()(std::string((const char*)key.pattern, key.pattern_len)) ^ std::hash<AppId>()(key.cl_id) ^ std::hash<AppId>()(key.pl_id);
    }
};

typedef std::unordered_map<HostTmpCacheKey, HostPattern*, HostTmpCacheKeyHasher> HostTmpCache;

struct MatchedHostPatterns
{
    HostPattern* mpattern;
    uint32_t match_start_pos;
    struct MatchedHostPatterns* next;
};

struct HostPatternList
{
    HostPattern* dpattern;
    HostPatternList* next;
};

class HostPatternMatchers
{
public:
    ~HostPatternMatchers();
    void add_host_pattern(const uint8_t*, size_t, uint8_t, AppId, AppId, HostPatternType, bool = true, bool = false);
    void finalize_patterns();
    void reload_patterns();
    unsigned get_pattern_count();
    bool scan_hostname(const uint8_t*, size_t, AppId&, AppId&);
    bool scan_cname(const uint8_t*, size_t, AppId&, AppId&);
    bool scan_url(const uint8_t*, size_t, AppId&, AppId&, bool* = nullptr);

private:
    HostPatternList* host_pattern_list = nullptr;
    HostTmpCache host_pattern_set;
    snort::SearchTool host_matcher = snort::SearchTool();
    unsigned pattern_count = 0;
};

#endif
