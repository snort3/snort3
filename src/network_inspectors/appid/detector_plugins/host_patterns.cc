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

// host_patterns.cc author Shravan Rangaraju <shrarang@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "host_patterns.h"

#include "utils/util.h"

using namespace snort;

#define HOST_PATTERN_CERT_TYPE_MASK 6 // HostPatternType::HOST_PATTERN_TYPE_SNI | HostPatternType::HOST_PATTERN_TYPE_CNAME

int cert_pattern_match(void* id, void*, int match_end_pos, void* data, void*);
int cname_pattern_match(void* id, void*, int match_end_pos, void* data, void*);
int url_pattern_match(void* id, void*, int match_end_pos, void* data, void*);

static void create_matcher(SearchTool& matcher, HostPatternList* list, unsigned& pattern_count)
{
    size_t* pattern_index;
    size_t size = 0;
    HostPatternList* element = nullptr;

    pattern_index = &size;

    for (element = list; element; element = element->next)
    {
        matcher.add(element->dpattern->pattern,
            element->dpattern->pattern_size, element->dpattern, true, element->dpattern->is_literal);
        (*pattern_index)++;
    }
    pattern_count = size;
    matcher.prep();
}

int cert_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    HostPattern* target = (HostPattern*)id;

    if ( target->pattern_type & HOST_PATTERN_CERT_TYPE_MASK )
    {
        MatchedHostPatterns* cm;
        MatchedHostPatterns** matches = (MatchedHostPatterns**)data;

        cm = (MatchedHostPatterns*)snort_alloc(sizeof(MatchedHostPatterns));
        cm->mpattern = target;
        cm->match_start_pos = match_end_pos - target->pattern_size;
        cm->next = *matches;
        *matches = cm;
    }
    return 0;
}

int cname_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    HostPattern* target = (HostPattern*)id;

    if ( target->pattern_type & HostPatternType::HOST_PATTERN_TYPE_CNAME )
    {
        MatchedHostPatterns* cm;
        MatchedHostPatterns** matches = (MatchedHostPatterns**)data;

        cm = (MatchedHostPatterns*)snort_alloc(sizeof(MatchedHostPatterns));
        cm->mpattern = target;
        cm->match_start_pos = match_end_pos - target->pattern_size;
        cm->next = *matches;
        *matches = cm;
    }
    return 0;
}

int url_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    HostPattern* target = (HostPattern*)id;

    if ( target->pattern_type & HostPatternType::HOST_PATTERN_TYPE_URL )
    {
        MatchedHostPatterns* cm;
        MatchedHostPatterns** matches = (MatchedHostPatterns**)data;
        
        cm = (MatchedHostPatterns*)snort_alloc(sizeof(MatchedHostPatterns));
        cm->mpattern = target;
        cm->match_start_pos = match_end_pos - target->pattern_size;
        cm->next = *matches;
        *matches = cm;
    }
    return 0;
}
/*
Only patterns that match end of the payload AND
(match the start of the payload
or match after '.'
or patterns starting with '.')
are considered a match. */
inline bool host_pattern_validate_match(const MatchedHostPatterns * const mp, const uint8_t* data, const size_t& data_size)
{
    return mp->match_start_pos + mp->mpattern->pattern_size == data_size and
            (mp->match_start_pos == 0 or
            data[mp->match_start_pos-1] == '.' or
            *mp->mpattern->pattern == '.');
}

inline bool host_pattern_validate_url_match(const MatchedHostPatterns * const mp, const uint8_t* data)
{
        return mp->match_start_pos == 0 or
                data[mp->match_start_pos-1] == '.';
}

inline bool is_perfect_literal_match(const MatchedHostPatterns * const mp, const size_t& data_size)
{
    return mp->mpattern->is_literal and  mp->match_start_pos == 0 and
            (mp->match_start_pos + mp->mpattern->pattern_size == data_size);

}

template<HostPatternType T>
bool scan_patterns(SearchTool& matcher, const uint8_t* data, size_t size,
    AppId& client_id, AppId& payload_id, bool* is_referred_appid = nullptr)
{
    MatchedHostPatterns* mp = nullptr;
    HostPattern* best_match = nullptr;

    matcher.find_all((const char*)data, size, 
        T == HostPatternType::HOST_PATTERN_TYPE_CNAME ? cname_pattern_match :
        T == HostPatternType::HOST_PATTERN_TYPE_URL ? url_pattern_match :
        cert_pattern_match, false, &mp);

    if ( !mp )
        return false;

    MatchedHostPatterns* tmp = mp;

    while ( tmp )
    {
        auto match = tmp->mpattern;
        if ( !match->is_literal or ( T == HostPatternType::HOST_PATTERN_TYPE_URL ? host_pattern_validate_url_match(tmp, data) : host_pattern_validate_match(tmp, data, size) ))
        {
            if ( T != HostPatternType::HOST_PATTERN_TYPE_URL)
            {
                if ( is_perfect_literal_match(tmp, size) )
                {
                    best_match = match;
                    break;
                }
            }

            if ( !best_match or match->pattern_size > best_match->pattern_size )
            {
                best_match = match;
            }
        }
        tmp = tmp->next;
    }

    while ( mp )
    {
        MatchedHostPatterns* tmpMp = mp;
        mp = mp->next;
        snort_free(tmpMp);
    }

    if ( !best_match )
        return false;

    if ( T == HostPatternType::HOST_PATTERN_TYPE_URL )
    {
        client_id = best_match->client_id;
        payload_id = best_match->payload_id;
        if(is_referred_appid)
        {
            *is_referred_appid = best_match->is_referred;
        }
    }
    else
    {
        if (best_match->type)
        {
            client_id = best_match->client_id;
            payload_id = 0;
        }
        else
        {
            client_id =  APP_ID_SSL_CLIENT;
            payload_id = best_match->payload_id;
        }
    }

    return true;
}

static void free_patterns(HostPatternList*& list)
{
    HostPatternList* tmp_pattern;

    while ( (tmp_pattern = list) )
    {
        list = tmp_pattern->next;
        if ( tmp_pattern->dpattern )
        {
            if ( tmp_pattern->dpattern->pattern )
                snort_free(tmp_pattern->dpattern->pattern);
            snort_free(tmp_pattern->dpattern);
        }
        snort_free(tmp_pattern);
    }
}

static void add_pattern(HostPatternList*& list, const uint8_t* pattern_str, size_t
    pattern_size, uint8_t type, AppId client_id, AppId payload_id, HostPatternType pattern_type, bool is_literal, bool is_referred, HostTmpCache& set)
{

    HostTmpCacheKey key { pattern_str, pattern_size, client_id, payload_id };
    auto tmp_lookup_it = set.find(key);
    if ( tmp_lookup_it != set.end() )
    {
        auto cached_list_entry = tmp_lookup_it->second;

        cached_list_entry->pattern_type |= pattern_type;
        cached_list_entry->is_referred |= is_referred;
        return;
    }

    HostPatternList* new_host_pattern;

    new_host_pattern = (HostPatternList*)snort_calloc(sizeof(HostPatternList));
    new_host_pattern->dpattern = (HostPattern*)snort_calloc(sizeof(HostPattern));
    new_host_pattern->dpattern->type = type;
    new_host_pattern->dpattern->client_id = client_id;
    new_host_pattern->dpattern->payload_id = payload_id;
    new_host_pattern->dpattern->pattern_size = pattern_size;
    new_host_pattern->dpattern->pattern_type = pattern_type;
    new_host_pattern->dpattern->is_literal = is_literal;
    new_host_pattern->dpattern->is_referred = is_referred;
    new_host_pattern->dpattern->pattern = (uint8_t*)snort_alloc(pattern_size);
    memcpy(new_host_pattern->dpattern->pattern, pattern_str, pattern_size);

    new_host_pattern->next = list;
    list = new_host_pattern;

    key.pattern = new_host_pattern->dpattern->pattern;
    set[key] = new_host_pattern->dpattern;
}

HostPatternMatchers::~HostPatternMatchers()
{
    free_patterns(host_pattern_list);
}

void HostPatternMatchers::add_host_pattern(const uint8_t* pattern_str, size_t pattern_size, uint8_t type, AppId client_id, AppId payload_id, HostPatternType pattern_type, bool is_literal, bool is_referred)
{
    add_pattern(host_pattern_list, pattern_str, pattern_size, type, client_id, payload_id, pattern_type, is_literal, is_referred, host_pattern_set);
}

void HostPatternMatchers::finalize_patterns()
{
    create_matcher(host_matcher, host_pattern_list, pattern_count);
    host_pattern_set.clear();
}

void HostPatternMatchers::reload_patterns()
{
    host_matcher.reload();
}

unsigned HostPatternMatchers::get_pattern_count()
{
    return pattern_count;
}

bool HostPatternMatchers::scan_url(const uint8_t *url, size_t size, AppId &client_id, AppId &payload_id, bool* is_referred_appid)
{
    return scan_patterns<HostPatternType::HOST_PATTERN_TYPE_URL>(host_matcher, url, size, client_id, payload_id, is_referred_appid);
}

bool HostPatternMatchers::scan_hostname(const uint8_t* hostname, size_t size, AppId& client_id, AppId& payload_id)
{
    return scan_patterns<HostPatternType::HOST_PATTERN_TYPE_SNI>(host_matcher, hostname, size, client_id, payload_id);
}

bool HostPatternMatchers::scan_cname(const uint8_t* common_name, size_t size, AppId& client_id, AppId& payload_id)
{
    return scan_patterns<HostPatternType::HOST_PATTERN_TYPE_CNAME>(host_matcher, common_name, size, client_id, payload_id);
}
