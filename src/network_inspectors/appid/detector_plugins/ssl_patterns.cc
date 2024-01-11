//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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

// ssl_patterns.cc author Shravan Rangaraju <shrarang@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ssl_patterns.h"

#include "utils/util.h"

using namespace snort;

static void create_matcher(SearchTool& matcher, SslPatternList* list, CnameCache& set, unsigned& pattern_count)
{
    size_t* pattern_index;
    size_t size = 0;
    SslPatternList* element = nullptr;

    pattern_index = &size;

    for (element = list; element; element = element->next)
    {
        if (!element->dpattern->is_cname and set.count(*(element->dpattern)))
            continue;

        matcher.add(element->dpattern->pattern,
            element->dpattern->pattern_size, element->dpattern, true, element->dpattern->is_literal);
        (*pattern_index)++;
    }
    pattern_count = size;
    matcher.prep();
}

static int cert_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    MatchedSslPatterns* cm;
    MatchedSslPatterns** matches = (MatchedSslPatterns**)data;
    SslPattern* target = (SslPattern*)id;

    cm = (MatchedSslPatterns*)snort_alloc(sizeof(MatchedSslPatterns));
    cm->mpattern = target;
    cm->match_start_pos = match_end_pos - target->pattern_size;
    cm->next = *matches;
    *matches = cm;

    return 0;
}

static int cname_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    MatchedSslPatterns* cm;
    MatchedSslPatterns** matches = (MatchedSslPatterns**)data;
    SslPattern* target = (SslPattern*)id;

    /* Only collect the match if it is a cname pattern. */
    if (target->is_cname)
    {
        cm = (MatchedSslPatterns*)snort_alloc(sizeof(MatchedSslPatterns));
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
inline static bool ssl_pattern_validate_match(const MatchedSslPatterns * const mp, const uint8_t* data, int data_size)
{
    return mp->match_start_pos + mp->mpattern->pattern_size == data_size and
            (mp->match_start_pos == 0 or
            data[mp->match_start_pos-1] == '.' or
            *mp->mpattern->pattern == '.');
}

inline static bool is_perfect_literal_match(const MatchedSslPatterns * const mp, int data_size)
{
    return mp->mpattern->is_literal and
            (mp->match_start_pos + mp->mpattern->pattern_size == data_size) and
            mp->match_start_pos == 0;

}

static bool scan_patterns(SearchTool& matcher, const uint8_t* data, size_t size,
    AppId& client_id, AppId& payload_id, bool is_cname_search)
{
    MatchedSslPatterns* mp = nullptr;
    SslPattern* best_match = nullptr;

    if (is_cname_search)
        matcher.find_all((const char*)data, size, cname_pattern_match, false, &mp);
    else
        matcher.find_all((const char*)data, size, cert_pattern_match, false, &mp);

    if (!mp)
        return false;
    
    MatchedSslPatterns* tmp = mp;

    while (tmp)
    {
        if (!tmp->mpattern->is_literal or ssl_pattern_validate_match(tmp, data, (int)size))
        {
            if(is_perfect_literal_match(tmp, (int)size))
            {
                best_match = tmp->mpattern;
                break;
            }

            if (!best_match or
                    tmp->mpattern->pattern_size > best_match->pattern_size)
            {
                best_match = tmp->mpattern;
            }
        }
        tmp = tmp->next;
    }

    while (mp)
    {
        MatchedSslPatterns* tmpMp = mp;
        mp = mp->next;
        snort_free(tmpMp);
    }
    if (!best_match)
        return false;

    switch (best_match->type)
    {
    /* type 0 means WEB APP */
    case 0:
        client_id = APP_ID_SSL_CLIENT;
        payload_id = best_match->app_id;
        break;
    /* type 1 means CLIENT */
    case 1:
        client_id = best_match->app_id;
        payload_id = 0;
        break;
    default:
        return false;
    }

    return true;
}

static void free_patterns(SslPatternList*& list)
{
    SslPatternList* tmp_pattern;

    while ((tmp_pattern = list))
    {
        list = tmp_pattern->next;
        if (tmp_pattern->dpattern)
        {
            if (tmp_pattern->dpattern->pattern)
                snort_free(tmp_pattern->dpattern->pattern);
            snort_free(tmp_pattern->dpattern);
        }
        snort_free(tmp_pattern);
    }
}

static void add_pattern(SslPatternList*& list, uint8_t* pattern_str, size_t
    pattern_size, uint8_t type, AppId app_id, bool is_cname, bool is_literal, CnameCache& set)
{
    SslPatternList* new_ssl_pattern;

    new_ssl_pattern = (SslPatternList*)snort_calloc(sizeof(SslPatternList));
    new_ssl_pattern->dpattern = (SslPattern*)snort_calloc(sizeof(SslPattern));
    new_ssl_pattern->dpattern->type = type;
    new_ssl_pattern->dpattern->app_id = app_id;
    new_ssl_pattern->dpattern->pattern = pattern_str;
    new_ssl_pattern->dpattern->pattern_size = pattern_size;
    new_ssl_pattern->dpattern->is_cname = is_cname;
    new_ssl_pattern->dpattern->is_literal = is_literal;

    new_ssl_pattern->next = list;
    list = new_ssl_pattern;

    if (is_cname)
        set.emplace(*(new_ssl_pattern->dpattern));
}

SslPatternMatchers::~SslPatternMatchers()
{
    free_patterns(cert_pattern_list);
}

void SslPatternMatchers::add_cert_pattern(uint8_t* pattern_str, size_t pattern_size, uint8_t type, AppId app_id, bool is_cname, bool is_literal)
{
    add_pattern(cert_pattern_list, pattern_str, pattern_size, type, app_id, is_cname, is_literal, cert_pattern_set);
}

void SslPatternMatchers::finalize_patterns()
{
    create_matcher(ssl_host_matcher, cert_pattern_list, cert_pattern_set, pattern_count);
    cert_pattern_set.clear();
}

void SslPatternMatchers::reload_patterns()
{
    ssl_host_matcher.reload();
}

unsigned SslPatternMatchers::get_pattern_count()
{
    return pattern_count;
}

bool SslPatternMatchers::scan_hostname(const uint8_t* hostname, size_t size, AppId& client_id, AppId& payload_id)
{
    return scan_patterns(ssl_host_matcher, hostname, size, client_id, payload_id, false);
}

bool SslPatternMatchers::scan_cname(const uint8_t* common_name, size_t size, AppId& client_id, AppId& payload_id)
{
    return scan_patterns(ssl_host_matcher, common_name, size, client_id, payload_id, true);
}
