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

// dns_patterns.cc author Shravan Rangaraju <shrarang@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dns_patterns.h"
#include "utils/util.h"

using namespace snort;

void DnsPatternMatchers::add_host_pattern(uint8_t* pattern_str, size_t pattern_size, uint8_t type, AppId app_id)
{
    DnsHostPatternList* new_dns_host_pattern;

    new_dns_host_pattern = static_cast<DnsHostPatternList*>(snort_calloc(
        sizeof(DnsHostPatternList)));
    new_dns_host_pattern->dpattern = static_cast<DnsHostPattern*>(snort_calloc(
        sizeof(DnsHostPattern)));

    new_dns_host_pattern->dpattern->type = type;
    new_dns_host_pattern->dpattern->app_id = app_id;
    new_dns_host_pattern->dpattern->pattern = pattern_str;
    new_dns_host_pattern->dpattern->pattern_size = pattern_size;

    new_dns_host_pattern->next = dns_host_pattern_list;
    dns_host_pattern_list = new_dns_host_pattern;
}

void DnsPatternMatchers::finalize_patterns()
{
    DnsHostPatternList* element = nullptr;

    /* Add patterns from Lua API */
    for (element = dns_host_pattern_list; element; element = element->next)
    {
        pattern_count++;
        dns_host_matcher.add((char*)element->dpattern->pattern,
            element->dpattern->pattern_size, element->dpattern, true);
    }

    dns_host_matcher.prep();
}

void DnsPatternMatchers::reload_patterns()
{
    dns_host_matcher.reload();
}

unsigned DnsPatternMatchers::get_pattern_count()
{
    return pattern_count;
}

DnsPatternMatchers::~DnsPatternMatchers()
{
    DnsHostPatternList* tmp_pattern;

    while ((tmp_pattern = dns_host_pattern_list))
    {
        dns_host_pattern_list = tmp_pattern->next;
        if (tmp_pattern->dpattern)
        {
            if (tmp_pattern->dpattern->pattern)
                snort_free(tmp_pattern->dpattern->pattern);
            snort_free (tmp_pattern->dpattern);
        }
        snort_free(tmp_pattern);
    }
}

static int dns_host_pattern_match(void* id, void*, int, void* data, void*)
{
    MatchedDnsPatterns* cm;
    MatchedDnsPatterns** matches = (MatchedDnsPatterns**)data;
    DnsHostPattern* target = (DnsHostPattern*)id;

    cm = (MatchedDnsPatterns*)snort_calloc(sizeof(MatchedDnsPatterns));
    cm->mpattern = target;
    cm->next = *matches;
    *matches = cm;

    return 0;
}

int DnsPatternMatchers::scan_hostname(const uint8_t* pattern, size_t size, AppId& client_id,
    AppId& payload_id)
{
    MatchedDnsPatterns* mp = nullptr;
    MatchedDnsPatterns* tmp_mp;
    DnsHostPattern* best_match;

    dns_host_matcher.find_all((const char*)pattern, size, dns_host_pattern_match, false, &mp);

    if (!mp)
        return 0;

    best_match = mp->mpattern;
    tmp_mp = mp->next;
    snort_free(mp);

    while ((mp = tmp_mp))
    {
        tmp_mp = mp->next;
        if (mp->mpattern->pattern_size > best_match->pattern_size)
        {
            best_match = mp->mpattern;
        }
        snort_free(mp);
    }

    switch (best_match->type)
    {
    // type 0 means WEB APP
    case 0:
        client_id = APP_ID_DNS;
        payload_id = best_match->app_id;
        break;
    // type 1 means CLIENT
    case 1:
        client_id = best_match->app_id;
        payload_id = 0;
        break;
    default:
        return 0;
    }

    return 1;
}
