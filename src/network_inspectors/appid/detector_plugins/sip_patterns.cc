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

// sip_patterns.cc author Shravan Rangaraju <shrarang@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sip_patterns.h"

#include "utils/util.h"

#include "appid_config.h"

using namespace snort;

static int add_pattern(DetectorAppSipPattern** patternList, AppId client_id,
    const char* client_version, const char* server_pattern)
{
    /* Allocate memory for data structures */
    DetectorAppSipPattern* pattern = (DetectorAppSipPattern*)snort_calloc(
        sizeof(DetectorAppSipPattern));
    pattern->user_data.client_id = client_id;
    pattern->user_data.client_version = snort_strdup(client_version);
    pattern->pattern.pattern = (uint8_t*)snort_strdup(server_pattern);
    pattern->pattern.patternSize = (int)strlen(server_pattern);
    pattern->next = *patternList;
    *patternList = pattern;

    return 0;
}

static int get_sip_client_app(tMlmpTree* pattern_matcher, const char* pattern, uint32_t pattern_len,
    AppId& client_id, char*& client_version)
{
    tMlmpPattern patterns[3];
    DetectorAppSipPattern* data;

    if ( !pattern )
        return 0;

    patterns[0].pattern = (const uint8_t*)pattern;
    patterns[0].patternSize = pattern_len;
    patterns[1].pattern = nullptr;

    data = (DetectorAppSipPattern*)mlmpMatchPatternGeneric(pattern_matcher, patterns);

    if ( !data )
        return 0;

    client_id = data->user_data.client_id;
    client_version = data->user_data.client_version;

    return 1;
}

static void free_patterns(DetectorAppSipPattern*& list)
{
    for ( DetectorAppSipPattern* node = list; node; node = list )
    {
        list = node->next;
        snort_free((void*)node->pattern.pattern);
        snort_free(node->user_data.client_version);
        snort_free(node);
    }
}

SipPatternMatchers::~SipPatternMatchers()
{
    if ( sip_ua_matcher )
    {
        mlmpDestroy(sip_ua_matcher);
    }

    free_patterns(sip_ua_list);

    if ( sip_server_matcher )
    {
        mlmpDestroy(sip_server_matcher);
    }

    free_patterns(sip_server_list);
}

int SipPatternMatchers::add_ua_pattern(AppId client_id, const char* client_version, const
    char* pattern)
{
    return add_pattern(&sip_ua_list, client_id, client_version, pattern);
}

int SipPatternMatchers::add_server_pattern(AppId client_id, const char* client_version, const
    char* pattern)
{
    return add_pattern(&sip_server_list, client_id, client_version,
        pattern);
}

#ifndef SIP_UNIT_TEST
void SipPatternMatchers::finalize_patterns(OdpContext& odp_ctxt)
{
    int num_patterns;
    DetectorAppSipPattern* pattern_node;

    sip_ua_matcher = mlmpCreate();
    sip_server_matcher = mlmpCreate();

    for ( pattern_node = sip_ua_list; pattern_node; pattern_node =
        pattern_node->next )
    {
        pattern_count++;
        num_patterns = odp_ctxt.get_http_matchers().parse_multiple_http_patterns(
            (const char*)pattern_node->pattern.pattern, patterns, PATTERN_PART_MAX, 0);
        patterns[num_patterns].pattern = nullptr;

        mlmpAddPattern(sip_ua_matcher, patterns, pattern_node);
    }

    for ( pattern_node = sip_server_list; pattern_node; pattern_node =
        pattern_node->next )
    {
        pattern_count++;
        num_patterns = odp_ctxt.get_http_matchers().parse_multiple_http_patterns(
            (const char*)pattern_node->pattern.pattern, patterns, PATTERN_PART_MAX, 0);
        patterns[num_patterns].pattern = nullptr;

        mlmpAddPattern(sip_server_matcher, patterns, pattern_node);
    }

    mlmpProcessPatterns(sip_ua_matcher);
    mlmpProcessPatterns(sip_server_matcher);
}

void SipPatternMatchers::reload_patterns()
{
    assert(sip_ua_matcher);
    mlmp_reload_patterns(*sip_ua_matcher);
    assert(sip_server_matcher);
    mlmp_reload_patterns(*sip_server_matcher);
}

unsigned SipPatternMatchers::get_pattern_count()
{
    return pattern_count;
}

int SipPatternMatchers::get_client_from_ua(const char* pattern, uint32_t pattern_len,
    AppId& client_id, char*& client_version)
{
    return get_sip_client_app(sip_ua_matcher, pattern, pattern_len, client_id, client_version);
}
#endif

int SipPatternMatchers::get_client_from_server(const char* pattern, uint32_t pattern_len,
    AppId& client_id, char*& client_version)
{
    return get_sip_client_app(sip_server_matcher, pattern, pattern_len, client_id, client_version);
}

