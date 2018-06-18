//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
// http_url_patterns_test.cc author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/detector_plugins/http_url_patterns.cc"

#include "protocols/protocol_ids.h"
#include "framework/module.cc"
#include "network_inspectors/appid/appid_utils/sf_multi_mpse.h"
#include "network_inspectors/appid/appid_utils/sf_mlmp.cc"
#include "utils/util_cstring.cc"
#include "detector_plugins_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

static HttpPatternMatchers* hm = nullptr;
static Packet pkt;
static const SfIp* sfip = nullptr;
static AppIdModule appid_mod;
static AppIdInspector appid_inspector(appid_mod);
static AppIdSession session(IpProtocol::IP, sfip, 0, appid_inspector);
static AppIdHttpSession hsession(session);
static ChpMatchDescriptor cmd;
static MatchedCHPAction mchp;
static CHPAction chpa;
static char* version = nullptr;
static char* user = nullptr;
static char* my_action_data = (char*)"0";
static const char* my_chp_data = (const char*)"chp_data";
static int total_found;
static AppIdModuleConfig mod_config;
static AppId service_id = APP_ID_NONE;
static AppId client_id = APP_ID_NONE;
static DetectorHTTPPattern mpattern;
static const char* my_buffer[NUM_HTTP_FIELDS] = { nullptr };
static uint16_t my_length[NUM_HTTP_FIELDS] = { 0 };
static CHPAction my_match;
static void* my_chp_rewritten = nullptr;

TEST_GROUP(http_url_patterns_tests)
{
    void setup() override
    {
        hm = new HttpPatternMatchers();
    }

    void teardown() override
    {
        delete hm;
        delete sfip;
    }
};

TEST(http_url_patterns_tests, http_field_pattern_match)
{
    FieldPatternData fpd;
    FieldPattern fp;
    pair_t off;

    // verify service_strstr getting called
    fp.patternType = REQ_HOST_FID;
    fpd.payload = (const uint8_t*)"Google";
    fpd.length = 6;
    fpd.hsession = &hsession;

    test_service_strstr_enabled = false;
    test_field_offset_set_done = false;
    hsession.set_offset(fp.patternType, 0, 5);
    CHECK_EQUAL(1, http_field_pattern_match(&fp, nullptr, 0, &fpd, nullptr));
    hsession.get_offset(fp.patternType, off.first, off.second);
    CHECK_EQUAL(5, off.second);     // check offset did not change

    test_service_strstr_enabled = true;
    CHECK_EQUAL(1, http_field_pattern_match(&fp, nullptr, 0, &fpd, nullptr));
    hsession.get_offset(fp.patternType, off.first, off.second);
    CHECK_EQUAL(0, off.second);     // if it changed, service_strstr was called
}

TEST(http_url_patterns_tests, match_query_elements)
{
    // null check
    CHECK_EQUAL(0, match_query_elements(nullptr, nullptr, nullptr, 0));

    // pattern matched
    char appVersion[10];
    const char pattern1[] = "6.2.3-1515 & Official Build";
    tMlpPattern packetData;
    packetData.pattern = (const uint8_t*)pattern1;
    packetData.patternSize = sizeof(pattern1) - 1;
    const char pattern2[] = "6.2.3";
    tMlpPattern userPattern;
    userPattern.pattern = (const uint8_t*)pattern2;
    userPattern.patternSize = sizeof(pattern2) - 1;
    CHECK_EQUAL(sizeof(pattern2), match_query_elements(&packetData, &userPattern, appVersion, 10));
}

TEST(http_url_patterns_tests, chp_add_candidate_to_tally)
{
    CHPMatchTally match_tally;
    CHPApp chpapp;
    CHPMatchCandidate chc;

    // verify pattern countdown
    chc.chpapp = &chpapp;
    chc.key_pattern_countdown = 1;
    chc.key_pattern_length_sum = 0;
    match_tally.push_back(chc);
    chp_add_candidate_to_tally(match_tally, &chpapp);
    CHECK_EQUAL(match_tally[0].key_pattern_countdown, 0);
}

TEST(http_url_patterns_tests, get_http_offsets)
{
    // field_offset is set for small payload
    test_field_offset_set_done = false;
    pkt.data = (const uint8_t*)"Go";
    pkt.dsize = 2;

    pair_t off;
    hsession.set_offset(REQ_AGENT_FID, 5, 0);
    hm->get_http_offsets(&pkt, &hsession);
    hsession.get_offset(REQ_AGENT_FID, off.first, off.second);
    CHECK_EQUAL(0, off.first);

    // find_all is not called for bigger payload when service_strstr returns nullptr
    test_service_strstr_enabled = false;
    test_find_all_done = false;
    pkt.data = (const uint8_t*)"GET http://www.w3.org HTTP/1.1";
    pkt.dsize = strlen((const char*)pkt.data);
    hm->get_http_offsets(&pkt, &hsession);
    CHECK_EQUAL(false, test_find_all_done);

    // find_all is called for bigger payload when service_strstr returns something
    test_service_strstr_enabled = true;
    hm->get_http_offsets(&pkt, &hsession);
    CHECK_EQUAL(true, test_find_all_done);
}

TEST(http_url_patterns_tests, rewrite_chp_exist)
{
    // don't insert a string that is already present
    my_buffer[REQ_AGENT_FID] = (const char*)"existing data";
    my_match.action_data = (char*)"exist";
    my_match.psize = 0;
    rewrite_chp(my_buffer[REQ_AGENT_FID], my_length[REQ_AGENT_FID], 0, my_match.psize,
        my_match.action_data, (const char**)&my_chp_rewritten, 1);
    CHECK((char*)my_chp_rewritten == nullptr);
}

TEST(http_url_patterns_tests, rewrite_chp_insert)
{
    // insert a string in my_chp_rewritten
    my_buffer[REQ_AGENT_FID] = (const char*)"existing data";
    my_match.action_data = (char*)"new";
    rewrite_chp(my_buffer[REQ_AGENT_FID], my_length[REQ_AGENT_FID], 0, my_match.psize,
        my_match.action_data, (const char**)&my_chp_rewritten, 1);
    STRCMP_EQUAL((const char*)my_chp_rewritten, (const char*)my_match.action_data);
    snort_free(my_chp_rewritten);
    my_chp_rewritten = nullptr;
}

TEST(http_url_patterns_tests, rewrite_chp_same)
{
    // don't replace if they are same
    my_chp_rewritten = nullptr;
    my_buffer[REQ_AGENT_FID] = (const char*)"some data";
    my_match.action_data = (char*)"some data";
    rewrite_chp(my_buffer[REQ_AGENT_FID], my_length[REQ_AGENT_FID], 0, my_match.psize,
        my_match.action_data, (const char**)&my_chp_rewritten, 0);
    CHECK((char*)my_chp_rewritten == nullptr);
}

TEST(http_url_patterns_tests, rewrite_chp_replace_null)
{
    // replace null action data in my_chp_rewritten
    my_chp_rewritten = nullptr;
    my_buffer[REQ_AGENT_FID] = (const char*)"existing data";
    my_match.action_data = nullptr;
    my_match.psize = 0;
    rewrite_chp(my_buffer[REQ_AGENT_FID], strlen(my_buffer[REQ_AGENT_FID]), 0, my_match.psize,
        my_match.action_data, (const char**)&my_chp_rewritten, 0);
    STRCMP_EQUAL((const char*)my_chp_rewritten, my_buffer[REQ_AGENT_FID]);
    snort_free(my_chp_rewritten);
    my_chp_rewritten = nullptr;
}

TEST(http_url_patterns_tests, rewrite_chp_replace_non_null)
{
    // replace non-null action data in my_chp_rewritten
    my_chp_rewritten = nullptr;
    my_buffer[REQ_AGENT_FID] = (const char*)"existing data";
    my_match.action_data = (char*)"new data";
    my_match.psize = 1;
    rewrite_chp(my_buffer[REQ_AGENT_FID], 1, 0, my_match.psize,
        my_match.action_data, (const char**)&my_chp_rewritten, 0);
    STRCMP_EQUAL((const char*)my_chp_rewritten, (const char*)my_match.action_data);
    snort_free(my_chp_rewritten);
    my_chp_rewritten = nullptr;
}

TEST(http_url_patterns_tests, normalize_userid)
{
    // no change
    char uid1[] = "abcd_ID";
    normalize_userid(uid1);
    STRCMP_EQUAL((const char*)uid1, (const char*)"abcd_ID");

    // % is replaced with alpha id
    char uid2[] = "%abcd_ID";
    normalize_userid(uid2);
    CHECK(strchr(uid2, '%') == nullptr);

    // % is replaced with numeric id
    char uid3[] = "%1234";
    normalize_userid(uid3);
    CHECK(strchr(uid3, '%') == nullptr);
}

TEST(http_url_patterns_tests, scan_header_x_working_with)
{
    // appid is APP_ID_ASPROXY
    char* version = snort_strdup("456");
    const char* data = "ASProxy/123";
    CHECK(hm->scan_header_x_working_with(data, (uint32_t)strlen(data), (char**)&version) ==
        APP_ID_ASPROXY);
    STRCMP_EQUAL(version, "123");
    snort_free(version);
    version = nullptr;

    // appid is APP_ID_NONE
    const char* data2 = "Not ASProxy format";
    CHECK(hm->scan_header_x_working_with(data2, (uint32_t)strlen(data2), (char**)&version) ==
        APP_ID_NONE);
    CHECK(version == nullptr);
}

TEST(http_url_patterns_tests, scan_chp_defer)
{
    // testing DEFER_TO_SIMPLE_DETECT
    test_find_all_done = false;
    chpa.appIdInstance = APP_ID_NONE;
    chpa.action = DEFER_TO_SIMPLE_DETECT;
    mchp.mpattern = &chpa;
    cmd.chp_matches[RSP_BODY_FID].push_back(mchp);
    cmd.cur_ptype = RSP_BODY_FID;
    mod_config.safe_search_enabled = false;
    CHECK(hm->scan_chp(cmd, &version, &user, &total_found, &hsession, (const
        AppIdModuleConfig*)&mod_config) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);
}

TEST(http_url_patterns_tests, scan_chp_alt_appid)
{
    // testing ALTERNATE_APPID
    test_find_all_done = false;
    chpa.action_data = my_action_data;
    chpa.appIdInstance = APP_ID_NONE;
    chpa.action = ALTERNATE_APPID;
    mchp.mpattern = &chpa;
    cmd.chp_matches[RSP_BODY_FID].push_back(mchp);
    cmd.cur_ptype = RSP_BODY_FID;
    mod_config.safe_search_enabled = false;
    CHECK(hm->scan_chp(cmd, &version, &user, &total_found, &hsession, (const
        AppIdModuleConfig*)&mod_config) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);
}

TEST(http_url_patterns_tests, scan_chp_extract_user)
{
    // testing EXTRACT_USER
    test_find_all_done = false;
    chpa.action_data = my_action_data;
    chpa.appIdInstance = APP_ID_NONE;
    chpa.action = EXTRACT_USER;
    chpa.psize = 1;
    mchp.mpattern = &chpa;
    mchp.start_match_pos = 0;
    cmd.cur_ptype = RSP_BODY_FID;
    mod_config.safe_search_enabled = false;
    cmd.chp_matches[RSP_BODY_FID].push_back(mchp);
    cmd.buffer[RSP_BODY_FID] = (const char*)"userid\n\rpassword";
    cmd.length[RSP_BODY_FID] = strlen(cmd.buffer[RSP_BODY_FID]);
    CHECK(hm->scan_chp(cmd, &version, &user, &total_found, &hsession, (const
        AppIdModuleConfig*)&mod_config) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);
    snort_free(user);
    user = nullptr;
}

TEST(http_url_patterns_tests, scan_chp_rewrite_field)
{
    // testing REWRITE_FIELD
    test_find_all_done = false;
    cmd.cur_ptype = RSP_BODY_FID;
    mod_config.safe_search_enabled = false;
    chpa.action_data = my_action_data;
    chpa.appIdInstance = APP_ID_NONE;
    chpa.action = REWRITE_FIELD;
    chpa.psize = 1;
    mchp.mpattern = &chpa;
    mchp.start_match_pos = 0;
    cmd.chp_matches[RSP_BODY_FID].push_back(mchp);
    cmd.buffer[RSP_BODY_FID] = my_chp_data;
    cmd.length[RSP_BODY_FID] = strlen(cmd.buffer[RSP_BODY_FID]);
    CHECK(hm->scan_chp(cmd, &version, &user, &total_found, &hsession, (const
        AppIdModuleConfig*)&mod_config) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);
    snort_free(const_cast<char*>(cmd.chp_rewritten[RSP_BODY_FID]));
    cmd.chp_rewritten[RSP_BODY_FID] = nullptr;
}

TEST(http_url_patterns_tests, scan_chp_insert_without_action)
{
    // testing INSERT_FIELD without action_data
    test_find_all_done = false;
    cmd.cur_ptype = RSP_BODY_FID;
    mod_config.safe_search_enabled = false;
    chpa.action_data = nullptr;
    chpa.appIdInstance = APP_ID_NONE;
    chpa.action = INSERT_FIELD;
    chpa.psize = 1;
    mchp.mpattern = &chpa;
    mchp.start_match_pos = 0;
    cmd.chp_matches[RSP_BODY_FID].push_back(mchp);
    cmd.buffer[RSP_BODY_FID] = my_chp_data;
    cmd.length[RSP_BODY_FID] = strlen(cmd.buffer[RSP_BODY_FID]);
    CHECK(hm->scan_chp(cmd, &version, &user, &total_found, &hsession, (const
        AppIdModuleConfig*)&mod_config) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);
    snort_free(const_cast<char*>(cmd.chp_rewritten[RSP_BODY_FID]));
    cmd.chp_rewritten[RSP_BODY_FID] = nullptr;
}

TEST(http_url_patterns_tests, scan_chp_insert_with_action)
{
    // testing INSERT_FIELD with action_data
    test_find_all_done = false;
    cmd.cur_ptype = RSP_BODY_FID;
    mod_config.safe_search_enabled = false;
    chpa.action_data = my_action_data;
    chpa.appIdInstance = APP_ID_NONE;
    chpa.action = INSERT_FIELD;
    chpa.psize = 1;
    mchp.mpattern = &chpa;
    mchp.start_match_pos = 0;
    cmd.chp_matches[RSP_BODY_FID].push_back(mchp);
    cmd.buffer[RSP_BODY_FID] = my_chp_data;
    cmd.length[RSP_BODY_FID] = strlen(cmd.buffer[RSP_BODY_FID]);
    CHECK(hm->scan_chp(cmd, &version, &user, &total_found, &hsession, (const
        AppIdModuleConfig*)&mod_config) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);
    snort_free(const_cast<char*>(cmd.chp_rewritten[RSP_BODY_FID]));
    cmd.chp_rewritten[RSP_BODY_FID] = nullptr;
}

TEST(http_url_patterns_tests, scan_chp_hold_and_default)
{
    // testing HOLD_FLOW
    test_find_all_done = false;
    chpa.action_data = my_action_data;
    chpa.appIdInstance = APP_ID_NONE;
    chpa.action = HOLD_FLOW;
    mchp.mpattern = &chpa;
    cmd.chp_matches[RSP_BODY_FID].push_back(mchp);
    cmd.cur_ptype = RSP_BODY_FID;
    mod_config.safe_search_enabled = false;
    chpa.psize = 1;
    mchp.start_match_pos = 0;
    cmd.buffer[RSP_BODY_FID] = my_chp_data;
    cmd.length[RSP_BODY_FID] = strlen(cmd.buffer[RSP_BODY_FID]);
    CHECK(hm->scan_chp(cmd, &version, &user, &total_found, &hsession, (const
        AppIdModuleConfig*)&mod_config) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);

    // testing FUTURE_APPID_SESSION_SIP (default action)
    test_find_all_done = false;
    chpa.action_data = my_action_data;
    chpa.appIdInstance = APP_ID_NONE;
    chpa.action = FUTURE_APPID_SESSION_SIP;
    mchp.mpattern = &chpa;
    cmd.chp_matches[RSP_BODY_FID].push_back(mchp);
    CHECK(hm->scan_chp(cmd, &version, &user, &total_found, &hsession, (const
        AppIdModuleConfig*)&mod_config) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);
}

TEST(http_url_patterns_tests, insert_and_process_pattern)
{
    DetectorHTTPPattern url_pat, payload_pat;
    DetectorAppUrlPattern* au_pat = (DetectorAppUrlPattern*)snort_calloc(
        sizeof(DetectorAppUrlPattern));

    // adding to host_payload_patterns
    payload_pat.init(nullptr, 6, SINGLE, APP_ID_HTTP, APP_ID_NONE, APP_ID_GOOGLE, APP_ID_NONE); // null
                                                                                                // pattern
                                                                                                // test
    payload_pat.init((const uint8_t*)"Google", 6, (DHPSequence)10, APP_ID_HTTP, APP_ID_NONE,
        APP_ID_GOOGLE, APP_ID_NONE);                                                                                      // high
                                                                                                                          // seq
                                                                                                                          // test
    payload_pat.init((const uint8_t*)"Google", 6, SINGLE, APP_ID_HTTP, APP_ID_NONE, APP_ID_GOOGLE,
        APP_ID_NONE);
    snort_free(const_cast<uint8_t*>(payload_pat.pattern));
    payload_pat.pattern = nullptr;
    hm->insert_http_pattern(HTTP_PAYLOAD, payload_pat);

    // adding to url_patterns
    url_pat.pattern = nullptr;
    hm->insert_http_pattern(HTTP_URL, url_pat);

    // adding to app_url_patterns
    au_pat->userData.query.pattern = nullptr;
    au_pat->patterns.host.pattern = nullptr;
    au_pat->patterns.path.pattern = nullptr;
    au_pat->patterns.scheme.pattern = nullptr;
    hm->insert_app_url_pattern(au_pat);

    // The above insert operations would generate errors
    // 1. by ~HttpPatternMatchers if there is allocation/deallocation mismatch
    // 2. by CHECK if there is any leaks
    CHECK(true);
}

TEST(http_url_patterns_tests, identify_user_agent_firefox)
{
    test_find_all_enabled = true;

    // null buffPtr in continue_buffer_scan for APP_ID_FIREFOX
    mpattern.client_id = APP_ID_FIREFOX;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns)); // freed by
                                                                       // identify_user_agent
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 100; // exceeding size
    mock_mp->next = nullptr;
    hm->identify_user_agent("Firefox/57.1", 12, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;

    // invalid version format following after_match_pos for APP_ID_FIREFOX
    mpattern.client_id = APP_ID_FIREFOX;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 7;
    mock_mp->next = nullptr;
    hm->identify_user_agent("Firefox/;", 9, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;

    test_find_all_enabled = false;
}

TEST(http_url_patterns_tests, identify_user_agent_chrome)
{
    test_find_all_enabled = true;

    // null buffPtr in continue_buffer_scan for APP_ID_CHROME
    mpattern.client_id = APP_ID_CHROME;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 100; // exceeding size
    mock_mp->next = nullptr;
    hm->identify_user_agent("Chrome/64.0", 11, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;

    // invalid version format following after_match_pos for APP_ID_CHROME
    mpattern.client_id = APP_ID_CHROME;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 6;
    mock_mp->next = nullptr;
    hm->identify_user_agent("Chrome/;", 8, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;

    test_find_all_enabled = false;
}

TEST(http_url_patterns_tests, identify_user_agent_android)
{
    // invalid version format following after_match_pos for APP_ID_ANDROID_BROWSER
    test_find_all_enabled = true;
    mpattern.client_id = APP_ID_ANDROID_BROWSER;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 7;
    mock_mp->next = nullptr;
    hm->identify_user_agent("Android/;", 9, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;
    test_find_all_enabled = false;
}

TEST(http_url_patterns_tests, identify_user_agent_bittorrent)
{
    test_find_all_enabled = true;

    // null buffPtr in continue_buffer_scan for APP_ID_BITTORRENT
    mpattern.client_id = APP_ID_BITTORRENT;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 100; // exceeding size
    mock_mp->next = nullptr;
    hm->identify_user_agent("BitTorrent/64.0", 15, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;

    // invalid version format following after_match_pos for APP_ID_BITTORRENT
    mpattern.client_id = APP_ID_BITTORRENT;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns)); // freed by
                                                                       // identify_user_agent
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 10;
    mock_mp->next = nullptr;
    hm->identify_user_agent("BitTorrent/;", 12, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;

    test_find_all_enabled = false;
}

TEST(http_url_patterns_tests, identify_user_agent_google_desktop)
{
    test_find_all_enabled = true;

    // exceeding after_match_pos for APP_ID_GOOGLE_DESKTOP
    mpattern.client_id = APP_ID_GOOGLE_DESKTOP;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns)); // freed by
                                                                       // identify_user_agent
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 100; // exceeding size
    mock_mp->next = nullptr;
    hm->identify_user_agent("GoogleDesktop/12", 16, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;

    // no tab/space/slash format for APP_ID_GOOGLE_DESKTOP
    mpattern.client_id = APP_ID_GOOGLE_DESKTOP;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 13;
    mock_mp->next = nullptr;
    hm->identify_user_agent("GoogleDesktopVersion12", 22, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;

    // invalid version format following after_match_pos for APP_ID_GOOGLE_DESKTOP
    mpattern.client_id = APP_ID_GOOGLE_DESKTOP;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 13;
    mock_mp->next = nullptr;
    hm->identify_user_agent("GoogleDesktop/;", 15, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;

    test_find_all_enabled = false;
}

TEST(http_url_patterns_tests, identify_user_agent_wget)
{
    // exceeding after_match_pos for APP_ID_WGET
    test_find_all_enabled = true;
    mpattern.client_id = APP_ID_WGET;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 100; // exceeding size
    mock_mp->next = nullptr;
    hm->identify_user_agent("Wget/12", 7, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;
    test_find_all_enabled = false;
}

TEST(http_url_patterns_tests, identify_user_agent_fake_version_appid)
{
    // exceeding after_match_pos for FAKE_VERSION_APP_ID
    test_find_all_enabled = true;
    mpattern.client_id = FAKE_VERSION_APP_ID;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns)); // freed by
                                                                       // identify_user_agent
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 100; // exceeding size
    mock_mp->next = nullptr;
    hm->identify_user_agent("Fake/12", 7, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;
    test_find_all_enabled = false;
}

TEST(http_url_patterns_tests, identify_user_agent_blackberry)
{
    test_find_all_enabled = true;

    // null buffPtr in continue_buffer_scan for APP_ID_BLACKBERRY_BROWSER
    mpattern.client_id = APP_ID_BLACKBERRY_BROWSER;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns)); // freed by
                                                                       // identify_user_agent
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 100;
    mock_mp->next = nullptr;
    hm->identify_user_agent("Blackberry", 10, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;

    // invalid version format following after_match_pos for APP_ID_BLACKBERRY_BROWSER
    mpattern.client_id = APP_ID_BLACKBERRY_BROWSER;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 10;
    mock_mp->next = nullptr;
    hm->identify_user_agent("Blackberry/;", 12, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;

    test_find_all_enabled = false;
}

TEST(http_url_patterns_tests, identify_user_agent_http)
{
    // APP_ID_HTTP
    test_find_all_enabled = true;
    mpattern.client_id = APP_ID_HTTP;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 4;
    mock_mp->next = nullptr;
    hm->identify_user_agent("HTTP/2.1", 8, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;
    test_find_all_enabled = false;
}

TEST(http_url_patterns_tests, identify_user_agent_mobiledirect)
{
    // mobileDetect
    test_find_all_enabled = true;
    mpattern.client_id = APP_ID_SAFARI_MOBILE_DUMMY;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 11;
    mock_mp->next = nullptr;
    hm->identify_user_agent("SafariMobile/2.1", 16, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    snort_free(version);
    version = nullptr;
    test_find_all_enabled = false;
}

TEST(http_url_patterns_tests, identify_user_agent_skypedirect)
{
    // skypeDetect
    test_find_all_enabled = true;
    mpattern.client_id = APP_ID_SKYPE;
    mock_mp = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns)); // freed by
                                                                       // identify_user_agent
    mock_mp->mpattern = &mpattern;
    mock_mp->after_match_pos = 5;
    mock_mp->next = nullptr;
    hm->identify_user_agent("Skype/2.1", 9, service_id, client_id, &version);
    STRCMP_EQUAL(version, "");
    CHECK_EQUAL(service_id, APP_ID_SKYPE_AUTH);
    CHECK_EQUAL(client_id, APP_ID_SKYPE);
    snort_free(version);
    version = nullptr;
    test_find_all_enabled = false;
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}

