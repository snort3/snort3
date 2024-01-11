//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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
#include "network_inspectors/appid/appid_utils/sf_mlmp.cc"
#include "utils/util_cstring.cc"
#include "detector_plugins_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

static AppIdConfig config;
static AppIdContext ctxt(config);
static OdpContext odpctxt(config, nullptr);
OdpContext* AppIdContext::odp_ctxt = &odpctxt;
static HttpPatternMatchers* hm = nullptr;
static Packet pkt;
static SfIp sfip;
static AppIdModule appid_mod;
static AppIdInspector appid_inspector(appid_mod);
static AppIdSession session(IpProtocol::IP, &sfip, 0, appid_inspector, odpctxt, 0, 0);
static AppIdHttpSession mock_hsession(session, 0);
static ChpMatchDescriptor cmd_test;
static MatchedCHPAction mchp;
static CHPAction chpa_test;
static char* version = nullptr;
static char* user = nullptr;
static char* my_action_data = (char*)"0";
static const char* my_chp_data = (const char*)"chp_data";
static int total_found;
static AppId service_id = APP_ID_NONE;
static AppId client_id = APP_ID_NONE;
static DetectorHTTPPattern mpattern;

namespace snort
{
AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&) :
    StashGenericObject(STASH_GENERIC_OBJECT_APPID) {}
SearchTool::SearchTool(bool, const char*) { }
void SearchTool::reload() { }
static bool test_find_all_done = false;
static bool test_find_all_enabled = false;
static MatchedPatterns* mock_mp = nullptr;
int SearchTool::find_all(const char*, unsigned, MpseMatch, bool, void* mp_arg, const SnortConfig*)
{
    test_find_all_done = true;
    if (test_find_all_enabled)
        memcpy(mp_arg, &mock_mp, sizeof(MatchedPatterns*));
    return 0;
}
}

void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }
AppIdDiscovery::~AppIdDiscovery() = default;
void ClientDiscovery::initialize(AppIdInspector&) { }
void ClientDiscovery::reload() { }
void AppIdDiscovery::register_detector(const string&, AppIdDetector*, IpProtocol) { }
void AppIdDiscovery::add_pattern_data(AppIdDetector*, snort::SearchTool&, int, unsigned char const*, unsigned int, unsigned int) { }
void AppIdDiscovery::register_tcp_pattern(AppIdDetector*, unsigned char const*, unsigned int, int, unsigned int) { }
void AppIdDiscovery::register_udp_pattern(AppIdDetector*, unsigned char const*, unsigned int, int, unsigned int) { }
int AppIdDiscovery::add_service_port(AppIdDetector*, ServiceDetectorPort const&) { return 0; }
DnsPatternMatchers::~DnsPatternMatchers() = default;
EveCaPatternMatchers::~EveCaPatternMatchers() = default;
SipPatternMatchers::~SipPatternMatchers() = default;
SslPatternMatchers::~SslPatternMatchers() = default;
AlpnPatternMatchers::~AlpnPatternMatchers() = default;
CipPatternMatchers::~CipPatternMatchers() = default;
void AppIdModule::reset_stats() {}
bool AppIdInspector::configure(snort::SnortConfig*) { return true; }
void appid_log(const snort::Packet*, unsigned char, char const*, ...) { }

TEST_GROUP(http_url_patterns_tests)
{
    void setup() override
    {
        hm = new HttpPatternMatchers();
    }

    void teardown() override
    {
        delete hm;
    }
};

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
    match_tally.emplace_back(chc);
    chp_add_candidate_to_tally(match_tally, &chpapp);
    CHECK_EQUAL(match_tally[0].key_pattern_countdown, 0);
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
    char* loc_version = snort_strdup("456");
    const char* data = "ASProxy/123";
    CHECK(hm->scan_header_x_working_with(data, (uint32_t)strlen(data), (char**)&loc_version) ==
        APP_ID_ASPROXY);
    STRCMP_EQUAL(loc_version, "123");
    snort_free(loc_version);
    loc_version = nullptr;

    // appid is APP_ID_NONE
    const char* data2 = "Not ASProxy format";
    CHECK(hm->scan_header_x_working_with(data2, (uint32_t)strlen(data2), (char**)&loc_version) ==
        APP_ID_NONE);
    CHECK(loc_version == nullptr);
}

TEST(http_url_patterns_tests, scan_chp_defer)
{
    // testing DEFER_TO_SIMPLE_DETECT
    test_find_all_done = false;
    chpa_test.appIdInstance = APP_ID_NONE;
    chpa_test.action = DEFER_TO_SIMPLE_DETECT;
    mchp.mpattern = &chpa_test;
    cmd_test.chp_matches[RSP_BODY_FID].emplace_back(mchp);
    cmd_test.cur_ptype = RSP_BODY_FID;
    CHECK(hm->scan_chp(cmd_test, &version, &user, &total_found, &mock_hsession, odpctxt) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);
}

TEST(http_url_patterns_tests, scan_chp_alt_appid)
{
    // testing ALTERNATE_APPID
    test_find_all_done = false;
    chpa_test.action_data = my_action_data;
    chpa_test.appIdInstance = APP_ID_NONE;
    chpa_test.action = ALTERNATE_APPID;
    mchp.mpattern = &chpa_test;
    cmd_test.chp_matches[RSP_BODY_FID].emplace_back(mchp);
    cmd_test.cur_ptype = RSP_BODY_FID;
    CHECK(hm->scan_chp(cmd_test, &version, &user, &total_found, &mock_hsession, odpctxt) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);
}

TEST(http_url_patterns_tests, scan_chp_extract_user)
{
    // testing EXTRACT_USER
    test_find_all_done = false;
    chpa_test.action_data = my_action_data;
    chpa_test.appIdInstance = APP_ID_NONE;
    chpa_test.action = EXTRACT_USER;
    chpa_test.psize = 1;
    mchp.mpattern = &chpa_test;
    mchp.start_match_pos = 0;
    cmd_test.cur_ptype = RSP_BODY_FID;
    cmd_test.chp_matches[RSP_BODY_FID].emplace_back(mchp);
    cmd_test.buffer[RSP_BODY_FID] = (const char*)"userid\n\rpassword";
    cmd_test.length[RSP_BODY_FID] = strlen(cmd_test.buffer[RSP_BODY_FID]);
    CHECK(hm->scan_chp(cmd_test, &version, &user, &total_found, &mock_hsession, odpctxt) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);
    snort_free(user);
    user = nullptr;
}

TEST(http_url_patterns_tests, scan_chp_hold_and_default)
{
    // testing HOLD_FLOW
    test_find_all_done = false;
    chpa_test.action_data = my_action_data;
    chpa_test.appIdInstance = APP_ID_NONE;
    chpa_test.action = HOLD_FLOW;
    mchp.mpattern = &chpa_test;
    cmd_test.chp_matches[RSP_BODY_FID].emplace_back(mchp);
    cmd_test.cur_ptype = RSP_BODY_FID;
    chpa_test.psize = 1;
    mchp.start_match_pos = 0;
    cmd_test.buffer[RSP_BODY_FID] = my_chp_data;
    cmd_test.length[RSP_BODY_FID] = strlen(cmd_test.buffer[RSP_BODY_FID]);
    CHECK(hm->scan_chp(cmd_test, &version, &user, &total_found, &mock_hsession, odpctxt) == APP_ID_NONE);
    CHECK_EQUAL(true, test_find_all_done);

    // testing FUTURE_APPID_SESSION_SIP (default action)
    test_find_all_done = false;
    chpa_test.action_data = my_action_data;
    chpa_test.appIdInstance = APP_ID_NONE;
    chpa_test.action = FUTURE_APPID_SESSION_SIP;
    mchp.mpattern = &chpa_test;
    cmd_test.chp_matches[RSP_BODY_FID].emplace_back(mchp);
    CHECK(hm->scan_chp(cmd_test, &version, &user, &total_found, &mock_hsession, odpctxt) == APP_ID_NONE);
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
