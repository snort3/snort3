//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// http_url_patterns.h author Sourcefire Inc.

#ifndef HTTP_URL_PATTERNS_H
#define HTTP_URL_PATTERNS_H

#include <vector>

#include "appid_utils/sf_multi_mpse.h"
#include "appid_utils/sf_mlmp.h"
#include "flow/flow.h"
#include "utils/util.h"

struct Packet;
struct AppIdServiceSubtype;
class AppIdHttpSession;
class AppIdModuleConfig;
class SearchTool;

enum httpPatternType
{
    HTTP_PAYLOAD    = 1,
    HTTP_USER_AGENT = 2,
    HTTP_URL        = 3
};

struct HTTPHeaderIndices
{
    int start;
    int end;
};

struct UrlUserData
{
    uint32_t service_id;
    uint32_t client_app;
    uint32_t payload;
    AppId appId;
    tMlpPattern query;
};

struct DetectorAppUrlPattern
{
    struct
    {
        tMlpPattern host;
        tMlpPattern path;
        tMlpPattern scheme;
    } patterns;

    UrlUserData userData;
};

// These values are used in Lua code as raw numbers. Do NOT reassign new values.
enum DHPSequence
{
    SINGLE = 0,
    SKYPE_URL = 1,
    SKYPE_VERSION = 2,
    BT_ANNOUNCE = 3,
    BT_OTHER = 4,
    USER_AGENT_HEADER = 5
};

struct DetectorHTTPPattern
{
    DHPSequence seq;
    AppId service_id;
    AppId client_app;
    AppId payload;
    int pattern_size;
    uint8_t* pattern;
    AppId appId;
};

struct HTTPListElement
{
    DetectorHTTPPattern detector_http_pattern;
    HTTPListElement* next;
};

#define CHP_APPID_BITS_FOR_INSTANCE  7
#define CHP_APPID_INSTANCE_MAX (1 << CHP_APPID_BITS_FOR_INSTANCE)
#define CHP_APPIDINSTANCE_TO_ID(_appIdInstance) \
    (_appIdInstance >> CHP_APPID_BITS_FOR_INSTANCE)
#define CHP_APPIDINSTANCE_TO_INSTANCE(_appIdInstance) \
    (_appIdInstance & (CHP_APPID_INSTANCE_MAX-1))
/*
  NOTE: The following structures have a field called appIdInstance.
    The low-order CHP_APPID_BITS_FOR_INSTANCE bits of appIdInstance field are used
    for the instance value while the remaining bits are used for the appId, shifted left
    that same number of bits. The legacy value for older apis is generated with the
    macro below.
*/
#define CHP_APPID_SINGLE_INSTANCE(_appId) \
    ((_appId << CHP_APPID_BITS_FOR_INSTANCE) + (CHP_APPID_INSTANCE_MAX-1))

// These values are used in Lua code as raw numbers. Do NOT reassign new values.
enum ActionType
{
    NO_ACTION,                              //0
    COLLECT_VERSION,                        //1
    EXTRACT_USER,                           //2
    REWRITE_FIELD,                          //3
    INSERT_FIELD,                           //4
    ALTERNATE_APPID,                        //5
    FUTURE_APPID_SESSION_SIP,               //6
    FUTURE_APPID_SESSION_DIP,               //7
    FUTURE_APPID_SESSION_SPORT,             //8
    FUTURE_APPID_SESSION_DPORT,             //9
    FUTURE_APPID_SESSION_PROTOCOL,          //10
    FUTURE_APPID_SESSION_CREATE,            //11
    HOLD_FLOW,                              //12
    GET_OFFSETS_FROM_REBUILT,               //13
    SEARCH_UNSUPPORTED,                     //14
    DEFER_TO_SIMPLE_DETECT,                 //15
    MAX_ACTION_TYPE = DEFER_TO_SIMPLE_DETECT,
};

// These values are used in Lua code as raw numbers. Do NOT reassign new values.
enum PatternType
{
    // Request-side headers
    AGENT_PT,          // 0
    HOST_PT,           // 1
    REFERER_PT,        // 2
    URI_PT,            // 3
    COOKIE_PT,         // 4
    REQ_BODY_PT,       // 5
    // Response-side headers
    CONTENT_TYPE_PT,   // 6
    LOCATION_PT,       // 7
    BODY_PT,           // 8
    NUMBER_OF_PTYPES,  // 9
    MAX_PATTERN_TYPE = BODY_PT,
    MAX_KEY_PATTERN = URI_PT,
};

struct CHPApp
{
    AppId appIdInstance; // * see note above
    unsigned app_type_flags;
    int num_matches;
    int num_scans;
    int key_pattern_count;
    int key_pattern_length_sum;
    int ptype_scan_counts[NUMBER_OF_PTYPES];
    int ptype_req_counts[NUMBER_OF_PTYPES];
    int ptype_rewrite_insert_used[NUMBER_OF_PTYPES]; // boolean
};

struct CHPAction
{
    AppId appIdInstance; // * see note above
    unsigned precedence; // order of creation
    int key_pattern;
    PatternType ptype;
    int psize;
    char* pattern;
    ActionType action;
    char* action_data;
    CHPApp* chpapp;
};

struct CHPListElement
{
    CHPAction chp_action;
    CHPListElement* next;
};

struct MatchedCHPAction
{
    CHPAction* mpattern;
    int start_match_pos;
    MatchedCHPAction* next;
};

// This is an array element for the dynamically growing tally below
struct CHPMatchCandidate
{
    CHPApp* chpapp;
    int key_pattern_length_sum;
    int key_pattern_countdown;
};

typedef std::vector<CHPMatchCandidate> CHPMatchTally;

struct CHPTallyAndActions
{
    CHPMatchTally match_tally;
    MatchedCHPAction* matches;
};

struct HostUrlDetectorPattern
{
    tMlpPattern host;
    tMlpPattern path;
    tMlpPattern query;
    uint32_t payload_id;
    uint32_t service_id;
    uint32_t client_id;
    AppId appId;
    DHPSequence seq;
    HostUrlDetectorPattern* next;
};

struct HostUrlPatterns
{
    HostUrlDetectorPattern* head;
    HostUrlDetectorPattern* tail;
};

class HttpPatternMatchers
{
public:
    HttpPatternMatchers() { }
    ~HttpPatternMatchers();

    static HttpPatternMatchers* get_instance();
    int finalize();
    void insert_chp_pattern(CHPListElement*);
    void insert_http_pattern_element(enum httpPatternType, HTTPListElement*);
    void remove_http_patterns_for_id(AppId);
    void insert_content_type_pattern(HTTPListElement*);
    void insert_url_pattern(DetectorAppUrlPattern*);
    void insert_rtmp_url_pattern(DetectorAppUrlPattern*);
    void insert_app_url_pattern(DetectorAppUrlPattern*);
    int process_chp_list(CHPListElement*);
    int process_host_patterns(DetectorHTTPPattern*, size_t patternListCount);
    int process_mlmp_patterns();

    void free_matched_chp_actions(MatchedCHPAction* ma);
    void scan_key_chp(PatternType, char* buf, int buf_size, CHPTallyAndActions&);
    AppId scan_chp(PatternType, char*, int, MatchedCHPAction*, char**, char**, char**,
        int*, AppIdHttpSession*, AppIdModuleConfig*);
    AppId scan_header_x_working_with(const uint8_t*, uint32_t, char**);
    int get_appid_by_pattern(const uint8_t*, unsigned, char**);
    bool get_appid_from_url(char*, char*, char**, char*, AppId*, AppId*,
        AppId*, AppId*, unsigned);
    AppId get_appid_by_content_type(const uint8_t*, int);
    void get_server_vendor_version(const uint8_t*, int, char**, char**, AppIdServiceSubtype**);
    void identify_user_agent(const uint8_t*, int, AppId*, AppId*, char**);
    void get_http_offsets(Packet*, AppIdHttpSession*);
    uint32_t parse_multiple_http_patterns(const char* pattern, tMlmpPattern*,
        uint32_t numPartLimit, int level);

private:
    HTTPListElement* hostPayloadPatternList = nullptr;
    HTTPListElement* urlPatternList = nullptr;
    HTTPListElement* clientAgentPatternList = nullptr;
    HTTPListElement* contentTypePatternList = nullptr;
    CHPListElement* chpList = nullptr;
    std::vector<DetectorAppUrlPattern*> app_url_patterns;
    std::vector<DetectorAppUrlPattern*> rtmp_url_patterns;

    SearchTool* url_matcher = nullptr;
    SearchTool* client_agent_matcher = nullptr;
    SearchTool* via_matcher = nullptr;
    SearchTool* content_type_matcher = nullptr;
    SearchTool* field_matcher = nullptr;
    SearchTool* chp_matchers[MAX_PATTERN_TYPE + 1] = { nullptr };
    tMlmpTree* host_url_matcher = nullptr;
    tMlmpTree* rtmp_host_url_matcher = nullptr;
    HostUrlPatterns* host_url_patterns = nullptr;

    void free_app_url_patterns(std::vector<DetectorAppUrlPattern*>&);
    void free_http_elements(HTTPListElement*);
    void free_chp_app_elements();
    int add_mlmp_pattern(void* host_url_matcher,
        const uint8_t* host_pattern, int host_pattern_size, const uint8_t* path_pattern,
        int path_pattern_size, const uint8_t* query_pattern, int query_pattern_size,
        AppId, uint32_t payload_id, uint32_t service_id, uint32_t client_id, DHPSequence);
};

#endif

