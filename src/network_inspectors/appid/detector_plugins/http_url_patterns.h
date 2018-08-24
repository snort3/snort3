//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include <list>
#include <vector>

#include "flow/flow.h"
#include "log/messages.h"
#include "search_engines/search_tool.h"
#include "utils/util.h"

#include "appid_http_session.h"
#include "appid_utils/sf_mlmp.h"
#include "appid_utils/sf_multi_mpse.h"
#include "application_ids.h"

namespace snort
{
struct AppIdServiceSubtype;
struct Packet;
}
class AppIdHttpSession;
class AppIdModuleConfig;

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
    uint32_t client_id;
    uint32_t payload_id;
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
    bool init(const uint8_t* pat, unsigned len, DHPSequence seq, AppId service, AppId client, AppId payload, AppId app)
    {
        if( !pat )
        {
            snort::ErrorMessage("HTTP pattern string is NULL.");
            return false;
        }

        if (seq < SINGLE || seq > USER_AGENT_HEADER)
        {
            snort::ErrorMessage("Invalid HTTP DHP Sequence.");
            return false;
        }

        pattern_size = len;
        pattern = (const uint8_t*)snort::snort_strdup((const char*)pat);
        sequence = seq;
        service_id = service;
        client_id = client;
        payload_id = payload;
        app_id = app;

        return true;
    }

    DHPSequence sequence;
    AppId service_id;
    AppId client_id;
    AppId payload_id;
    AppId app_id;
    unsigned pattern_size;
    const uint8_t* pattern;
};
typedef std::vector<DetectorHTTPPattern> DetectorHTTPPatterns;

// CHP (Complex HTTP Pattern) uses more than one HTTP pattern
// to do appid detection and/or perform other actions
#define CHP_APPID_BITS_FOR_INSTANCE  7
#define CHP_APPID_INSTANCE_MAX (1 << CHP_APPID_BITS_FOR_INSTANCE)
#define CHP_APPIDINSTANCE_TO_ID(_appIdInstance) \
    ((_appIdInstance) >> CHP_APPID_BITS_FOR_INSTANCE)
#define CHP_APPIDINSTANCE_TO_INSTANCE(_appIdInstance) \
    ((_appIdInstance) & (CHP_APPID_INSTANCE_MAX-1))
/*
  NOTE: The following structures have a field called appIdInstance.
    The low-order CHP_APPID_BITS_FOR_INSTANCE bits of appIdInstance field are used
    for the instance value while the remaining bits are used for the appId, shifted left
    that same number of bits. The legacy value for older apis is generated with the
    macro below.
*/
#define CHP_APPID_SINGLE_INSTANCE(_appId) \
    (((_appId) << CHP_APPID_BITS_FOR_INSTANCE) + (CHP_APPID_INSTANCE_MAX-1))

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

struct CHPApp
{
    AppId appIdInstance; // * see note above
    unsigned app_type_flags;
    int num_matches;
    int num_scans;
    int key_pattern_count;
    int key_pattern_length_sum;
    int ptype_scan_counts[NUM_HTTP_FIELDS];
    int ptype_req_counts[NUM_HTTP_FIELDS];
    int ptype_rewrite_insert_used[NUM_HTTP_FIELDS]; // boolean
};

struct CHPAction
{
    AppId appIdInstance; // * see note above
    unsigned precedence; // order of creation
    int key_pattern;
    HttpFieldIds ptype;
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
};

// This is an array element for the dynamically growing tally below
struct CHPMatchCandidate
{
    CHPApp* chpapp;
    int key_pattern_length_sum;
    int key_pattern_countdown;
};

typedef std::vector<CHPMatchCandidate> CHPMatchTally;

class ChpMatchDescriptor
{
public:
    void free_rewrite_buffers()
    {
        for (unsigned i = 0; i < NUM_HTTP_FIELDS; i++)
            if (chp_rewritten[i])
            {
                snort_free((void*)chp_rewritten[i]);
                chp_rewritten[i] = nullptr;
            }
    }

    void sort_chp_matches()
    {
        chp_matches[cur_ptype].sort(ChpMatchDescriptor::comp_chp_actions);
    }

    HttpFieldIds cur_ptype;
    const char* buffer[NUM_HTTP_FIELDS] = { nullptr };
    uint16_t length[NUM_HTTP_FIELDS] = { 0 };
    const char* chp_rewritten[NUM_HTTP_FIELDS] = { nullptr };
    std::list<MatchedCHPAction> chp_matches[NUM_HTTP_FIELDS];
    CHPMatchTally match_tally;

private:
    static bool comp_chp_actions( const MatchedCHPAction& lhs, const MatchedCHPAction& rhs)
    {
        if ( ( lhs.mpattern->appIdInstance < rhs.mpattern->appIdInstance ) ||
             ( lhs.mpattern->appIdInstance == rhs.mpattern->appIdInstance
                  && lhs.mpattern->precedence < rhs.mpattern->precedence ) )
            return true;
        else
            return false;
    }
};

class HostUrlDetectorPattern
{
public:
    HostUrlDetectorPattern(const uint8_t* host_pattern, unsigned length)
    {
        host.pattern = (const uint8_t*)snort::snort_strdup((const char*)host_pattern);
        host.patternSize = length;
    }

    ~HostUrlDetectorPattern()
    {
        snort_free((void*)host.pattern);
        if (path.pattern)
            snort_free((void*)path.pattern);
        if (query.pattern)
            snort_free((void*)query.pattern);
    }

    tMlpPattern host = { nullptr, 0 };
    tMlpPattern path = { nullptr, 0 };
    tMlpPattern query = { nullptr, 0 };
    uint32_t payload_id = APP_ID_NONE;
    uint32_t service_id = APP_ID_NONE;
    uint32_t client_id = APP_ID_NONE;
    AppId appId = APP_ID_NONE;
    DHPSequence seq = SINGLE;
};

class HttpPatternMatchers
{
public:
    HttpPatternMatchers()
        : url_matcher("ac_full", true), client_agent_matcher("ac_full", true), via_matcher("ac_full", true),
          content_type_matcher("ac_full", true)
    { }
    ~HttpPatternMatchers();

    static HttpPatternMatchers* get_instance();
    int finalize_patterns();
    void insert_chp_pattern(CHPListElement*);
    void insert_http_pattern(enum httpPatternType, DetectorHTTPPattern&);
    void remove_http_patterns_for_id(AppId);
    void insert_content_type_pattern(DetectorHTTPPattern&);
    void insert_url_pattern(DetectorAppUrlPattern*);
    void insert_rtmp_url_pattern(DetectorAppUrlPattern*);
    void insert_app_url_pattern(DetectorAppUrlPattern*);
    int process_chp_list(CHPListElement*);
    int process_host_patterns(DetectorHTTPPatterns);
    int process_mlmp_patterns();

    void scan_key_chp(ChpMatchDescriptor&);
    AppId scan_chp(ChpMatchDescriptor&, char**, char**, int*, AppIdHttpSession*,
           const AppIdModuleConfig*);
    AppId scan_header_x_working_with(const char*, uint32_t, char**);
    int get_appid_by_pattern(const char*, unsigned, char**);
    bool get_appid_from_url(char*, const char*, char**, const char*, AppId*, AppId*,
        AppId*, AppId*, bool);
    AppId get_appid_by_content_type(const char*, int);
    void get_server_vendor_version(const char*, int, char**, char**, snort::AppIdServiceSubtype**);
    void identify_user_agent(const char*, int, AppId&, AppId&, char**);
    void get_http_offsets(snort::Packet*, AppIdHttpSession*);
    uint32_t parse_multiple_http_patterns(const char* pattern, tMlmpPattern*,
        uint32_t numPartLimit, int level);

private:
    DetectorHTTPPatterns client_agent_patterns;
    DetectorHTTPPatterns content_type_patterns;
    DetectorHTTPPatterns host_payload_patterns;
    DetectorHTTPPatterns url_patterns;
    std::vector<DetectorAppUrlPattern*> app_url_patterns;
    std::vector<DetectorAppUrlPattern*> rtmp_url_patterns;
    std::vector<HostUrlDetectorPattern*> host_url_patterns;
    CHPListElement* chpList = nullptr;

    snort::SearchTool url_matcher;
    snort::SearchTool client_agent_matcher;
    snort::SearchTool via_matcher;
    snort::SearchTool content_type_matcher;
    snort::SearchTool* field_matcher = nullptr;
    snort::SearchTool* chp_matchers[NUM_HTTP_FIELDS] = { nullptr };
    tMlmpTree* host_url_matcher = nullptr;
    tMlmpTree* rtmp_host_url_matcher = nullptr;

    void free_chp_app_elements();
    int add_mlmp_pattern(tMlmpTree* matcher, DetectorHTTPPattern& pattern );
    int add_mlmp_pattern(tMlmpTree* matcher, DetectorAppUrlPattern& pattern);

};

#endif

