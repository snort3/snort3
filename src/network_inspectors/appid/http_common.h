//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// http_common.h author Sourcefire Inc.

#ifndef HTTP_COMMON_H
#define HTTP_COMMON_H

#include "appid.h"
#include "appid_api.h"
#include "appid_utils/sf_multi_mpse.h"

#include "utils/sflsq.h"

#define MAX_USERNAME_SIZE   64
#define MAX_URL_SIZE        65535

class SearchTool;
struct tMlmpTree;

// FIXIT-M hack to get initial port to build, define these properly
#if 1
struct HttpParsedHeaders
{
    struct HttpBuf
    {
        char* start;
        int len;
    };

    HttpBuf host;
    HttpBuf url;
    HttpBuf userAgent;
    HttpBuf referer;
    HttpBuf via;
    HttpBuf contentType;
    HttpBuf responseCode;
};

#define HTTP_XFF_FIELD_X_FORWARDED_FOR ""
#define HTTP_XFF_FIELD_TRUE_CLIENT_IP ""

#endif

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
    DetectorHTTPPattern detectorHTTPPattern;
    HTTPListElement* next;
};


// These values are used in Lua code as raw numbers. Do NOT reassign new values.
#define APP_TYPE_SERVICE    0x1
#define APP_TYPE_CLIENT     0x2
#define APP_TYPE_PAYLOAD    0x4

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
    MAX_PATTERN_TYPE = BODY_PT,
    MAX_KEY_PATTERN = URI_PT,
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
    int index;
    MatchedCHPAction* next;
};

// This is an array element for the dynamically growing tally below
struct CHPMatchCandidate
{
    CHPApp* chpapp;
    int key_pattern_length_sum;
    int key_pattern_countdown;
};

// FIXIT-M: make the 'item' field a std:vector and refactor code to eliminate realloc calls
struct CHPMatchTally
{
    int allocated_elements;
    int in_use_elements;
    CHPMatchCandidate item[1];
};

// url parts extracted from http headers.
struct UrlStruct
{
    tMlpPattern host;      /*from host header */
    tMlpPattern path;      /*from GET/POST request */
    tMlpPattern scheme;    /*hardcoded to "http:" */
    tMlpPattern query;     /*query match for version number */
};

struct HosUrlDetectorPattern
{
    tMlpPattern host;
    tMlpPattern path;
    tMlpPattern query;
    uint32_t payload_id;
    uint32_t service_id;
    uint32_t client_id;
    AppId appId;
    DHPSequence seq;
    HosUrlDetectorPattern* next;
};

struct HosUrlPatternsList
{
    HosUrlDetectorPattern* head;
    HosUrlDetectorPattern* tail;
};

#endif

