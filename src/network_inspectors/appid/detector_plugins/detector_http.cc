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

// detector_http.cc author Sourcefire Inc.

#include "detector_http.h"

#include "search_engines/search_tool.h"
#include "main/snort_debug.h"
#include "sfip/sf_ip.h"

#include "service_plugins/service_api.h"
#include "service_plugins/service_util.h"
#include "appid_utils/sf_mlmp.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "application_ids.h"
#include "client_plugins/client_app_base.h"
#include "http_url_patterns.h"

/* URL line patterns for identifying client */
#define HTTP_GET "GET "
#define HTTP_PUT "PUT "
#define HTTP_POST "POST "
#define HTTP_HEAD "HEAD "
#define HTTP_TRACE "TRACE "
#define HTTP_DELETE "DELETE "
#define HTTP_OPTIONS "OPTIONS "
#define HTTP_PROPFIND "PROPFIND "
#define HTTP_PROPPATCH "PROPPATCH "
#define HTTP_MKCOL "MKCOL "
#define HTTP_COPY "COPY "
#define HTTP_MOVE "MOVE "
#define HTTP_LOCK "LOCK "
#define HTTP_UNLOCK "UNLOCK "

#define HTTP_GET_SIZE (sizeof(HTTP_GET)-1)
#define HTTP_PUT_SIZE (sizeof(HTTP_PUT)-1)
#define HTTP_POST_SIZE (sizeof(HTTP_POST)-1)
#define HTTP_HEAD_SIZE (sizeof(HTTP_HEAD)-1)
#define HTTP_TRACE_SIZE (sizeof(HTTP_TRACE)-1)
#define HTTP_DELETE_SIZE (sizeof(HTTP_DELETE)-1)
#define HTTP_OPTIONS_SIZE (sizeof(HTTP_OPTIONS)-1)
#define HTTP_PROPFIND_SIZE (sizeof(HTTP_PROPFIND)-1)
#define HTTP_PROPPATCH_SIZE (sizeof(HTTP_PROPPATCH)-1)
#define HTTP_MKCOL_SIZE (sizeof(HTTP_MKCOL)-1)
#define HTTP_COPY_SIZE (sizeof(HTTP_COPY)-1)
#define HTTP_MOVE_SIZE (sizeof(HTTP_MOVE)-1)
#define HTTP_LOCK_SIZE (sizeof(HTTP_LOCK)-1)
#define HTTP_UNLOCK_SIZE (sizeof(HTTP_UNLOCK)-1)

/* media type patterns*/
#define VIDEO_BANNER "video/"
#define AUDIO_BANNER "audio/"
#define APPLICATION_BANNER "application/"
#define QUICKTIME_BANNER "quicktime"
#define MPEG_BANNER "mpeg"
#define MPA_BANNER "mpa"
#define ROBUST_MPA_BANNER "robust-mpa"
#define MP4A_BANNER "mp4a-latm"
#define SHOCKWAVE_BANNER "x-shockwave-flash"
#define RSS_BANNER "rss+xml"
#define ATOM_BANNER "atom+xml"
#define MP4_BANNER "mp4"
#define WMV_BANNER "x-ms-wmv"
#define WMA_BANNER "x-ms-wma"
#define WAV_BANNER "wav"
#define X_WAV_BANNER "x-wav"
#define VND_WAV_BANNER "vnd.wav"
#define FLV_BANNER "x-flv"
#define M4V_BANNER "x-m4v"
#define GPP_BANNER "3gpp"
#define XSCPLS_BANNER "x-scpls"

#define VIDEO_BANNER_MAX_POS (sizeof(VIDEO_BANNER)-2)
#define AUDIO_BANNER_MAX_POS (sizeof(AUDIO_BANNER)-2)
#define APPLICATION_BANNER_MAX_POS (sizeof(APPLICATION_BANNER)-2)
#define QUICKTIME_BANNER_MAX_POS (sizeof(QUICKTIME_BANNER)-2)
#define MPEG_BANNER_MAX_POS (sizeof(MPEG_BANNER)-2)
#define MPA_BANNER_MAX_POS (sizeof(MPA_BANNER)-2)
#define ROBUST_MPA_BANNER_MAX_POS (sizeof(ROBUST_MPA_BANNER)-2)
#define MP4A_BANNER_MAX_POS (sizeof(MP4A_BANNER)-2)
#define SHOCKWAVE_BANNER_MAX_POS (sizeof(SHOCKWAVE_BANNER)-2)
#define RSS_BANNER_MAX_POS (sizeof(RSS_BANNER)-2)
#define ATOM_BANNER_MAX_POS (sizeof(ATOM_BANNER)-2)
#define MP4_BANNER_MAX_POS (sizeof(MP4_BANNER)-2)
#define WMV_BANNER_MAX_POS (sizeof(WMV_BANNER)-2)
#define WMA_BANNER_MAX_POS (sizeof(WMA_BANNER)-2)
#define WAV_BANNER_MAX_POS (sizeof(WAV_BANNER)-2)
#define X_WAV_BANNER_MAX_POS (sizeof(X_WAV_BANNER)-2)
#define VND_WAV_BANNER_MAX_POS (sizeof(VND_WAV_BANNER)-2)
#define FLV_BANNER_MAX_POS (sizeof(FLV_BANNER)-2)
#define M4V_BANNER_MAX_POS (sizeof(M4V_BANNER)-2)
#define GPP_BANNER_MAX_POS (sizeof(GPP_BANNER)-2)
#define XSCPLS_BANNER_MAX_POS (sizeof(XSCPLS_BANNER)-2)

/* version patterns*/
static const char MSIE_PATTERN[] = "MSIE";
static const char KONQUEROR_PATTERN[] = "Konqueror";
static const char SKYPE_PATTERN[] = "Skype";
static const char BITTORRENT_PATTERN[] = "BitTorrent";
static const char FIREFOX_PATTERN[] = "Firefox";
static const char WGET_PATTERN[] = "Wget/";
static const char CURL_PATTERN[] = "curl";
static const char GOOGLE_DESKTOP_PATTERN[] = "Google Desktop";
static const char PICASA_PATTERN[] = "Picasa";
static const char SAFARI_PATTERN[] = "Safari";
static const char OPERA_PATTERN[] = "Opera";
static const char CHROME_PATTERN[] = "Chrome";
static const char MOBILE_PATTERN[] = "Mobile";
static const char BLACKBERRY_PATTERN[] = "BlackBerry";
static const char ANDROID_PATTERN[] = "Android";
static const char MEDIAPLAYER_PATTERN[] = "Windows-Media-Player";
static const char APPLE_EMAIL_PATTERN[] = "Maci";
static const char* APPLE_EMAIL_PATTERNS[] = { "Mozilla/5.0","AppleWebKit","(KHTML, like Gecko)" };

/* "fake" patterns for user-agent matching */
static const char VERSION_PATTERN[] = "Version";
#define VERSION_PATTERN_SIZE (sizeof(VERSION_PATTERN)-1)
#define FAKE_VERSION_APP_ID 3

/* proxy patterns*/
static const char SQUID_PATTERN[] = "squid";
#define SQUID_PATTERN_SIZE (sizeof(SQUID_PATTERN)-1)

static const char MYSPACE_PATTERN[] = "myspace.com";
static const char GMAIL_PATTERN[] = "gmail.com";
static const char GMAIL_PATTERN2[] = "mail.google.com";
static const char AOL_PATTERN[] = "webmail.aol.com";
static const char MSUP_PATTERN[] = "update.microsoft.com";
static const char MSUP_PATTERN2[] = "windowsupdate.com";
static const char YAHOO_MAIL_PATTERN[] = "mail.yahoo.com";
static const char YAHOO_TB_PATTERN[] = "rd.companion.yahoo.com";
static const char ADOBE_UP_PATTERN[] = "swupmf.adobe.com";
static const char HOTMAIL_PATTERN1[] = "hotmail.com";
static const char HOTMAIL_PATTERN2[] = "mail.live.com";
static const char GOOGLE_TB_PATTERN[] = "toolbarqueries.google.com";
#define MYSPACE_PATTERN_SIZE (sizeof(MYSPACE_PATTERN)-1)
#define GMAIL_PATTERN_SIZE (sizeof(GMAIL_PATTERN)-1)
#define GMAIL_PATTERN2_SIZE (sizeof(GMAIL_PATTERN2)-1)
#define AOL_PATTERN_SIZE (sizeof(AOL_PATTERN)-1)
#define MSUP_PATTERN_SIZE (sizeof(MSUP_PATTERN)-1)
#define MSUP_PATTERN2_SIZE (sizeof(MSUP_PATTERN2)-1)
#define YAHOO_MAIL_PATTERN_SIZE (sizeof(YAHOO_MAIL_PATTERN)-1)
#define YAHOO_TB_PATTERN_SIZE (sizeof(YAHOO_TB_PATTERN)-1)
#define ADOBE_UP_PATTERN_SIZE (sizeof(ADOBE_UP_PATTERN)-1)
#define HOTMAIL_PATTERN1_SIZE (sizeof(HOTMAIL_PATTERN1)-1)
#define HOTMAIL_PATTERN2_SIZE (sizeof(HOTMAIL_PATTERN2)-1)
#define GOOGLE_TB_PATTERN_SIZE (sizeof(GOOGLE_TB_PATTERN)-1)

#define COMPATIBLE_BROWSER_STRING " (Compat)"

struct MatchedPatterns
{
    DetectorHTTPPattern* mpattern;
    int index;
    MatchedPatterns* next;
};

static DetectorHTTPPattern content_type_patterns[] =
{
    { SINGLE, 0, APP_ID_QUICKTIME, 0,
      sizeof(QUICKTIME_BANNER)-1, (uint8_t*)QUICKTIME_BANNER, APP_ID_QUICKTIME },
    { SINGLE, 0, APP_ID_MPEG, 0,
      sizeof(MPEG_BANNER)-1, (uint8_t*)MPEG_BANNER, APP_ID_MPEG },
    { SINGLE, 0, APP_ID_MPEG, 0,
      sizeof(MPA_BANNER)-1, (uint8_t*)MPA_BANNER, APP_ID_MPEG },
    { SINGLE, 0, APP_ID_MPEG, 0,
      sizeof(MP4A_BANNER)-1, (uint8_t*)MP4A_BANNER, APP_ID_MPEG },
    { SINGLE, 0, APP_ID_MPEG, 0,
      sizeof(ROBUST_MPA_BANNER)-1, (uint8_t*)ROBUST_MPA_BANNER, APP_ID_MPEG },
    { SINGLE, 0, APP_ID_MPEG, 0,
      sizeof(XSCPLS_BANNER)-1, (uint8_t*)XSCPLS_BANNER, APP_ID_MPEG },
    { SINGLE, 0, APP_ID_SHOCKWAVE, 0,
      sizeof(SHOCKWAVE_BANNER)-1, (uint8_t*)SHOCKWAVE_BANNER, APP_ID_SHOCKWAVE },
    { SINGLE, 0, APP_ID_RSS, 0,
      sizeof(RSS_BANNER)-1, (uint8_t*)RSS_BANNER, APP_ID_RSS },
    { SINGLE, 0, APP_ID_ATOM, 0,
      sizeof(ATOM_BANNER)-1, (uint8_t*)ATOM_BANNER, APP_ID_ATOM },
    { SINGLE, 0, APP_ID_MP4, 0,
      sizeof(MP4_BANNER)-1, (uint8_t*)MP4_BANNER, APP_ID_MP4 },
    { SINGLE, 0, APP_ID_WMV, 0,
      sizeof(WMV_BANNER)-1, (uint8_t*)WMV_BANNER, APP_ID_WMV },
    { SINGLE, 0, APP_ID_WMA, 0,
      sizeof(WMA_BANNER)-1, (uint8_t*)WMA_BANNER, APP_ID_WMA },
    { SINGLE, 0, APP_ID_WAV, 0,
      sizeof(WAV_BANNER)-1, (uint8_t*)WAV_BANNER, APP_ID_WAV },
    { SINGLE, 0, APP_ID_WAV, 0,
      sizeof(X_WAV_BANNER)-1, (uint8_t*)X_WAV_BANNER, APP_ID_WAV },
    { SINGLE, 0, APP_ID_WAV, 0,
      sizeof(VND_WAV_BANNER)-1, (uint8_t*)VND_WAV_BANNER, APP_ID_WAV },
    { SINGLE, 0, APP_ID_FLASH_VIDEO, 0,
      sizeof(FLV_BANNER)-1, (uint8_t*)FLV_BANNER, APP_ID_FLASH_VIDEO },
    { SINGLE, 0, APP_ID_FLASH_VIDEO, 0,
      sizeof(M4V_BANNER)-1, (uint8_t*)M4V_BANNER, APP_ID_FLASH_VIDEO },
    { SINGLE, 0, APP_ID_FLASH_VIDEO, 0,
      sizeof(GPP_BANNER)-1, (uint8_t*)GPP_BANNER, APP_ID_FLASH_VIDEO },
    { SINGLE, 0, APP_ID_GENERIC, 0,
      sizeof(VIDEO_BANNER)-1, (uint8_t*)VIDEO_BANNER, APP_ID_GENERIC },
    { SINGLE, 0, APP_ID_GENERIC, 0,
      sizeof(AUDIO_BANNER)-1, (uint8_t*)AUDIO_BANNER, APP_ID_GENERIC },
};

static DetectorHTTPPattern via_http_detector_patterns[] =
{
    { SINGLE, APP_ID_SQUID, 0, 0,
      SQUID_PATTERN_SIZE, (uint8_t*)SQUID_PATTERN, APP_ID_SQUID },
};

static DetectorHTTPPattern host_payload_http_detector_patterns[] =
{
    { SINGLE, 0, 0, APP_ID_MYSPACE,
      MYSPACE_PATTERN_SIZE, (uint8_t*)MYSPACE_PATTERN, APP_ID_MYSPACE },
    { SINGLE, 0, 0, APP_ID_GMAIL,
      GMAIL_PATTERN_SIZE, (uint8_t*)GMAIL_PATTERN, APP_ID_GMAIL,},
    { SINGLE, 0, 0, APP_ID_GMAIL,
      GMAIL_PATTERN2_SIZE, (uint8_t*)GMAIL_PATTERN2, APP_ID_GMAIL,},
    { SINGLE, 0, 0, APP_ID_AOL_EMAIL,
      AOL_PATTERN_SIZE, (uint8_t*)AOL_PATTERN, APP_ID_AOL_EMAIL,},
    { SINGLE, 0, 0, APP_ID_MICROSOFT_UPDATE,
      MSUP_PATTERN_SIZE, (uint8_t*)MSUP_PATTERN, APP_ID_MICROSOFT_UPDATE,},
    { SINGLE, 0, 0, APP_ID_MICROSOFT_UPDATE,
      MSUP_PATTERN2_SIZE, (uint8_t*)MSUP_PATTERN2, APP_ID_MICROSOFT_UPDATE,},
    { SINGLE, 0, 0, APP_ID_YAHOOMAIL,
      YAHOO_MAIL_PATTERN_SIZE, (uint8_t*)YAHOO_MAIL_PATTERN, APP_ID_YAHOOMAIL,},
    { SINGLE, 0, 0, APP_ID_YAHOO_TOOLBAR,
      YAHOO_TB_PATTERN_SIZE, (uint8_t*)YAHOO_TB_PATTERN, APP_ID_YAHOO_TOOLBAR,},
    { SINGLE, 0, 0, APP_ID_ADOBE_UPDATE,
      ADOBE_UP_PATTERN_SIZE, (uint8_t*)ADOBE_UP_PATTERN, APP_ID_ADOBE_UPDATE,},
    { SINGLE, 0, 0, APP_ID_HOTMAIL,
      HOTMAIL_PATTERN1_SIZE, (uint8_t*)HOTMAIL_PATTERN1, APP_ID_HOTMAIL,},
    { SINGLE, 0, 0, APP_ID_HOTMAIL,
      HOTMAIL_PATTERN2_SIZE, (uint8_t*)HOTMAIL_PATTERN2, APP_ID_HOTMAIL,},
    { SINGLE, 0, 0, APP_ID_GOOGLE_TOOLBAR,
      GOOGLE_TB_PATTERN_SIZE, (uint8_t*)GOOGLE_TB_PATTERN, APP_ID_GOOGLE_TOOLBAR,},
};

static DetectorHTTPPattern client_agent_patterns[] =
{
    { USER_AGENT_HEADER, 0, FAKE_VERSION_APP_ID, 0,
      VERSION_PATTERN_SIZE, (uint8_t*)VERSION_PATTERN, FAKE_VERSION_APP_ID,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_INTERNET_EXPLORER, 0,
      sizeof(MSIE_PATTERN)-1, (uint8_t*)MSIE_PATTERN, APP_ID_INTERNET_EXPLORER,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_KONQUEROR, 0,
      sizeof(KONQUEROR_PATTERN)-1, (uint8_t*)KONQUEROR_PATTERN, APP_ID_KONQUEROR,},
    { USER_AGENT_HEADER, APP_ID_SKYPE_AUTH, APP_ID_SKYPE, 0,
      sizeof(SKYPE_PATTERN)-1, (uint8_t*)SKYPE_PATTERN, APP_ID_SKYPE,},
    { USER_AGENT_HEADER, APP_ID_BITTORRENT, APP_ID_BITTORRENT, 0,
      sizeof(BITTORRENT_PATTERN)-1, (uint8_t*)BITTORRENT_PATTERN, APP_ID_BITTORRENT,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_FIREFOX, 0,
      sizeof(FIREFOX_PATTERN)-1, (uint8_t*)FIREFOX_PATTERN, APP_ID_FIREFOX,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_WGET, 0,
      sizeof(WGET_PATTERN)-1, (uint8_t*)WGET_PATTERN, APP_ID_WGET,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_CURL, 0,
      sizeof(CURL_PATTERN)-1, (uint8_t*)CURL_PATTERN, APP_ID_CURL,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_GOOGLE_DESKTOP, 0,
      sizeof(GOOGLE_DESKTOP_PATTERN)-1, (uint8_t*)GOOGLE_DESKTOP_PATTERN, APP_ID_GOOGLE_DESKTOP,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_PICASA, 0,
      sizeof(PICASA_PATTERN)-1, (uint8_t*)PICASA_PATTERN, APP_ID_PICASA,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_SAFARI, 0,
      sizeof(SAFARI_PATTERN)-1, (uint8_t*)SAFARI_PATTERN, APP_ID_SAFARI,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_OPERA, 0,
      sizeof(OPERA_PATTERN)-1, (uint8_t*)OPERA_PATTERN, APP_ID_OPERA,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_CHROME, 0,
      sizeof(CHROME_PATTERN)-1, (uint8_t*)CHROME_PATTERN, APP_ID_CHROME,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_SAFARI_MOBILE_DUMMY, 0,
      sizeof(MOBILE_PATTERN)-1, (uint8_t*)MOBILE_PATTERN, APP_ID_SAFARI_MOBILE_DUMMY,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_BLACKBERRY_BROWSER, 0,
      sizeof(BLACKBERRY_PATTERN)-1, (uint8_t*)BLACKBERRY_PATTERN, APP_ID_BLACKBERRY_BROWSER,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_ANDROID_BROWSER, 0,
      sizeof(ANDROID_PATTERN)-1, (uint8_t*)ANDROID_PATTERN, APP_ID_ANDROID_BROWSER,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_WINDOWS_MEDIA_PLAYER, 0,
      sizeof(MEDIAPLAYER_PATTERN)-1, (uint8_t*)MEDIAPLAYER_PATTERN, APP_ID_WINDOWS_MEDIA_PLAYER,},
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_APPLE_EMAIL, 0,
      sizeof(APPLE_EMAIL_PATTERN)-1, (uint8_t*)APPLE_EMAIL_PATTERN, APP_ID_APPLE_EMAIL,},
};

struct HeaderPattern
{
    int id;
    uint8_t* data;
    unsigned length;
};

static const char HTTP_HEADER_CONTENT_TYPE[] = "Content-Type: ";
static const char HTTP_HEADER_SERVER_FIELD[] = "Server: ";
static const char HTTP_HEADER_X_WORKING_WITH[] = "X-Working-With: ";
static const char HTTP_HEADER_CRLF[] = "\r";
static const char HTTP_HEADER_LF[] = "\n";

#define HTTP_HEADER_CONTENT_TYPE_SIZE (sizeof(HTTP_HEADER_CONTENT_TYPE)-1)
#define HTTP_HEADER_SERVER_FIELD_SIZE (sizeof(HTTP_HEADER_SERVER_FIELD)-1)
#define HTTP_HEADER_X_WORKING_WITH_SIZE (sizeof(HTTP_HEADER_X_WORKING_WITH)-1)
#define HTTP_HEADER_CRLF_SIZE (sizeof(HTTP_HEADER_CRLF)-1)
#define HTTP_HEADER_LF_SIZE (sizeof(HTTP_HEADER_LF)-1)

static HeaderPattern header_patterns[] =
{
    { HTTP_ID_CONTENT_TYPE, (uint8_t*)HTTP_HEADER_CONTENT_TYPE,HTTP_HEADER_CONTENT_TYPE_SIZE },
    { HTTP_ID_SERVER, (uint8_t*)HTTP_HEADER_SERVER_FIELD,HTTP_HEADER_SERVER_FIELD_SIZE },
    { HTTP_ID_COPY, (uint8_t*)HTTP_COPY, HTTP_COPY_SIZE },
    { HTTP_ID_DELETE, (uint8_t*)HTTP_DELETE, HTTP_DELETE_SIZE },
    { HTTP_ID_GET, (uint8_t*)HTTP_GET, HTTP_GET_SIZE },
    { HTTP_ID_HEAD, (uint8_t*)HTTP_HEAD, HTTP_HEAD_SIZE },
    { HTTP_ID_OPTIONS, (uint8_t*)HTTP_OPTIONS, HTTP_OPTIONS_SIZE },
    { HTTP_ID_PROPFIND, (uint8_t*)HTTP_PROPFIND, HTTP_PROPFIND_SIZE },
    { HTTP_ID_PROPPATCH, (uint8_t*)HTTP_PROPPATCH, HTTP_PROPPATCH_SIZE },
    { HTTP_ID_MKCOL, (uint8_t*)HTTP_MKCOL, HTTP_MKCOL_SIZE },
    { HTTP_ID_LOCK, (uint8_t*)HTTP_LOCK, HTTP_LOCK_SIZE },
    { HTTP_ID_MOVE, (uint8_t*)HTTP_MOVE, HTTP_MOVE_SIZE },
    { HTTP_ID_PUT, (uint8_t*)HTTP_PUT, HTTP_PUT_SIZE },
    { HTTP_ID_TRACE, (uint8_t*)HTTP_TRACE, HTTP_TRACE_SIZE },
    { HTTP_ID_UNLOCK, (uint8_t*)HTTP_UNLOCK, HTTP_UNLOCK_SIZE },
    { HTTP_ID_X_WORKING_WITH, (uint8_t*)HTTP_HEADER_X_WORKING_WITH,
      HTTP_HEADER_X_WORKING_WITH_SIZE },
    { HTTP_ID_LEN, (uint8_t*)HTTP_HEADER_CRLF, HTTP_HEADER_CRLF_SIZE },
    { HTTP_ID_LEN, (uint8_t*)HTTP_HEADER_LF, HTTP_HEADER_LF_SIZE }
};

class DetectorHttpConfig
{
public:
    DetectorHttpConfig() {}
    ~DetectorHttpConfig() {}

    SearchTool* url_matcher = nullptr;
    SearchTool* client_agent_matcher = nullptr;
    SearchTool* via_matcher = nullptr;
    tMlmpTree* host_url_matcher = nullptr;
    tMlmpTree* RTMPHosUrlMatcher = nullptr;
    SearchTool* header_matcher = nullptr;
    SearchTool* content_type_matcher = nullptr;
    SearchTool* field_matcher = nullptr;
    SearchTool* chp_matchers[MAX_PATTERN_TYPE + 1] = { nullptr };
    HosUrlPatternsList* hosUrlPatternsList = nullptr;
};

static THREAD_LOCAL DetectorHttpConfig* detectorHttpConfig = nullptr;

#define URL_LIST_STEP_SIZE  5000
class HttpPatternLists
{
public:
    HttpPatternLists() {}
    ~HttpPatternLists() {}

    HTTPListElement* hostPayloadPatternList = nullptr;
    HTTPListElement* urlPatternList = nullptr;
    HTTPListElement* clientAgentPatternList = nullptr;
    HTTPListElement* contentTypePatternList = nullptr;
    CHPListElement* chpList = nullptr;
    std::vector<DetectorAppUrlPattern*> app_url_patterns;
    std::vector<DetectorAppUrlPattern*> rtmp_url_patterns;
};

static THREAD_LOCAL HttpPatternLists* httpPatternLists = nullptr;

void init_http_detector()
{
    httpPatternLists = new HttpPatternLists;
}

static void FreeDetectorAppUrlPattern(DetectorAppUrlPattern* pattern)
{
    if (pattern)
    {
        if (pattern->userData.query.pattern)
            snort_free(*(void**)&pattern->userData.query.pattern);
        if (pattern->patterns.host.pattern)
            snort_free(*(void**)&pattern->patterns.host.pattern);
        if (pattern->patterns.path.pattern)
            snort_free(*(void**)&pattern->patterns.path.pattern);
        if (pattern->patterns.scheme.pattern)
            snort_free(*(void**)&pattern->patterns.scheme.pattern);
        snort_free(pattern);
    }
}

void insert_chp_pattern(CHPListElement* chpa)
{
    CHPListElement* tmp_chpa = httpPatternLists->chpList;
    if (!tmp_chpa)
        httpPatternLists->chpList = chpa;
    else
    {
        while (tmp_chpa->next)
            tmp_chpa = tmp_chpa->next;
        tmp_chpa->next = chpa;
    }
}

void insert_http_pattern_element(enum httpPatternType pType, HTTPListElement* element)
{
    switch (pType)
    {
    case HTTP_PAYLOAD:
        element->next = httpPatternLists->hostPayloadPatternList;
        httpPatternLists->hostPayloadPatternList = element;
        break;
    case HTTP_URL:
        element->next = httpPatternLists->urlPatternList;
        httpPatternLists->urlPatternList = element;
        break;
    case HTTP_USER_AGENT:
        element->next = httpPatternLists->clientAgentPatternList;
        httpPatternLists->clientAgentPatternList = element;
        break;
    }
}

void remove_http_patterns_for_id( AppId id )
{
    // Walk the list of all the patterns we have inserted, searching for this appIdInstance and free them.
    // The purpose is for the 14 and 15 to be used together to only set the APPINFO_FLAG_SEARCH_ENGINE flag
    // If the reserved pattern is not used, it is a mixed use case and should just behave normally.
    CHPListElement* chpa = nullptr;
    CHPListElement* prev_chpa = nullptr;
    CHPListElement* tmp_chpa = httpPatternLists->chpList;
    while (tmp_chpa)
    {
        if (tmp_chpa->chp_action.appIdInstance == id)
        {
            // advance the tmp_chpa pointer by removing the item pointed to. Keep prev_chpa unchanged.

            // 1) unlink the struct, 2) free strings and then 3) free the struct.
            chpa = tmp_chpa; // preserve this pointer to be freed at the end.
            if (prev_chpa == NULL)
            {
                // Remove from head
                httpPatternLists->chpList = tmp_chpa->next;
                tmp_chpa = httpPatternLists->chpList;
            }
            else
            {
                // Remove from middle of list.
                prev_chpa->next = tmp_chpa->next;
                tmp_chpa = prev_chpa->next;
            }
            snort_free(chpa->chp_action.pattern);
            if (chpa->chp_action.action_data)
                snort_free(chpa->chp_action.action_data);
            snort_free(chpa);
        }
        else
        {
            // advance both pointers
            prev_chpa = tmp_chpa;
            tmp_chpa = tmp_chpa->next;
        }
    }
}

void insert_content_type_pattern(HTTPListElement* element)
{
    element->next = httpPatternLists->contentTypePatternList;
    httpPatternLists->contentTypePatternList = element;
}

void insert_url_pattern(DetectorAppUrlPattern* pattern)
{
    httpPatternLists->app_url_patterns.push_back(pattern);
}

void insert_rtmp_url_pattern(DetectorAppUrlPattern* pattern)
{
    httpPatternLists->rtmp_url_patterns.push_back(pattern);
}

void insert_app_url_pattern(DetectorAppUrlPattern* pattern)
{
    insert_url_pattern( pattern );
}

static void FreeHTTPListElement(HTTPListElement* element)
{
    if (element)
    {
        if (element->detectorHTTPPattern.pattern)
            snort_free(element->detectorHTTPPattern.pattern);
        snort_free(element);
    }
}

static void FreeCHPAppListElement(CHPListElement* element)
{
    if (element)
    {
        if (element->chp_action.pattern)
            snort_free(element->chp_action.pattern);
        if (element->chp_action.action_data)
            snort_free(element->chp_action.action_data);
        snort_free (element);
    }
}

static void CleanHttpPatternLists()
{
    HTTPListElement* element;
    CHPListElement* chpe;

    for(auto* pattern: httpPatternLists->app_url_patterns)
        FreeDetectorAppUrlPattern(pattern);

    httpPatternLists->app_url_patterns.clear();

    for(auto* pattern: httpPatternLists->rtmp_url_patterns)
        FreeDetectorAppUrlPattern(pattern);

    httpPatternLists->rtmp_url_patterns.clear();

    while ((element = httpPatternLists->clientAgentPatternList))
    {
        httpPatternLists->clientAgentPatternList = element->next;
        FreeHTTPListElement(element);
    }
    while ((element = httpPatternLists->hostPayloadPatternList))
    {
        httpPatternLists->hostPayloadPatternList = element->next;
        FreeHTTPListElement(element);
    }
    while ((element = httpPatternLists->urlPatternList))
    {
        httpPatternLists->urlPatternList = element->next;
        FreeHTTPListElement(element);
    }
    while ((element = httpPatternLists->contentTypePatternList))
    {
        httpPatternLists->contentTypePatternList = element->next;
        FreeHTTPListElement(element);
    }
    while ((chpe = httpPatternLists->chpList))
    {
        httpPatternLists->chpList = chpe->next;
        FreeCHPAppListElement(chpe);
    }
}

static int content_pattern_match(void* id, void*, int index, void* data, void*)
{
    MatchedPatterns* cm;
    MatchedPatterns** matches = (MatchedPatterns**)data;
    DetectorHTTPPattern* target = (DetectorHTTPPattern*)id;

    cm = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    cm->mpattern = target;
    cm->index = index;
    cm->next = *matches;
    *matches = cm;

    return 0;
}

static int chp_pattern_match(void* id, void*, int index, void* data, void*)
{
    MatchedCHPAction* new_match;
    MatchedCHPAction* current_search;
    MatchedCHPAction* prev_search;
    MatchedCHPAction** matches = (MatchedCHPAction**)data;
    CHPAction* target = (CHPAction*)id;

    new_match = (MatchedCHPAction*)snort_calloc(sizeof(MatchedCHPAction));
    new_match->mpattern = target;
    new_match->index = index;

    // preserving order is required: sort by appIdInstance, then by precedence
    for (current_search = *matches, prev_search = nullptr;
        nullptr != current_search;
        prev_search = current_search, current_search = current_search->next)
    {
        CHPAction* match_data = current_search->mpattern;
        if (target->appIdInstance < match_data->appIdInstance)
            break;
        if (target->appIdInstance == match_data->appIdInstance)
        {
            if (target->precedence < match_data->precedence)
                break;
        }
    }

    if (prev_search)
    {
        new_match->next = prev_search->next;
        prev_search->next = new_match;
    }
    else
    {
        // insert at head of list.
        new_match->next = *matches;
        *matches = new_match;
    }

    return 0;
}

static inline void chp_add_candidate_to_tally(CHPMatchTally& match_tally, CHPApp* chpapp)
{
    for (auto& item: match_tally)
    {
        if (chpapp == item.chpapp)
        {
            item.key_pattern_countdown--;
            return;
        }
    }

    match_tally.push_back({chpapp, chpapp->key_pattern_length_sum, chpapp->key_pattern_count - 1});
}

// In addition to creating the linked list of matching actions this function will
// create the CHPMatchTally needed to find the longest matching pattern.
static int chp_key_pattern_match(void* id, void*, int index, void* data, void*)
{
    CHPTallyAndActions* chp = (CHPTallyAndActions*)data;
    CHPAction* target = (CHPAction*)id;

    if (target->key_pattern)
    {
        // We have a match from a key pattern. We need to have it's parent chpapp represented in
        // the tally. If the chpapp has never been seen then add an item to the tally's array
        // else decrement the count of expected key_patterns until zero so that we know when we
        // have them all.
        chp_add_candidate_to_tally(chp->match_tally, target->chpapp);
    }

    return chp_pattern_match(id, nullptr, index, &chp->matches, nullptr);
}

static int http_pattern_match(void* id, void*, int index, void* data, void*)
{
    MatchedPatterns* cm = nullptr;
    MatchedPatterns** tmp;
    MatchedPatterns** matches = (MatchedPatterns**)data;
    DetectorHTTPPattern* target = (DetectorHTTPPattern*)id;

    // make sure we haven't already seen this pattern
    for (tmp = matches; *tmp; tmp = &(*tmp)->next)
        cm = *tmp;

    if (!*tmp)
    {
        cm = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
        cm->mpattern = target;
        cm->index = index + 1;
        cm->next = nullptr;
        *tmp = cm;
    }

    /* if its one of the host patterns, return after first match*/
    if (cm->mpattern->seq == SINGLE)
        return 1;
    else
        return 0;
}

static SearchTool* processPatterns(DetectorHTTPPattern* patternList,
    size_t patternListCount, size_t*, HTTPListElement* luaPatternList)
{
    SearchTool* patternMatcher = new SearchTool("ac_full");

    for (uint32_t i = 0; i < patternListCount; i++)
        patternMatcher->add(patternList[i].pattern, patternList[i].pattern_size,
            &patternList[i], false);

    /* Add patterns from Lua API */
    HTTPListElement* element;
    for (element = luaPatternList; element != 0; element = element->next)
        patternMatcher->add(element->detectorHTTPPattern.pattern,
            element->detectorHTTPPattern.pattern_size, &element->detectorHTTPPattern, false);

    patternMatcher->prep();
    return patternMatcher;
}

static int processHostPatterns(DetectorHTTPPattern* patternList, size_t patternListCount)
{
    HTTPListElement* element;

    if (!detectorHttpConfig->host_url_matcher)
        detectorHttpConfig->host_url_matcher = mlmpCreate();

    if (!detectorHttpConfig->RTMPHosUrlMatcher)
        detectorHttpConfig->RTMPHosUrlMatcher = mlmpCreate();

    for (uint32_t i = 0; i < patternListCount; i++)
    {
        if (addMlmpPattern(detectorHttpConfig->host_url_matcher,  &detectorHttpConfig->hosUrlPatternsList,
            patternList[i].pattern, patternList[i].pattern_size,
            nullptr, 0, nullptr, 0, patternList[i].appId, patternList[i].payload,
            patternList[i].service_id,
            patternList[i].client_app, patternList[i].seq) < 0)
            return -1;
    }

    for (element = httpPatternLists->hostPayloadPatternList; element != 0; element = element->next)
    {
        if (addMlmpPattern(detectorHttpConfig->host_url_matcher, &detectorHttpConfig->hosUrlPatternsList,
            element->detectorHTTPPattern.pattern, element->detectorHTTPPattern.pattern_size,
            nullptr, 0, nullptr, 0, element->detectorHTTPPattern.appId,
            element->detectorHTTPPattern.payload, element->detectorHTTPPattern.service_id,
            element->detectorHTTPPattern.client_app, element->detectorHTTPPattern.seq) < 0)
            return -1;
    }

    for (auto* pattern: httpPatternLists->rtmp_url_patterns)
    {
        if (addMlmpPattern(detectorHttpConfig->RTMPHosUrlMatcher, &detectorHttpConfig->hosUrlPatternsList,
            pattern->patterns.host.pattern, pattern->patterns.host.patternSize,
            pattern->patterns.path.pattern, pattern->patterns.path.patternSize,
            pattern->userData.query.pattern, pattern->userData.query.patternSize,
            pattern->userData.appId,         pattern->userData.payload,
            pattern->userData.service_id,    pattern->userData.client_app,
            SINGLE) < 0)
            return -1;
    }

    for (auto* pattern: httpPatternLists->app_url_patterns)
    {
        if (addMlmpPattern(detectorHttpConfig->host_url_matcher, &detectorHttpConfig->hosUrlPatternsList,
            pattern->patterns.host.pattern, pattern->patterns.host.patternSize,
            pattern->patterns.path.pattern, pattern->patterns.path.patternSize,
            pattern->userData.query.pattern, pattern->userData.query.patternSize,
            pattern->userData.appId,         pattern->userData.payload,
            pattern->userData.service_id,    pattern->userData.client_app,
            SINGLE) < 0)
            return -1;
    }

    mlmpProcessPatterns(detectorHttpConfig->host_url_matcher);
    mlmpProcessPatterns(detectorHttpConfig->RTMPHosUrlMatcher);
    return 0;
}

static SearchTool* processContentTypePatterns(DetectorHTTPPattern* patternList,
    size_t patternListCount, HTTPListElement* luaPatternList, size_t*)
{
    SearchTool* patternMatcher = new SearchTool("ac_full");
    HTTPListElement* element;

    for (uint32_t i = 0; i < patternListCount; i++)
    {
        patternMatcher->add(patternList[i].pattern, patternList[i].pattern_size,
            &patternList[i], false);
    }

    // Add patterns from Lua API
    for (element = luaPatternList; element; element = element->next)
    {
        patternMatcher->add(element->detectorHTTPPattern.pattern,
            element->detectorHTTPPattern.pattern_size,
            &element->detectorHTTPPattern, false);
    }

    patternMatcher->prep();

    return patternMatcher;
}

static int processCHPList(CHPListElement* chplist)
{
    CHPListElement* chpe;

    for (size_t i = 0; i <= MAX_PATTERN_TYPE; i++)
    {
        detectorHttpConfig->chp_matchers[i] = new SearchTool("ac_full");
        if (!detectorHttpConfig->chp_matchers[i])
            return 0;
    }

    for (chpe = chplist; chpe; chpe = chpe->next)
    {
        detectorHttpConfig->chp_matchers[chpe->chp_action.ptype]->add(chpe->chp_action.pattern,
            chpe->chp_action.psize,
            &chpe->chp_action,
            true);
    }

    for (size_t i = 0; i < sizeof(detectorHttpConfig->chp_matchers)/sizeof(detectorHttpConfig->chp_matchers[0]);
        i++)
        detectorHttpConfig->chp_matchers[i]->prep();

    return 1;
}

static SearchTool* registerHeaderPatterns(HeaderPattern* patternList, size_t patternListCount)
{
    SearchTool* patternMatcher = new SearchTool("ac_full");

    for (uint32_t i = 0; i < patternListCount; i++)
        patternMatcher->add(patternList[i].data, patternList[i].length, &patternList[i], true);

    patternMatcher->prep();

    return patternMatcher;
}

#define HTTP_FIELD_PREFIX_USER_AGENT    "\r\nUser-Agent: "
#define HTTP_FIELD_PREFIX_USER_AGENT_SIZE (sizeof(HTTP_FIELD_PREFIX_USER_AGENT)-1)
#define HTTP_FIELD_PREFIX_HOST    "\r\nHost: "
#define HTTP_FIELD_PREFIX_HOST_SIZE (sizeof(HTTP_FIELD_PREFIX_HOST)-1)
#define HTTP_FIELD_PREFIX_REFERER    "\r\nReferer: "
#define HTTP_FIELD_PREFIX_REFERER_SIZE (sizeof(HTTP_FIELD_PREFIX_REFERER)-1)
#define HTTP_FIELD_PREFIX_URI    " "
#define HTTP_FIELD_PREFIX_URI_SIZE (sizeof(HTTP_FIELD_PREFIX_URI)-1)
#define HTTP_FIELD_PREFIX_COOKIE    "\r\nCookie: "
#define HTTP_FIELD_PREFIX_COOKIE_SIZE (sizeof(HTTP_FIELD_PREFIX_COOKIE)-1)

typedef struct _FIELD_PATTERN
{
    PatternType patternType;
    uint8_t* data;
    unsigned length;
} FieldPattern;

static FieldPattern http_field_patterns[] =
{
    {URI_PT, (uint8_t*) HTTP_FIELD_PREFIX_URI, HTTP_FIELD_PREFIX_URI_SIZE},
    {HOST_PT, (uint8_t*) HTTP_FIELD_PREFIX_HOST,HTTP_FIELD_PREFIX_HOST_SIZE},
    {REFERER_PT, (uint8_t*) HTTP_FIELD_PREFIX_REFERER, HTTP_FIELD_PREFIX_REFERER_SIZE},
    {COOKIE_PT, (uint8_t*) HTTP_FIELD_PREFIX_COOKIE, HTTP_FIELD_PREFIX_COOKIE_SIZE},
    {AGENT_PT, (uint8_t*) HTTP_FIELD_PREFIX_USER_AGENT,HTTP_FIELD_PREFIX_USER_AGENT_SIZE},
};

static SearchTool* processHttpFieldPatterns(FieldPattern* patternList, size_t patternListCount)
{
    u_int32_t i;

    SearchTool* patternMatcher = new SearchTool("ac_full");

    for (i=0; i < patternListCount; i++)
        patternMatcher->add( (char  *)patternList[i].data, patternList[i].length,
                             &patternList[i], false);

    patternMatcher->prep();
    return patternMatcher;
}

typedef struct fieldPatternData_t
{
    const uint8_t*payload;
    unsigned length;
    httpSession *hsession;
} FieldPatternData;

static int http_field_pattern_match(void *id, void *, int index, void *data, void *)
{
    static const uint8_t crlf[] = "\r\n";
    static unsigned crlfLen = sizeof(crlf)-1;
    FieldPatternData *pFieldData = (FieldPatternData*)data;
    FieldPattern *target = (FieldPattern  *)id;
    const uint8_t* p;
    unsigned fieldOffset = target->length + index;
    unsigned remainingLength = pFieldData->length - fieldOffset;

    if (!(p = (uint8_t*)service_strstr(&pFieldData->payload[fieldOffset], remainingLength, crlf, crlfLen)))
    {
        return 1;
    }
    pFieldData->hsession->fieldOffset[target->patternType] = (uint16_t)fieldOffset;
    pFieldData->hsession->fieldEndOffset[target->patternType] = p - pFieldData->payload;
    return 1;
}

void httpGetNewOffsetsFromPacket(Packet *pkt, httpSession *hsession)
{
    constexpr auto MIN_HTTP_REQ_HEADER_SIZE = (sizeof("GET /\r\n\r\n") - 1);
    static const uint8_t crlfcrlf[] = "\r\n\r\n";
    static unsigned crlfcrlfLen = sizeof(crlfcrlf) - 1;
    uint8_t*headerEnd;
    unsigned fieldId;
    FieldPatternData patternMatchData;

    for (fieldId = AGENT_PT; fieldId <= COOKIE_PT; fieldId++)
        hsession->fieldOffset[fieldId] = 0;


    if (!pkt->data || pkt->dsize < MIN_HTTP_REQ_HEADER_SIZE)
        return;

    patternMatchData.hsession = hsession;
    patternMatchData.payload = pkt->data;

    if (!(headerEnd = (uint8_t*)service_strstr(pkt->data, pkt->dsize, crlfcrlf, crlfcrlfLen)))
        return;

    headerEnd += crlfcrlfLen;
    patternMatchData.length = (unsigned)(headerEnd - pkt->data);
    detectorHttpConfig->field_matcher->find_all((char*)pkt->data, patternMatchData.length,
                   &http_field_pattern_match, false, (void*)(&patternMatchData));

}

int finalize_http_detector()
{
    size_t upc = 0;
    size_t apc = 0;
    size_t ctc = 0;
    size_t vpc = 0;
    uint32_t numPatterns;

    detectorHttpConfig = new DetectorHttpConfig;

    /*create via pattern matcher */
    numPatterns = sizeof(via_http_detector_patterns)/sizeof(*via_http_detector_patterns);
    detectorHttpConfig->via_matcher = processPatterns(via_http_detector_patterns, numPatterns, &vpc,
        nullptr);
    if (!detectorHttpConfig->via_matcher)
        return -1;

    /*create url pattern matcher */
    detectorHttpConfig->url_matcher = processPatterns(nullptr, 0, &upc, httpPatternLists->urlPatternList);
    if (!detectorHttpConfig->url_matcher)
        return -1;

    /*create client agent pattern matcher */
    numPatterns = sizeof(client_agent_patterns)/sizeof(*client_agent_patterns);
    detectorHttpConfig->client_agent_matcher = processPatterns(client_agent_patterns,numPatterns,
            &apc, httpPatternLists->clientAgentPatternList);
    if (!detectorHttpConfig->client_agent_matcher)
        return -1;

    numPatterns = sizeof(header_patterns)/sizeof(*header_patterns);
    detectorHttpConfig->header_matcher = registerHeaderPatterns(header_patterns, numPatterns);
    if (!detectorHttpConfig->header_matcher)
        return -1;

    numPatterns = sizeof(host_payload_http_detector_patterns)/
        sizeof(*host_payload_http_detector_patterns);
    if (processHostPatterns(host_payload_http_detector_patterns, numPatterns) < 0)
        return -1;

    numPatterns = sizeof(content_type_patterns)/sizeof(*content_type_patterns);
    detectorHttpConfig->content_type_matcher = processContentTypePatterns(content_type_patterns,
        numPatterns, httpPatternLists->contentTypePatternList, &ctc);
    if (!detectorHttpConfig->content_type_matcher)
        return -1;

    numPatterns = sizeof(http_field_patterns)/sizeof(*http_field_patterns);
    detectorHttpConfig->field_matcher = processHttpFieldPatterns(http_field_patterns, numPatterns);
    if (!detectorHttpConfig->field_matcher)
        return -1;

    if (!processCHPList(httpPatternLists->chpList))
        return -1;

    return 0;
}

void clean_http_detector()
{
    delete detectorHttpConfig->via_matcher;
    delete detectorHttpConfig->url_matcher;
    delete detectorHttpConfig->client_agent_matcher;
    delete detectorHttpConfig->header_matcher;
    delete detectorHttpConfig->content_type_matcher;
    delete detectorHttpConfig->field_matcher;

    for (size_t i = 0; i <= MAX_PATTERN_TYPE; i++)
         delete detectorHttpConfig->chp_matchers[i];

    destroyHosUrlMatcher(&detectorHttpConfig->host_url_matcher);
    destroyHosUrlMatcher(&detectorHttpConfig->RTMPHosUrlMatcher);
    destroyHosUrlPatternList(&detectorHttpConfig->hosUrlPatternsList);

    CleanHttpPatternLists();
    delete httpPatternLists;
    delete detectorHttpConfig;
}

static inline void FreeMatchStructures(MatchedPatterns* mp)
{
    MatchedPatterns* tmp;

    while (mp)
    {
        tmp = mp;
        mp = mp->next;
        snort_free(tmp);
    }
}

static void rewriteCHP(const char* buf, int bs, int start,
    int psize, char* adata, char** outbuf,
    int insert)
{
    int maxs, bufcont, as;
    char* copyPtr;

    // special behavior for insert vs. rewrite
    if (insert)
    {
        // we don't want to insert a string that is already present
        if (!adata || strcasestr((const char*)buf, adata))
            return;

        start += psize;
        bufcont = start;
        as = strlen(adata);
        maxs = bs+as;
    }
    else
    {
        if (adata)
        {
            // we also don't want to replace a string with an identical one.
            if (!strncmp(buf+start,adata,psize))
                return;

            as = strlen(adata);
        }
        else
            as = 0;

        bufcont = start+psize;
        maxs = bs+(as-psize);
    }

    *outbuf = copyPtr = (char*)snort_calloc(maxs + 1);
    memcpy(copyPtr, buf, start);
    copyPtr += start;
    if (adata)
    {
        memcpy(copyPtr, adata, as);
        copyPtr += as;
    }
    memcpy(copyPtr, buf+bufcont, bs-bufcont);
}

static char* normalize_userid(char* user)
{
    int i, old_size;
    int percent_count = 0;
    char a, b;
    char* tmp_ret, *tmp_user;

    old_size = strlen(user);

    // find number of '%'
    for (i = 0; i < old_size; i++)
    {
        if (*(user + i) == '%')
            percent_count++;
    }
    if (0 == percent_count)
    {
        /* no change allows an early out */
        return user;
    }

    /* Shrink user string in place */
    tmp_ret = user;
    tmp_user = user;

    while (*tmp_user)
    {
        if ((*tmp_user == '%') &&
            ((a = tmp_user[1]) && (b = tmp_user[2])) &&
            (isxdigit(a) && isxdigit(b)))
        {
            if (a >= 'a')
                a -= 'a'-'A';

            if (a >= 'A')
                a -= ('A' - 10);
            else
                a -= '0';

            if (b >= 'a')
                b -= 'a'-'A';

            if (b >= 'A')
                b -= ('A' - 10);
            else
                b -= '0';

            *tmp_ret++ = 16*a+b;
            tmp_user+=3;
        }
        else
        {
            *tmp_ret++ = *tmp_user++;
        }
    }
    *tmp_ret++ = '\0';

    return user;
}

static void extractCHP(char* buf, int bs, int start, int psize, char* adata,  char** outbuf)
{
    char* begin = buf + start + psize;
    char* end = nullptr;
    char* tmp;
    int i, as;

    if (adata)
        as = strlen(adata);
    else
        as = 0;

    // find where the pattern ends so we can allocate a buffer
    for (i = 0; i < as; i++)
    {
        tmp = strchr(begin, *(adata+i));
        if (tmp)
        {
            if ((!end) || (end && tmp < end))
                end = tmp;
        }
    }
    if (!end)
    {
        if ((tmp = strchr(begin, 0x0d)))
        {
            end = tmp;
        }
        if ((tmp = strchr(begin, 0x0a)))
        {
            if ((!end) || (end && tmp < end))
                end = tmp;
        }
    }

    if (!end)
        end = begin+bs;

    *outbuf = snort_strndup(begin, end-begin);
}

void scan_key_chp(PatternType ptype, char* buf, int buf_size, CHPTallyAndActions& match_tally)
{
    detectorHttpConfig->chp_matchers[ptype]->find_all(buf, buf_size, &chp_key_pattern_match,
        false, (void*)(&match_tally));
}

AppId scan_chp(PatternType ptype, char* buf, int buf_size, MatchedCHPAction* mp, char** version,
        char** user, char** new_field, int* total_found, httpSession* hsession, Packet*)
{
    MatchedCHPAction* second_sweep_for_inserts = nullptr;
    int do_not_further_modify_field = 0;
    CHPAction* match = nullptr;
    AppId ret = APP_ID_NONE;
    MatchedCHPAction* tmp;

    if (ptype > MAX_KEY_PATTERN)
    {
        // There is no previous attempt to match generated by scan_key_chp()
        mp = nullptr;
        detectorHttpConfig->chp_matchers[ptype]->find_all(buf, buf_size, &chp_pattern_match,
            false, (void*)(&mp));
    }
    if (!mp)
        return APP_ID_NONE;

    if (AppIdConfig::get_appid_config()->mod_config->disable_safe_search)
    {
        new_field = nullptr;
    }

    for (tmp = mp; tmp; tmp = tmp->next)
    {
        match = (CHPAction*)tmp->mpattern;
        if (match->appIdInstance > hsession->chp_candidate)
            break; // because the list is sorted we know there are no more
        else if (match->appIdInstance == hsession->chp_candidate)
        {
            switch (match->action)
            {
            case DEFER_TO_SIMPLE_DETECT:
                // Ignore all other patterns; we are done.
                free_matched_chp_actions(mp);
                // Returning APP_ID_NONE will trigger the clearing of hsession->skip_simple_detect
                // and the freeing of any planned field rewrites.
                return APP_ID_NONE;
                break;

            default:
                (*total_found)++;
                break;

            case ALTERNATE_APPID:     // an "optional" action that doesn't count towards totals
            case REWRITE_FIELD:       // handled when the action completes successfully
            case INSERT_FIELD:        // handled when the action completes successfully
                break;
            }
            if (!ret)
                ret = hsession->chp_candidate;
        }
        else
            continue; // keep looking

        switch (match->action)
        {
        case COLLECT_VERSION:
            if (!*version)
                extractCHP(buf, buf_size, tmp->index, match->psize,
                    match->action_data, version);
            hsession->skip_simple_detect = true;
            break;
        case EXTRACT_USER:
            if (!*user && !AppIdConfig::get_appid_config()->mod_config->chp_userid_disabled)
            {
                extractCHP(buf, buf_size, tmp->index, match->psize,
                    match->action_data, user);
                if (*user)
                    *user = normalize_userid(*user);
            }
            break;
        case REWRITE_FIELD:
            if (!do_not_further_modify_field &&
                nullptr != new_field &&
                nullptr == *new_field)
            {
                // The field supports rewrites, and a rewrite hasn't happened.
                rewriteCHP(buf, buf_size, tmp->index, match->psize,
                    match->action_data, new_field, 0);
                (*total_found)++;
                do_not_further_modify_field = 1;
            }
            break;
        case INSERT_FIELD:
            if (!do_not_further_modify_field && second_sweep_for_inserts == nullptr)
            {
                if (match->action_data)
                {
                    // because this insert is the first one we have come across
                    // we only need to remember this ONE for later.
                    second_sweep_for_inserts = tmp;
                }
                else
                {
                    // This is an attempt to "insert nothing"; call it a match
                    // The side effect is to set the do_not_further_modify_field to 1 (true)

                    // Note that an attempt to "rewrite with identical string"
                    // is NOT equivalent to an "insert nothing" because of case-
                    //  insensitive pattern matching

                    do_not_further_modify_field = 1;
                    (*total_found)++;
                }
            }
            break;

        case ALTERNATE_APPID:
            hsession->chp_alt_candidate = strtol(match->action_data, nullptr, 10);
            hsession->skip_simple_detect = true;
            break;

        case HOLD_FLOW:
            hsession->chp_hold_flow = 1;
            break;

        case GET_OFFSETS_FROM_REBUILT:
            hsession->get_offsets_from_rebuilt = 1;
            hsession->chp_hold_flow = 1;
            break;

        case SEARCH_UNSUPPORTED:
        case NO_ACTION:
            hsession->skip_simple_detect = true;
            break;
        default:
            break;
        }
    }
    // non-nullptr second_sweep_for_inserts indicates the insert action we will use.
    if (!do_not_further_modify_field && second_sweep_for_inserts &&
        nullptr != new_field &&
        nullptr == *new_field)
    {
        // We will take the first INSERT_FIELD with an action string,
        // which was decided with the setting of second_sweep_for_inserts.
        rewriteCHP(buf, buf_size, second_sweep_for_inserts->index,
            second_sweep_for_inserts->mpattern->psize,
            second_sweep_for_inserts->mpattern->action_data,
            new_field, 1);     // insert
        (*total_found)++;
    }

    free_matched_chp_actions(mp);
    return ret;
}

static inline int optionallyReplaceWithStrdup(char** optionalStr, const char* strToDup)
{
    if (optionalStr)
    {
        if (*optionalStr)
            snort_free(*optionalStr);

        *optionalStr = snort_strdup(strToDup);
    }
    return 0;
}

static inline uint8_t* continue_buffer_scan(
    const uint8_t* start, const uint8_t* end, MatchedPatterns* mp, DetectorHTTPPattern*)
{
    uint8_t* bp = (uint8_t*) (start) + mp->index;
    if( (bp >= end) || (*bp != ' ' && *bp != 0x09 && *bp != '/') )
        return nullptr;
    else
        return ++bp;
}

void identify_user_agent(const uint8_t* start, int size, AppId* serviceAppId, AppId* ClientAppId,
    char** version)
{
    char temp_ver[MAX_VERSION_SIZE] = { 0 };
    MatchedPatterns* mp = nullptr;
    uint8_t* buffPtr = nullptr;

    detectorHttpConfig->client_agent_matcher->find_all((const char*)start, size, &http_pattern_match, false, (void*)&mp);
    if (mp)
    {
        const uint8_t* end = start + size;
        int skypeDetect = 0;
        int mobileDetect = 0;
        int safariDetect = 0;
        int firefox_detected = 0;
        int android_browser_detected = 0;
        int dominant_pattern_detected = 0;
        bool appleEmailDetect = true;
        int longest_misc_match = 0;
        unsigned i = 0;

        *ClientAppId = APP_ID_NONE;
        *serviceAppId = APP_ID_HTTP;
        for (MatchedPatterns* tmp = mp; tmp; tmp = tmp->next)
        {
            DetectorHTTPPattern* match = (DetectorHTTPPattern*)tmp->mpattern;
            switch (match->client_app)
            {
            case APP_ID_INTERNET_EXPLORER:
            case APP_ID_FIREFOX:
                if (dominant_pattern_detected)
                    break;
                buffPtr = continue_buffer_scan(start, end, tmp, match);
                if(!buffPtr)
                    break;
                while (i < MAX_VERSION_SIZE-1 && buffPtr < end)
                {
                    if (*buffPtr != ' ' && *buffPtr != 0x09 && *buffPtr != ';' && *buffPtr != ')')
                        temp_ver[i++] = *buffPtr++;
                    else
                        break;
                }
                if (i == 0)
                    break;

                temp_ver[i] = 0;

                /*compatibility check */
                if (match->client_app == APP_ID_INTERNET_EXPLORER
                    && strstr((char*)buffPtr, "SLCC2"))
                {
                    if ((MAX_VERSION_SIZE-i) >= (sizeof(COMPATIBLE_BROWSER_STRING) - 1))
                    {
                        strcat(temp_ver, COMPATIBLE_BROWSER_STRING);
                    }
                }
                // Pick firefox over some things, but pick a misc app over Firefox.
                if (match->client_app == APP_ID_FIREFOX)
                    firefox_detected = 1;
                *serviceAppId = APP_ID_HTTP;
                *ClientAppId = match->client_app;
                break;

            case APP_ID_CHROME:
                if (dominant_pattern_detected)
                    break;
                buffPtr = continue_buffer_scan(start, end, tmp, match);
                if(!buffPtr)
                    break;
                while (i < MAX_VERSION_SIZE-1 && buffPtr < end)
                {
                    if (*buffPtr != ' ' && *buffPtr != 0x09 && *buffPtr != ';' && *buffPtr != ')')
                        temp_ver[i++] = *buffPtr++;
                    else
                        break;
                }
                if (i == 0)
                    break;

                dominant_pattern_detected = 1;
                temp_ver[i] = 0;
                *serviceAppId = APP_ID_HTTP;
                *ClientAppId = match->client_app;
                break;

            case APP_ID_ANDROID_BROWSER:
                if (dominant_pattern_detected)
                    break;
                buffPtr = continue_buffer_scan(start, end, tmp, match);
                if(!buffPtr)
                    break;
                while (i < MAX_VERSION_SIZE-1 && buffPtr < end)
                {
                    if (*buffPtr != ' ' && *buffPtr != 0x09 && *buffPtr != ';' && *buffPtr != ')')
                        temp_ver[i++] = *buffPtr++;
                    else
                        break;
                }
                if (i == 0)
                    break;

                temp_ver[i] = 0;
                android_browser_detected = 1;
                break;

            case APP_ID_KONQUEROR:
            case APP_ID_CURL:
            case APP_ID_PICASA:
                if (dominant_pattern_detected)
                    break;
            case APP_ID_WINDOWS_MEDIA_PLAYER:
            case APP_ID_BITTORRENT:
                buffPtr = continue_buffer_scan(start, end, tmp, match);
                if(!buffPtr)
                    break;
                while (i < MAX_VERSION_SIZE-1 && buffPtr < end)
                {
                    if (*buffPtr != ' ' && *buffPtr != 0x09 && *buffPtr != ';' && *buffPtr != ')')
                        temp_ver[i++] = *buffPtr++;
                    else
                        break;
                }
                if (i == 0)
                    break;

                temp_ver[i] = 0;
                *serviceAppId = APP_ID_HTTP;
                *ClientAppId = match->client_app;
                goto done;

            case APP_ID_GOOGLE_DESKTOP:
                buffPtr = (uint8_t*)start + tmp->index;

                if(buffPtr >= end)
                    break;

                if (*buffPtr != ')')
                {
                    if (*buffPtr != ' ' && *buffPtr != 0x09 && *buffPtr != '/')
                        break;
                    buffPtr++;
                    while (i < MAX_VERSION_SIZE-1 && buffPtr < end)
                    {
                        if (*buffPtr != ' ' && *buffPtr != 0x09 && *buffPtr != ';')
                            temp_ver[i++] = *buffPtr++;
                        else
                            break;
                    }
                    if (i == 0)
                        break;
                    temp_ver[i] = 0;
                }
                *serviceAppId = APP_ID_HTTP;
                *ClientAppId = match->client_app;
                goto done;

            case APP_ID_SAFARI_MOBILE_DUMMY:
                mobileDetect = 1;
                break;

            case APP_ID_SAFARI:
                if (dominant_pattern_detected)
                    break;
                safariDetect = 1;
                break;

            case APP_ID_APPLE_EMAIL:
                appleEmailDetect = true;
                for (i = 0; i < 3 && appleEmailDetect; i++)
                {
                    buffPtr = (uint8_t*)strstr((char*)start, (char*)APPLE_EMAIL_PATTERNS[i]);
                    appleEmailDetect  = ((uint8_t*)buffPtr &&
                                    (i != 0 || (i == 0 && buffPtr == ((uint8_t*)start))));
                }
                if (appleEmailDetect)
                {
                    dominant_pattern_detected = !(buffPtr && strstr((char*)buffPtr,
                        SAFARI_PATTERN) != nullptr);
                    temp_ver[0] = 0;
                    *serviceAppId = APP_ID_HTTP;
                    *ClientAppId = match->client_app;
                }
                i = 0;
                break;

            case APP_ID_WGET:
                buffPtr = (uint8_t*)start + tmp->index;
                if(buffPtr >= end)
                    break;
                while (i < MAX_VERSION_SIZE - 1 && buffPtr < end)
                {
                    temp_ver[i++] = *buffPtr++;
                }
                temp_ver[i] = 0;
                *serviceAppId = APP_ID_HTTP;
                *ClientAppId = match->client_app;
                goto done;

            case APP_ID_BLACKBERRY_BROWSER:
                while ( start < end && *start != '/' )
                    start++;
                if (start >= end)
                    break;
                start++;
                while (i < MAX_VERSION_SIZE -1 && start < end)
                {
                    if (*start != ' ' && *start != 0x09 && *start != ';')
                        temp_ver[i++] = *start++;
                    else
                        break;
                }
                if (i == 0)
                    break;
                temp_ver[i] = 0;

                *serviceAppId = APP_ID_HTTP;
                *ClientAppId = match->client_app;
                goto done;

            case APP_ID_SKYPE:
                skypeDetect  = 1;
                break;

            case APP_ID_HTTP:
                break;

            case APP_ID_OPERA:
                *serviceAppId = APP_ID_HTTP;
                *ClientAppId = match->client_app;
                break;

            case FAKE_VERSION_APP_ID:
                if (temp_ver[0])
                {
                    temp_ver[0] = 0;
                    i = 0;
                }
                buffPtr = (uint8_t*)start + tmp->index;

                if(buffPtr >= end)
                    break;

                if (*buffPtr == (uint8_t)'/')
                {
                    buffPtr++;
                    while (i < MAX_VERSION_SIZE - 1 && buffPtr < end)
                    {
                        if (*buffPtr != ' ' && *buffPtr != 0x09 && *buffPtr != ';' && *buffPtr !=
                            ')')
                            temp_ver[i++] = *buffPtr++;
                        else
                            break;
                    }
                }
                temp_ver[i] = 0;
                break;

            default:
                if (match->client_app)
                {
                    if (match->pattern_size <= longest_misc_match)
                        break;
                    longest_misc_match = match->pattern_size;
                    i =0;
                    /* if we already collected temp_ver information after seeing 'Version', let's
                       use that*/
                    buffPtr = (uint8_t*)start + tmp->index;
                    if(buffPtr >= end)
                        break;
                    /* we may have to enter the pattern with the / in it. */
                    if (*buffPtr == (uint8_t)'/' || *buffPtr == (uint8_t)' ')
                        buffPtr++;
                    if (buffPtr-1 > start && buffPtr < end && (*(buffPtr-1) == (uint8_t)'/' ||
                        *(buffPtr-1) == (uint8_t)' '))
                    {
                        while (i < MAX_VERSION_SIZE -1 && buffPtr < end)
                        {
                            if (*buffPtr != ' ' && *buffPtr != 0x09 && *buffPtr != ';' &&
                                *buffPtr != ')')
                                temp_ver[i++] = *buffPtr++;
                            else
                                break;
                        }
                        temp_ver[i] = 0;
                    }
                    dominant_pattern_detected = 1;
                    *serviceAppId = APP_ID_HTTP;
                    *ClientAppId = match->client_app;
                }
            }
        }

        if (mobileDetect && safariDetect && !dominant_pattern_detected)
        {
            *serviceAppId = APP_ID_HTTP;
            *ClientAppId = APP_ID_SAFARI_MOBILE;
        }
        else if (safariDetect && !dominant_pattern_detected)
        {
            *serviceAppId = APP_ID_HTTP;
            *ClientAppId = APP_ID_SAFARI;
        }
        else if (firefox_detected && !dominant_pattern_detected)
        {
            *serviceAppId = APP_ID_HTTP;
            *ClientAppId = APP_ID_FIREFOX;
        }
        else if (android_browser_detected && !dominant_pattern_detected)
        {
            *serviceAppId = APP_ID_HTTP;
            *ClientAppId = APP_ID_ANDROID_BROWSER;
        }
        /* Better to choose Skype over any other ID  */
        else if (skypeDetect)
        {
            *serviceAppId = APP_ID_SKYPE_AUTH;
            *ClientAppId = APP_ID_SKYPE;
        }
    }

done:
    optionallyReplaceWithStrdup(version, temp_ver);
    FreeMatchStructures(mp);
}

int get_appid_by_pattern(const uint8_t* data, unsigned size, char** version)
{
    unsigned i;
    const uint8_t* data_ptr;
    const uint8_t* end = data + size;
    MatchedPatterns* mp = nullptr;
    DetectorHTTPPattern* match = nullptr;
    char temp_ver[MAX_VERSION_SIZE];

    if (detectorHttpConfig->via_matcher)
    {
        detectorHttpConfig->via_matcher->find_all((const char*)data, size, &http_pattern_match,
            false, (void*)&mp);
    }

    if (mp)
    {
        match = (DetectorHTTPPattern*)mp->mpattern;
        switch (match->service_id)
        {
        case APP_ID_SQUID:
            data_ptr = (uint8_t*)data + mp->index;

            if (data_ptr >= end)
                break;

            if (*data_ptr == '/')
            {
                data_ptr++;
                for (i = 0;
                    data_ptr < end && i < (MAX_VERSION_SIZE-1) && *data_ptr != ')' && isprint(
                    *data_ptr);
                    data_ptr++)
                {
                    temp_ver[i++] = (char)*data_ptr;
                }
            }
            else
                i = 0;
            temp_ver[i] = 0;
            optionallyReplaceWithStrdup(version,temp_ver);
            FreeMatchStructures(mp);
            return APP_ID_SQUID;

        default:
            FreeMatchStructures(mp);
            return APP_ID_NONE;
        }
    }
    return APP_ID_NONE;
}

#define HTTP_HEADER_WORKINGWITH_ASPROXY "ASProxy/"

AppId scan_header_x_working_with(const uint8_t* data, uint32_t size, char** version)
{
    uint32_t i;
    const uint8_t* end;
    char temp_ver[MAX_VERSION_SIZE];

    temp_ver[0] = 0;

    if (size >= (sizeof(HTTP_HEADER_WORKINGWITH_ASPROXY)-1)
        && memcmp(data,HTTP_HEADER_WORKINGWITH_ASPROXY,sizeof(HTTP_HEADER_WORKINGWITH_ASPROXY)-
        1) == 0)
    {
        end = data+size;
        data += sizeof(HTTP_HEADER_WORKINGWITH_ASPROXY)-1;
        for (i = 0;
            data < end && i < (MAX_VERSION_SIZE-1) && *data != ')' && isprint(*data);
            data++)
        {
            temp_ver[i++] = (char)*data;
        }
        temp_ver[i] = 0;
        optionallyReplaceWithStrdup(version,temp_ver);
        return APP_ID_ASPROXY;
    }
    return APP_ID_NONE;
}

AppId get_appid_by_content_type(const uint8_t* data, int size)
{
    MatchedPatterns* mp = nullptr;
    DetectorHTTPPattern* match;
    AppId payloadId;

    if (detectorHttpConfig->content_type_matcher)
    {
        detectorHttpConfig->content_type_matcher->find_all((const char*)data, size,
            &content_pattern_match, false, (void*)&mp);
    }

    if (!mp)
        return APP_ID_NONE;

    match = mp->mpattern;
    payloadId = match->appId;

    FreeMatchStructures(mp);

    return payloadId;
}

static int http_header_pattern_match(void* id, void*, int index, void* data, void*)
{
    HeaderMatchedPatterns* matches = (HeaderMatchedPatterns*)data;
    HeaderPattern* target = (HeaderPattern*)id;
    HTTPHeaderIndices* headers = matches->headers;

    if (matches->last_match >= 0)
    {
        headers[matches->last_match].end = index;
        matches->last_match = -1;
    }

    if (target->id < HTTP_ID_LEN)
    {
        if (index == 0)
        {
            goto store_index;
        }
        else if (index == matches->last_index_end)
        {
            /* This checks if the last match was \r or \n
               It is still possible to have nefarious payloads
               that have HTTP Headers in "" */
            goto store_index;
        }
    }

    goto done;

store_index:
    headers[target->id].start = index + target->length;
    headers[target->id].end = 0;
    matches->last_match = target->id;
done:
    matches->last_index_end = index + target->length;
    return 0;
}

int get_http_header_location(const uint8_t* data, unsigned size, HttpId id, int* start, int* end,
        HeaderMatchedPatterns* hmp)
{
    HTTPHeaderIndices* match;

    if (hmp->headers[id].start > 0)
    {
        *start = hmp->headers[id].start;
        *end = hmp->headers[id].end;
        return 1;
    }

    if (hmp->searched)
        return 0;

    if (detectorHttpConfig->header_matcher)
    {
        detectorHttpConfig->header_matcher->find_all((const char*)data, size,
            &http_header_pattern_match, false, (void*)hmp);
    }

    hmp->searched = 1;

    /*Close out search space for last matched if needed */
    if (hmp->last_match > 0 && hmp->headers[hmp->last_match].end <= 0)
        hmp->headers[hmp->last_match].end = size;

    match = &(hmp->headers[id]);
    if (match->start > 0)
    {
        *start = match->start;
        *end = match->end;
        return 1;
    }

    return 0;
}

AppId get_appid_from_url(char* host, char* url, char** version, char* referer, AppId* ClientAppId,
        AppId* serviceAppId, AppId* payloadAppId, AppId* referredPayloadAppId, unsigned from_rtmp)
{
    char* path;
    char* referer_start;
    char* temp_host = nullptr;
    const char* referer_path = nullptr;
    int host_len;
    int referer_len = 0;
    int referer_path_len = 0;
    int path_len;
    tMlmpPattern patterns[3];
    tMlpPattern query;
    HosUrlDetectorPattern* data;
    char* q;
    int payload_found = 0;
    int url_len;
    static tMlmpTree* matcher;

#define RTMP_MEDIA_STREAM_OFFSET    50000000
#define URL_SCHEME_END_PATTERN "://"
#define URL_SCHEME_MAX_LEN     (sizeof("https://")-1)

    matcher = (from_rtmp ? detectorHttpConfig->RTMPHosUrlMatcher : detectorHttpConfig->host_url_matcher);

    if (!host && !url)
        return 0;

    if (url)
    {
        size_t scheme_len = strlen(url);
        if (scheme_len > URL_SCHEME_MAX_LEN)
            scheme_len = URL_SCHEME_MAX_LEN;    // only need to search the first few bytes for
                                                // scheme
        char* url_offset = (char*)service_strstr((uint8_t*)url, scheme_len,
            (uint8_t*)URL_SCHEME_END_PATTERN, sizeof(URL_SCHEME_END_PATTERN)-1);
        if (url_offset)
            url_offset += sizeof(URL_SCHEME_END_PATTERN)-1;
        else
            return 0;

        url = url_offset;
        url_len = strlen(url);
    }
    else
        url_len = 0;

    if (!host)
    {
        temp_host = host = snort_strdup(url);
        host  = strchr(host, '/');
        if (host != nullptr)
            *host = '\0';
        host = temp_host;
    }
    host_len = strlen(host);

    if (url_len)
    {
        if (url_len < host_len)
        {
            snort_free(temp_host);
            return 0;
        }
        path_len = url_len - host_len;
        path = url + host_len;
    }
    else
    {
        path = nullptr;
        path_len = 0;
    }

    patterns[0].pattern = (uint8_t*)host;
    patterns[0].patternSize = host_len;
    patterns[1].pattern = (uint8_t*)path;
    patterns[1].patternSize = path_len;
    patterns[2].pattern = nullptr;

    data = (HosUrlDetectorPattern*)mlmpMatchPatternUrl(matcher, patterns);

    if (data)
    {
        payload_found = 1;
        if (url)
        {
            q = strchr(url, '?');
            if (q != nullptr)
            {
                char temp_ver[MAX_VERSION_SIZE];
                temp_ver[0] = 0;
                query.pattern = (uint8_t*)++q;
                query.patternSize = strlen(q);

                matchQueryElements(&query, &data->query, temp_ver, MAX_VERSION_SIZE);

                if (temp_ver[0] != 0)
                {
                    optionallyReplaceWithStrdup(version,temp_ver);
                }
            }
        }

        *ClientAppId = data->client_id;
        *serviceAppId = data->service_id;
        *payloadAppId = data->payload_id;
    }

    snort_free(temp_host);

    /* if referred_id feature id disabled, referer will be null */
    if (referer && (!payload_found || AppInfoManager::get_instance().get_app_info_flags(data->payload_id, APPINFO_FLAG_REFERRED)))
    {
        referer_start = referer;

        char* referer_offset = (char*)service_strstr((uint8_t*)referer_start, URL_SCHEME_MAX_LEN,
            (uint8_t*)URL_SCHEME_END_PATTERN, sizeof(URL_SCHEME_END_PATTERN)-1);
        if (referer_offset)
        {
            referer_offset += sizeof(URL_SCHEME_END_PATTERN)-1;
        }
        else
            return 0;

        referer_start = referer_offset;
        referer_len = strlen(referer_start);
        referer_path = strchr(referer_start, '/');

        if (referer_path)
        {
            referer_path_len = strlen(referer_path);
            referer_len -= referer_path_len;
        }
        else
        {
            referer_path = "/";
            referer_path_len = 1;
        }

        if (referer_start && referer_len > 0)
        {
            data = nullptr;
            patterns[0].pattern = (uint8_t*)referer_start;
            patterns[0].patternSize = referer_len;
            patterns[1].pattern = (uint8_t*)referer_path;
            patterns[1].patternSize = referer_path_len;
            patterns[2].pattern = nullptr;
            data = (HosUrlDetectorPattern*)mlmpMatchPatternUrl(matcher, patterns);
            if (data != nullptr)
            {
                if (payload_found)
                    *referredPayloadAppId = *payloadAppId;
                else
                    payload_found = 1;
                *payloadAppId = data->payload_id;
            }
        }
    }
    return payload_found;
}

void get_server_vendor_version(const uint8_t* data, int len, char** version, char** vendor,
    RNAServiceSubtype** subtype)
{
    int vendor_len = len;

    const uint8_t* ver = (const uint8_t*)memchr(data, '/', len);
    if (ver)
    {
        RNAServiceSubtype* sub;
        int version_len = 0;
        int subver_len;
        const uint8_t* subname = nullptr;
        int subname_len = 0;
        const uint8_t* subver = nullptr;
        const uint8_t* paren = nullptr;
        const uint8_t* p;
        const uint8_t* end = data + len;
        vendor_len = ver - data;
        ver++;

        for (p=ver; *p && p < end; p++)
        {
            if (*p == '(')
            {
                subname = nullptr;
                paren = p;
            }
            else if (*p == ')')
            {
                subname = nullptr;
                paren = nullptr;
            }
            /* some admins put tags in their http response lines.
               the anchors will cause problems for adaptive profiles in snort,
               so let's just get rid of them */
            else if (*p == '<')
                break;
            else if (!paren)
            {
                if (*p == ' ' || *p == '\t')
                {
                    if (subname && subname_len > 0 && subver && *subname)
                    {
                        sub = (RNAServiceSubtype*)snort_calloc(sizeof(RNAServiceSubtype));
                        char* tmp = (char*)snort_calloc(subname_len + 1);
                        memcpy(tmp, subname, subname_len);
                        tmp[subname_len] = 0;
                        sub->service = tmp;
                        subver_len = p - subver;
                        if (subver_len > 0 && *subver)
                        {
                            tmp = (char*)snort_calloc(subver_len + 1);
                            memcpy(tmp, subver, subver_len);
                            tmp[subver_len] = 0;
                            sub->version = tmp;
                        }
                        sub->next = *subtype;
                        *subtype = sub;
                    }
                    subname = p + 1;
                    subname_len = 0;
                    subver = nullptr;
                }
                else if (*p == '/' && subname)
                {
                    if (version_len <= 0)
                        version_len = subname - ver - 1;
                    subname_len = p - subname;
                    subver = p + 1;
                }
            }
        }
        if (subname && subname_len > 0 && subver && *subname)
        {
            sub = (RNAServiceSubtype*)snort_calloc(sizeof(RNAServiceSubtype));
            char* tmp = (char*)snort_calloc(subname_len + 1);
            memcpy(tmp, subname, subname_len);
            tmp[subname_len] = 0;
            sub->service = tmp;

            subver_len = p - subver;
            if (subver_len > 0 && *subver)
            {
                tmp = (char*)snort_calloc(subver_len + 1);
                memcpy(tmp, subver, subver_len);
                tmp[subver_len] = 0;
                sub->version = tmp;
            }
            sub->next = *subtype;
            *subtype = sub;
        }

        if (version_len <= 0)
            version_len = p - ver;
        if (version_len >= MAX_VERSION_SIZE)
            version_len = MAX_VERSION_SIZE - 1;
        *version = (char*)snort_calloc(sizeof(char) * (version_len + 1));
        memcpy(*version, ver, version_len);
        *(*version + version_len) = '\0';
    }

    if (vendor_len >= MAX_VERSION_SIZE)
        vendor_len = MAX_VERSION_SIZE - 1;
    *vendor = (char*)snort_calloc(sizeof(char) * (vendor_len + 1));
    memcpy(*vendor, data, vendor_len);
    *(*vendor+vendor_len) = '\0';
}

bool is_webdav_found(HeaderMatchedPatterns* hmp)
{
    bool found = false;

    if (hmp->headers[HTTP_ID_COPY].start > 0)
        found = true;
    else if (hmp->headers[HTTP_ID_MOVE].start > 0)
        found = true;
    else if (hmp->headers[HTTP_ID_LOCK].start > 0)
        found = true;
    else if (hmp->headers[HTTP_ID_UNLOCK].start > 0)
        found = true;
    else if (hmp->headers[HTTP_ID_MKCOL].start > 0)
        found = true;
    else if (hmp->headers[HTTP_ID_PROPPATCH].start > 0)
        found = true;
    else if (hmp->headers[HTTP_ID_PROPFIND].start > 0)
        found = true;

    return found;
}

// Start of HTTP/2 detection logic.
//
// This is intended to simply detect the presence of HTTP version 2 as a
// service protocol if it is seen (unencrypted) on non-std ports.  That way, we
// can notify Snort for future reference.  this covers the "with prior
// knowledge" case for HTTP/2 (i.e., the client knows the server supports
// HTTP/2 and jumps right in with the preface).

static CLIENT_APP_RETCODE http_client_init(const InitClientAppAPI* const init_api, SF_LIST* config);
static CLIENT_APP_RETCODE http_client_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdSession* asd, Packet* pkt, Detector* userData);
static int http_service_init(const InitServiceAPI* const init_api);
static int http_service_validate(ServiceValidationArgs* args);

static AppRegistryEntry appIdRegistry[] =
{
    {
        APP_ID_HTTP,
        0
    }
};

static const char HTTP2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define HTTP2_PREFACE_LEN (sizeof(HTTP2_PREFACE)-1)
#define HTTP2_PREFACE_MAXPOS (sizeof(HTTP2_PREFACE)-2)

struct Client_App_Pattern
{
    const uint8_t* pattern;
    unsigned length;
    int index;
    unsigned appId;
};

static Client_App_Pattern patterns[] =
{
    {
        (const uint8_t*)HTTP2_PREFACE,
        sizeof(HTTP2_PREFACE)-1,
        0,
        APP_ID_HTTP
    },
};

SO_PUBLIC RNAClientAppModule http_client_mod =
{
    "HTTP",
    IpProtocol::TCP,
    &http_client_init,
    nullptr,
    &http_client_validate,
    1,
    nullptr,
    nullptr,
    0,
    nullptr,
    0,
    0
};

static const RNAServiceValidationPort pp[] =
{
    {
        nullptr,
        0,
        IpProtocol::PROTO_NOT_SET,
        0
    }
};

static const RNAServiceElement http_service_element =
{
    nullptr,
    &http_service_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "http"
};

RNAServiceValidationModule http_service_mod =
{
    "HTTP",
    &http_service_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static CLIENT_APP_RETCODE http_client_init(const InitClientAppAPI* const init_api, SF_LIST*)
{
    if (AppIdConfig::get_appid_config()->mod_config->http2_detection_enabled)
    {
        for (unsigned i = 0; i < sizeof(patterns)/sizeof(*patterns); i++)
        {
            DebugFormat(DEBUG_LOG, "registering patterns: %s: %d",
                (const char*)patterns[i].pattern, patterns[i].index);
            init_api->RegisterPattern(&http_client_validate, IpProtocol::TCP, patterns[i].pattern,
                patterns[i].length, patterns[i].index);
        }
    }

    for (unsigned j = 0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_LOG, "registering appId: %d\n", appIdRegistry[j].appId);
        init_api->RegisterAppId(&http_client_validate, appIdRegistry[j].appId,
            appIdRegistry[j].additionalInfo);
    }

    return CLIENT_APP_SUCCESS;
}

static CLIENT_APP_RETCODE http_client_validate(const uint8_t*, uint16_t, const int dir,
    AppIdSession* asd, Packet* pkt, Detector*)
{
    http_client_mod.api->add_app(asd, APP_ID_HTTP, APP_ID_HTTP + GENERIC_APP_OFFSET, nullptr);
    asd->rna_client_state = RNA_STATE_FINISHED;
    http_service_mod.api->add_service(asd, pkt, dir, &http_service_element,
        APP_ID_HTTP, nullptr, nullptr, nullptr);
    asd->rnaServiceState = RNA_STATE_FINISHED;
    asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED | APPID_SESSION_SERVICE_DETECTED);
    asd->clear_session_flags(APPID_SESSION_CONTINUE);
    asd->is_http2 = true;

    return CLIENT_APP_SUCCESS;
}

static int http_service_init(const InitServiceAPI* const init_api)
{
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_LOG, "registering appId: %d\n", appIdRegistry[i].appId);
        init_api->RegisterAppId(&http_service_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo);
    }

    return 0;
}

static int http_service_validate(ServiceValidationArgs*)
{
    return SERVICE_INPROCESS;
}

// End of HTTP/2 detection logic.

