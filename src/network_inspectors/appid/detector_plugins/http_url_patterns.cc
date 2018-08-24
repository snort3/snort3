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

// http_url_patterns.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <utility>

#include "http_url_patterns.h"

#include "app_info_table.h"
#include "appid_module.h"
#include "appid_http_session.h"
#include "appid_session.h"
#include "appid_utils/sf_mlmp.h"
#include "log/messages.h"
#include "protocols/packet.h"

using namespace snort;

typedef AppIdHttpSession::pair_t pair_t;

static const char* const FP_OPERATION_AND = "%&%";
static const unsigned PATTERN_PART_MAX = 10;

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
#define MAX_VERSION_SIZE    64

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
    int after_match_pos;  // Warning: may point past end of buffer.
                          // Position of character in buffer after last
                          // matching character.
    MatchedPatterns* next;
};

static DetectorHTTPPatterns static_content_type_patterns =
{
    { SINGLE, 0, APP_ID_QUICKTIME, 0,
      APP_ID_QUICKTIME, sizeof(QUICKTIME_BANNER)-1, (const uint8_t*)QUICKTIME_BANNER },
    { SINGLE, 0, APP_ID_MPEG, 0,
      APP_ID_MPEG, sizeof(MPEG_BANNER)-1, (const uint8_t*)MPEG_BANNER },
    { SINGLE, 0, APP_ID_MPEG, 0,
      APP_ID_MPEG, sizeof(MPA_BANNER)-1, (const uint8_t*)MPA_BANNER },
    { SINGLE, 0, APP_ID_MPEG, 0,
      APP_ID_MPEG, sizeof(MP4A_BANNER)-1, (const uint8_t*)MP4A_BANNER },
    { SINGLE, 0, APP_ID_MPEG, 0,
      APP_ID_MPEG, sizeof(ROBUST_MPA_BANNER)-1, (const uint8_t*)ROBUST_MPA_BANNER },
    { SINGLE, 0, APP_ID_MPEG, 0,
      APP_ID_MPEG, sizeof(XSCPLS_BANNER)-1, (const uint8_t*)XSCPLS_BANNER },
    { SINGLE, 0, APP_ID_SHOCKWAVE, 0,
      APP_ID_SHOCKWAVE, sizeof(SHOCKWAVE_BANNER)-1, (const uint8_t*)SHOCKWAVE_BANNER },
    { SINGLE, 0, APP_ID_RSS, 0,
      APP_ID_RSS, sizeof(RSS_BANNER)-1, (const uint8_t*)RSS_BANNER },
    { SINGLE, 0, APP_ID_ATOM, 0,
      APP_ID_ATOM, sizeof(ATOM_BANNER)-1, (const uint8_t*)ATOM_BANNER },
    { SINGLE, 0, APP_ID_MP4, 0,
      APP_ID_MP4, sizeof(MP4_BANNER)-1, (const uint8_t*)MP4_BANNER },
    { SINGLE, 0, APP_ID_WMV, 0,
      APP_ID_WMV, sizeof(WMV_BANNER)-1, (const uint8_t*)WMV_BANNER },
    { SINGLE, 0, APP_ID_WMA, 0,
      APP_ID_WMA, sizeof(WMA_BANNER)-1, (const uint8_t*)WMA_BANNER },
    { SINGLE, 0, APP_ID_WAV, 0,
      APP_ID_WAV, sizeof(WAV_BANNER)-1, (const uint8_t*)WAV_BANNER },
    { SINGLE, 0, APP_ID_WAV, 0,
      APP_ID_WAV, sizeof(X_WAV_BANNER)-1, (const uint8_t*)X_WAV_BANNER },
    { SINGLE, 0, APP_ID_WAV, 0,
      APP_ID_WAV, sizeof(VND_WAV_BANNER)-1, (const uint8_t*)VND_WAV_BANNER },
    { SINGLE, 0, APP_ID_FLASH_VIDEO, 0,
      APP_ID_FLASH_VIDEO, sizeof(FLV_BANNER)-1, (const uint8_t*)FLV_BANNER },
    { SINGLE, 0, APP_ID_FLASH_VIDEO, 0,
      APP_ID_FLASH_VIDEO, sizeof(M4V_BANNER)-1, (const uint8_t*)M4V_BANNER },
    { SINGLE, 0, APP_ID_FLASH_VIDEO, 0,
      APP_ID_FLASH_VIDEO, sizeof(GPP_BANNER)-1, (const uint8_t*)GPP_BANNER },
    { SINGLE, 0, APP_ID_GENERIC, 0,
      APP_ID_GENERIC, sizeof(VIDEO_BANNER)-1, (const uint8_t*)VIDEO_BANNER },
    { SINGLE, 0, APP_ID_GENERIC, 0,
      APP_ID_GENERIC, sizeof(AUDIO_BANNER)-1, (const uint8_t*)AUDIO_BANNER },
};

static DetectorHTTPPatterns static_via_http_detector_patterns =
{
    { SINGLE, APP_ID_SQUID, 0, 0, APP_ID_SQUID, SQUID_PATTERN_SIZE,
      (const uint8_t*)SQUID_PATTERN },
};

static DetectorHTTPPatterns static_http_host_payload_patterns =
{
    { SINGLE, 0, 0, APP_ID_MYSPACE,
      APP_ID_MYSPACE, MYSPACE_PATTERN_SIZE, (const uint8_t*)MYSPACE_PATTERN },
    { SINGLE, 0, 0, APP_ID_GMAIL,
      APP_ID_GMAIL, GMAIL_PATTERN_SIZE, (const uint8_t*)GMAIL_PATTERN },
    { SINGLE, 0, 0, APP_ID_GMAIL,
      APP_ID_GMAIL, GMAIL_PATTERN2_SIZE, (const uint8_t*)GMAIL_PATTERN2 },
    { SINGLE, 0, 0, APP_ID_AOL_EMAIL,
      APP_ID_AOL_EMAIL, AOL_PATTERN_SIZE, (const uint8_t*)AOL_PATTERN },
    { SINGLE, 0, 0, APP_ID_MICROSOFT_UPDATE,
      APP_ID_MICROSOFT_UPDATE, MSUP_PATTERN_SIZE, (const uint8_t*)MSUP_PATTERN },
    { SINGLE, 0, 0, APP_ID_MICROSOFT_UPDATE,
      APP_ID_MICROSOFT_UPDATE,MSUP_PATTERN2_SIZE, (const uint8_t*)MSUP_PATTERN2 },
    { SINGLE, 0, 0, APP_ID_YAHOOMAIL,
      APP_ID_YAHOOMAIL, YAHOO_MAIL_PATTERN_SIZE, (const uint8_t*)YAHOO_MAIL_PATTERN },
    { SINGLE, 0, 0, APP_ID_YAHOO_TOOLBAR,
      APP_ID_YAHOO_TOOLBAR, YAHOO_TB_PATTERN_SIZE, (const uint8_t*)YAHOO_TB_PATTERN },
    { SINGLE, 0, 0, APP_ID_ADOBE_UPDATE,
      APP_ID_ADOBE_UPDATE, ADOBE_UP_PATTERN_SIZE, (const uint8_t*)ADOBE_UP_PATTERN },
    { SINGLE, 0, 0, APP_ID_HOTMAIL,
      APP_ID_HOTMAIL, HOTMAIL_PATTERN1_SIZE, (const uint8_t*)HOTMAIL_PATTERN1 },
    { SINGLE, 0, 0, APP_ID_HOTMAIL,
      APP_ID_HOTMAIL, HOTMAIL_PATTERN2_SIZE, (const uint8_t*)HOTMAIL_PATTERN2 },
    { SINGLE, 0, 0, APP_ID_GOOGLE_TOOLBAR,
      APP_ID_GOOGLE_TOOLBAR, GOOGLE_TB_PATTERN_SIZE, (const uint8_t*)GOOGLE_TB_PATTERN },
};

static DetectorHTTPPatterns static_client_agent_patterns =
{
    { USER_AGENT_HEADER, 0, FAKE_VERSION_APP_ID, 0,
      FAKE_VERSION_APP_ID, VERSION_PATTERN_SIZE, (const uint8_t*)VERSION_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_INTERNET_EXPLORER, 0,
      APP_ID_INTERNET_EXPLORER, sizeof(MSIE_PATTERN)-1, (const uint8_t*)MSIE_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_KONQUEROR, 0,
      APP_ID_KONQUEROR, sizeof(KONQUEROR_PATTERN)-1, (const uint8_t*)KONQUEROR_PATTERN },
    { USER_AGENT_HEADER, APP_ID_SKYPE_AUTH, APP_ID_SKYPE, 0,
      APP_ID_SKYPE, sizeof(SKYPE_PATTERN)-1, (const uint8_t*)SKYPE_PATTERN },
    { USER_AGENT_HEADER, APP_ID_BITTORRENT, APP_ID_BITTORRENT, 0,
      APP_ID_BITTORRENT, sizeof(BITTORRENT_PATTERN)-1, (const uint8_t*)BITTORRENT_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_FIREFOX, 0,
      APP_ID_FIREFOX, sizeof(FIREFOX_PATTERN)-1, (const uint8_t*)FIREFOX_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_WGET, 0,
      APP_ID_WGET, sizeof(WGET_PATTERN)-1, (const uint8_t*)WGET_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_CURL, 0,
      APP_ID_CURL, sizeof(CURL_PATTERN)-1, (const uint8_t*)CURL_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_GOOGLE_DESKTOP, 0,
      APP_ID_GOOGLE_DESKTOP, sizeof(GOOGLE_DESKTOP_PATTERN)-1,
      (const uint8_t*)GOOGLE_DESKTOP_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_PICASA, 0,
      APP_ID_PICASA, sizeof(PICASA_PATTERN)-1, (const uint8_t*)PICASA_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_SAFARI, 0,
      APP_ID_SAFARI, sizeof(SAFARI_PATTERN)-1, (const uint8_t*)SAFARI_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_OPERA, 0,
      APP_ID_OPERA, sizeof(OPERA_PATTERN)-1, (const uint8_t*)OPERA_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_CHROME, 0,
      APP_ID_CHROME, sizeof(CHROME_PATTERN)-1, (const uint8_t*)CHROME_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_SAFARI_MOBILE_DUMMY, 0,
      APP_ID_SAFARI_MOBILE_DUMMY, sizeof(MOBILE_PATTERN)-1, (const uint8_t*)MOBILE_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_BLACKBERRY_BROWSER, 0,
      APP_ID_BLACKBERRY_BROWSER, sizeof(BLACKBERRY_PATTERN)-1,
      (const uint8_t*)BLACKBERRY_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_ANDROID_BROWSER, 0,
      APP_ID_ANDROID_BROWSER, sizeof(ANDROID_PATTERN)-1, (const uint8_t*)ANDROID_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_WINDOWS_MEDIA_PLAYER, 0,
      APP_ID_WINDOWS_MEDIA_PLAYER, sizeof(MEDIAPLAYER_PATTERN)-1,
      (const uint8_t*)MEDIAPLAYER_PATTERN },
    { USER_AGENT_HEADER, APP_ID_HTTP, APP_ID_APPLE_EMAIL, 0,
      APP_ID_APPLE_EMAIL, sizeof(APPLE_EMAIL_PATTERN)-1, (const uint8_t*)APPLE_EMAIL_PATTERN },
};

static int match_query_elements(tMlpPattern* packetData, tMlpPattern* userPattern,
    char* appVersion, size_t appVersionSize)
{
    if (appVersion == nullptr)
        return 0;

    appVersion[0] = '\0';

    if (!userPattern || !userPattern->pattern || !packetData || !packetData->pattern)
        return 0;

    // queryEnd is 1 past the end.  key1=value1&key2=value2
    const uint8_t* endKey;
    uint32_t copySize = 0;
    const uint8_t* queryEnd = packetData->pattern + packetData->patternSize;
    for (const uint8_t* index = packetData->pattern; index < queryEnd; index = endKey + 1)
    {
        /*find end of query tuple */
        endKey = (const uint8_t*)memchr (index, '&',  queryEnd - index);
        if (!endKey)
            endKey = queryEnd;

        if (userPattern->patternSize < (uint32_t)(endKey - index))
        {
            if (memcmp(index, userPattern->pattern, userPattern->patternSize) == 0)
            {
                index += userPattern->patternSize;
                uint32_t extractedSize = (endKey - index);
                appVersionSize--;
                copySize = (extractedSize < appVersionSize) ? extractedSize : appVersionSize;
                memcpy(appVersion, index, copySize);
                appVersion[copySize] = '\0';
                break;
            }
        }
    }
    return copySize;
}

HttpPatternMatchers* HttpPatternMatchers::get_instance()
{
    static HttpPatternMatchers* http_matchers;
    if (!http_matchers)
        http_matchers = new HttpPatternMatchers;
    return http_matchers;
}

static void free_app_url_patterns(std::vector<DetectorAppUrlPattern*>& url_patterns)
{
    for (auto* pattern: url_patterns)
    {
        if (pattern->userData.query.pattern)
            snort_free(const_cast<uint8_t*>(pattern->userData.query.pattern));
        if (pattern->patterns.host.pattern)
            snort_free(const_cast<uint8_t*>(pattern->patterns.host.pattern));
        if (pattern->patterns.path.pattern)
            snort_free(const_cast<uint8_t*>(pattern->patterns.path.pattern));
        if (pattern->patterns.scheme.pattern)
            snort_free(const_cast<uint8_t*>(pattern->patterns.scheme.pattern));
        snort_free(pattern);
    }
    url_patterns.clear();
}

static void free_http_patterns(DetectorHTTPPatterns& patterns)
{
    for (auto& pat: patterns)
        if (pat.pattern)
            snort_free(const_cast<uint8_t*>(pat.pattern));
}

void HttpPatternMatchers::free_chp_app_elements()
{
    CHPListElement* chpe;

    while ( (chpe = chpList) )
    {
        chpList = chpe->next;

        if (chpe->chp_action.pattern)
            snort_free(chpe->chp_action.pattern);
        if (chpe->chp_action.action_data)
            snort_free(chpe->chp_action.action_data);
        snort_free (chpe);
    }
}

HttpPatternMatchers::~HttpPatternMatchers()
{
    free_app_url_patterns(app_url_patterns);
    free_app_url_patterns(rtmp_url_patterns);
    free_http_patterns(url_patterns);
    free_http_patterns(host_payload_patterns);
    free_http_patterns(client_agent_patterns);
    free_http_patterns(content_type_patterns);
    free_chp_app_elements();

    delete field_matcher;

    for (size_t i = 0; i < NUM_HTTP_FIELDS; i++)
        delete chp_matchers[i];

    for (auto* pattern : host_url_patterns)
        delete pattern;
    host_url_patterns.clear();
    if ( host_url_matcher )
        mlmpDestroy(host_url_matcher);
    if ( rtmp_host_url_matcher )
        mlmpDestroy(rtmp_host_url_matcher);
}

void HttpPatternMatchers::insert_chp_pattern(CHPListElement* chpa)
{
    CHPListElement* tmp_chpa = chpList;
    if (!tmp_chpa)
        chpList = chpa;
    else
    {
        while (tmp_chpa->next)
            tmp_chpa = tmp_chpa->next;
        tmp_chpa->next = chpa;
    }
}

void HttpPatternMatchers::insert_http_pattern(enum httpPatternType pType,
    DetectorHTTPPattern& pattern)
{
    switch (pType)
    {
    case HTTP_PAYLOAD:
        host_payload_patterns.push_back(pattern);
        break;

    case HTTP_URL:
        url_patterns.push_back(pattern);
        break;

    case HTTP_USER_AGENT:
        client_agent_patterns.push_back(pattern);
        break;
    }
}

void HttpPatternMatchers::remove_http_patterns_for_id(AppId id)
{
    // Walk the list of all the patterns we have inserted, searching for this appIdInstance and
    // free them.
    // The purpose is for the 14 and 15 to be used together to only set the
    // APPINFO_FLAG_SEARCH_ENGINE flag
    // If the reserved pattern is not used, it is a mixed use case and should just behave normally.
    CHPListElement* chpa = nullptr;
    CHPListElement* prev_chpa = nullptr;
    CHPListElement* tmp_chpa = chpList;
    while (tmp_chpa)
    {
        if (tmp_chpa->chp_action.appIdInstance == id)
        {
            // advance the tmp_chpa pointer by removing the item pointed to. Keep prev_chpa
            // unchanged.

            // 1) unlink the struct, 2) free strings and then 3) free the struct.
            chpa = tmp_chpa; // preserve this pointer to be freed at the end.
            if (prev_chpa == nullptr)
            {
                // Remove from head
                chpList = tmp_chpa->next;
                tmp_chpa = chpList;
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

void HttpPatternMatchers::insert_content_type_pattern(DetectorHTTPPattern& pattern)
{
    content_type_patterns.push_back(pattern);
}

void HttpPatternMatchers::insert_url_pattern(DetectorAppUrlPattern* pattern)
{
    app_url_patterns.push_back(pattern);
}

void HttpPatternMatchers::insert_rtmp_url_pattern(DetectorAppUrlPattern* pattern)
{
    rtmp_url_patterns.push_back(pattern);
}

void HttpPatternMatchers::insert_app_url_pattern(DetectorAppUrlPattern* pattern)
{
    HttpPatternMatchers::insert_url_pattern(pattern);
}

int HttpPatternMatchers::add_mlmp_pattern(tMlmpTree* matcher, DetectorHTTPPattern& pattern)
{
    assert(pattern.pattern);

    HostUrlDetectorPattern* detector = new HostUrlDetectorPattern(pattern.pattern,
        pattern.pattern_size);
    host_url_patterns.push_back(detector);

    detector->payload_id = pattern.payload_id;
    detector->service_id = pattern.service_id;
    detector->client_id = pattern.client_id;
    detector->seq = pattern.sequence;
    if (pattern.app_id > APP_ID_NONE)
        detector->appId = pattern.app_id;
    else if (pattern.payload_id > APP_ID_NONE)
        detector->appId = pattern.payload_id;
    else if (pattern.client_id > APP_ID_NONE)
        detector->appId = pattern.client_id;
    else
        detector->appId = pattern.service_id;

    tMlmpPattern patterns[PATTERN_PART_MAX];
    int num_patterns = parse_multiple_http_patterns((const char*)pattern.pattern, patterns,
        PATTERN_PART_MAX, 0);
    patterns[num_patterns].pattern = nullptr;
    return mlmpAddPattern(matcher, patterns, detector);
}

int HttpPatternMatchers::add_mlmp_pattern(tMlmpTree* matcher, DetectorAppUrlPattern& pattern)
{
    assert(pattern.patterns.host.pattern);

    HostUrlDetectorPattern* detector = new HostUrlDetectorPattern(pattern.patterns.host.pattern,
        pattern.patterns.host.patternSize);
    host_url_patterns.push_back(detector);

    if (pattern.patterns.path.pattern)
    {
        detector->path.pattern = (uint8_t*)snort_strdup((const char*)pattern.patterns.path.pattern);
        detector->path.patternSize = pattern.patterns.path.patternSize;
    }

    if (pattern.userData.query.pattern)
    {
        detector->query.pattern = (uint8_t*)snort_strdup((const char*)pattern.userData.query.pattern);
        detector->query.patternSize = pattern.userData.query.patternSize;
    }

    detector->payload_id = pattern.userData.payload_id;
    detector->service_id = pattern.userData.service_id;
    detector->client_id = pattern.userData.client_id;
    detector->seq = SINGLE;
    if (pattern.userData.appId > APP_ID_NONE)
        detector->appId = pattern.userData.appId;
    else if (pattern.userData.payload_id > APP_ID_NONE)
        detector->appId = pattern.userData.payload_id;
    else if (pattern.userData.client_id > APP_ID_NONE)
        detector->appId = pattern.userData.client_id;
    else
        detector->appId = pattern.userData.service_id;

    tMlmpPattern patterns[PATTERN_PART_MAX];
    int num_patterns = parse_multiple_http_patterns((const char*)pattern.patterns.host.pattern,
        patterns, PATTERN_PART_MAX, 0);
    if (pattern.patterns.path.pattern)
        num_patterns += parse_multiple_http_patterns((const char*)pattern.patterns.path.pattern,
            patterns + num_patterns, PATTERN_PART_MAX - num_patterns, 1);

    patterns[num_patterns].pattern = nullptr;
    return mlmpAddPattern(matcher, patterns, detector);
}

int HttpPatternMatchers::process_mlmp_patterns()
{
    for (auto& pattern: host_payload_patterns)
        if ( add_mlmp_pattern(host_url_matcher, pattern) < 0 )
            return -1;

    for (auto* pattern: rtmp_url_patterns)
        if ( add_mlmp_pattern(rtmp_host_url_matcher, *pattern) < 0 )
            return -1;

    for (auto* pattern: app_url_patterns)
        if ( add_mlmp_pattern(host_url_matcher, *pattern) < 0 )
            return -1;

    return 0;
}

static int content_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    MatchedPatterns** matches = (MatchedPatterns**)data;

    MatchedPatterns* cm = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
    cm->mpattern = (DetectorHTTPPattern*)id;
    cm->after_match_pos = match_end_pos;
    cm->next = *matches;
    *matches = cm;

    return 0;
}

static int chp_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    ChpMatchDescriptor* cmd = (ChpMatchDescriptor*)data;
    CHPAction* target = (CHPAction*)id;

    cmd->chp_matches[cmd->cur_ptype].push_back({ target, match_end_pos - target->psize });
    return 0;
}

static inline void chp_add_candidate_to_tally(CHPMatchTally& match_tally, CHPApp* chpapp)
{
    for (auto& item: match_tally)
        if (chpapp == item.chpapp)
        {
            item.key_pattern_countdown--;
            return;
        }

    match_tally.push_back({ chpapp, chpapp->key_pattern_length_sum,
                            chpapp->key_pattern_count - 1 });
}

// In addition to creating the linked list of matching actions this function will
// create the CHPMatchTally needed to find the longest matching pattern.
static int chp_key_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    ChpMatchDescriptor* cmd = (ChpMatchDescriptor*)data;
    CHPAction* target = (CHPAction*)id;

    if (target->key_pattern)
    {
        // We have a match from a key pattern. We need to have it's parent chpapp represented in
        // the tally. If the chpapp has never been seen then add an item to the tally's array
        // else decrement the count of expected key_patterns until zero so that we know when we
        // have them all.
        chp_add_candidate_to_tally(cmd->match_tally, target->chpapp);
    }

    return chp_pattern_match(id, nullptr, match_end_pos, cmd, nullptr);
}

static int http_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    MatchedPatterns* cm = nullptr;
    MatchedPatterns** tmp;
    MatchedPatterns** matches = (MatchedPatterns**)data;

    // make sure we haven't already seen this pattern
    for (tmp = matches; *tmp; tmp = &(*tmp)->next)
        cm = *tmp;

    if (!*tmp)
    {
        cm = (MatchedPatterns*)snort_calloc(sizeof(MatchedPatterns));
        cm->mpattern = (DetectorHTTPPattern*)id;
        cm->after_match_pos = match_end_pos;
        cm->next = nullptr;
        *tmp = cm;
    }

    /* if its one of the host patterns, return after first match*/
    if (cm->mpattern->sequence == SINGLE)
        return 1;
    else
        return 0;
}

int HttpPatternMatchers::process_host_patterns(DetectorHTTPPatterns patterns)
{
    if (!host_url_matcher)
        host_url_matcher = mlmpCreate();

    if (!rtmp_host_url_matcher)
        rtmp_host_url_matcher = mlmpCreate();

    for (auto& pat : patterns)
    {
        if ( add_mlmp_pattern(host_url_matcher, pat) < 0 )
            return -1;
    }

    if ( HttpPatternMatchers::process_mlmp_patterns() < 0 )
        return -1;

    mlmpProcessPatterns(host_url_matcher);
    mlmpProcessPatterns(rtmp_host_url_matcher);
    return 0;
}

int HttpPatternMatchers::process_chp_list(CHPListElement* chplist)
{
    for (size_t i = 0; i < NUM_HTTP_FIELDS; i++)
        chp_matchers[i] = new snort::SearchTool("ac_full", true);

    for (CHPListElement* chpe = chplist; chpe; chpe = chpe->next)
        chp_matchers[chpe->chp_action.ptype]->add(chpe->chp_action.pattern,
            chpe->chp_action.psize, &chpe->chp_action, true);

    for (size_t i = 0; i < NUM_HTTP_FIELDS; i++)
        chp_matchers[i]->prep();

    return 1;
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
    const uint8_t* data;
    HttpFieldIds patternType;
    unsigned length;
} FieldPattern;

static FieldPattern http_field_patterns[] =
{
    { (const uint8_t*)HTTP_FIELD_PREFIX_URI, REQ_URI_FID, HTTP_FIELD_PREFIX_URI_SIZE },
    { (const uint8_t*)HTTP_FIELD_PREFIX_HOST, REQ_HOST_FID, HTTP_FIELD_PREFIX_HOST_SIZE },
    { (const uint8_t*)HTTP_FIELD_PREFIX_REFERER, REQ_REFERER_FID, HTTP_FIELD_PREFIX_REFERER_SIZE },
    { (const uint8_t*)HTTP_FIELD_PREFIX_COOKIE, REQ_COOKIE_FID, HTTP_FIELD_PREFIX_COOKIE_SIZE },
    { (const uint8_t*)HTTP_FIELD_PREFIX_USER_AGENT, REQ_AGENT_FID,
      HTTP_FIELD_PREFIX_USER_AGENT_SIZE },
};

static snort::SearchTool* process_http_field_patterns(FieldPattern* patternList,
    size_t patternListCount)
{
    snort::SearchTool* patternMatcher = new snort::SearchTool("ac_full", true);

    for (size_t i=0; i < patternListCount; i++)
        patternMatcher->add( (const char*)patternList[i].data, patternList[i].length,
            &patternList[i], false);

    patternMatcher->prep();
    return patternMatcher;
}

static void process_patterns(snort::SearchTool& matcher, DetectorHTTPPatterns& patterns, bool
    last = true)
{
    for (auto& pat: patterns)
        matcher.add(pat.pattern, pat.pattern_size, &pat, false);

    if (last)
        matcher.prep();
}

int HttpPatternMatchers::finalize_patterns()
{
    process_patterns(via_matcher, static_via_http_detector_patterns);
    process_patterns(url_matcher, url_patterns);
    process_patterns(client_agent_matcher, static_client_agent_patterns, false);
    process_patterns(client_agent_matcher, client_agent_patterns);

    if (process_host_patterns(static_http_host_payload_patterns) < 0)
        return -1;

    process_patterns(content_type_matcher, static_content_type_patterns, false);
    process_patterns(content_type_matcher, content_type_patterns);

    uint32_t numPatterns = sizeof(http_field_patterns) / sizeof(*http_field_patterns);
    field_matcher = process_http_field_patterns(http_field_patterns, numPatterns);

    process_chp_list(chpList);

    return 0;
}

typedef struct fieldPatternData_t
{
    const uint8_t* payload;
    unsigned length;
    AppIdHttpSession* hsession;
} FieldPatternData;

static int http_field_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    static const uint8_t crlf[] = "\r\n";
    static unsigned crlfLen = sizeof(crlf)-1;
    FieldPatternData* pFieldData = (FieldPatternData*)data;
    FieldPattern* target = (FieldPattern*)id;
    const uint8_t* p;
    unsigned fieldOffset = match_end_pos;
    unsigned remainingLength = pFieldData->length - fieldOffset;

    if (!(p = (const uint8_t*)service_strstr(&pFieldData->payload[fieldOffset], remainingLength,
            crlf, crlfLen)))
    {
        return 1;
    }

    pFieldData->hsession->set_offset(target->patternType, fieldOffset, p-pFieldData->payload);

    return 1;
}

//  FIXIT-M: Is this still necessary now that we use inspection events?
void HttpPatternMatchers::get_http_offsets(snort::Packet* pkt, AppIdHttpSession* hsession)
{
    constexpr auto MIN_HTTP_REQ_HEADER_SIZE = (sizeof("GET /\r\n\r\n") - 1);
    static const uint8_t crlfcrlf[] = "\r\n\r\n";
    static unsigned crlfcrlfLen = sizeof(crlfcrlf) - 1;
    const uint8_t* headerEnd;
    FieldPatternData patternMatchData;

    for (int fieldId = REQ_AGENT_FID; fieldId <= REQ_COOKIE_FID; fieldId++)
    {
	pair_t off;
	if ( hsession->get_offset(fieldId, off.first, off.second) )
	    hsession->set_offset(fieldId, 0, off.second);
    }

    if (!pkt->data || pkt->dsize < MIN_HTTP_REQ_HEADER_SIZE)
        return;

    patternMatchData.hsession = hsession;
    patternMatchData.payload = pkt->data;

    if (!(headerEnd = (const uint8_t*)service_strstr(pkt->data, pkt->dsize, crlfcrlf,
            crlfcrlfLen)))
        return;

    headerEnd += crlfcrlfLen;
    patternMatchData.length = (unsigned)(headerEnd - pkt->data);
    field_matcher->find_all((const char*)pkt->data, patternMatchData.length,
        &http_field_pattern_match, false, (void*)(&patternMatchData));
}

static inline void free_matched_patterns(MatchedPatterns* mp)
{
    while (mp)
    {
        MatchedPatterns* tmp = mp;
        mp = mp->next;
        snort_free(tmp);
    }
}

static void rewrite_chp(const char* buf, int bs, int start, int psize, char* adata,
    const char** outbuf, int insert)
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
    int percent_count = 0;
    unsigned old_size = strlen(user);

    // find number of '%'
    for (unsigned i = 0; i < old_size; i++)
    {
        if (*(user + i) == '%')
            percent_count++;
    }
    if (0 == percent_count)
        return user;        // no change allows an early out

    /* Shrink user string in place */
    char* tmp_ret = user;
    char* tmp_user = user;
    while (*tmp_user)
    {
        char a, b;

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

static void extract_chp(const char* buf, int bs, int start, int psize, char* adata,  char** outbuf)
{
    const char* begin = buf + start + psize;
    const char* end = nullptr;
    unsigned as = 0;

    if (adata)
        as = strlen(adata);

    // find where the pattern ends so we can allocate a buffer
    for ( unsigned i = 0; i < as; i++)
    {
        const char* tmp = strchr(begin, *(adata + i));
        if (tmp)
        {
            if (!end || tmp < end)
                end = tmp;
        }
    }

    if (!end)
    {
        const char* tmp;

        if ((tmp = strchr(begin, 0x0d)))
        {
            end = tmp;
        }
        if ((tmp = strchr(begin, 0x0a)))
        {
            if (!end || tmp < end)
                end = tmp;
        }
    }

    if (!end)
        end = begin + bs;

    *outbuf = snort_strndup(begin, end - begin);
}

void HttpPatternMatchers::scan_key_chp(ChpMatchDescriptor& cmd)
{
    unsigned i = cmd.cur_ptype;
    chp_matchers[i]->find_all(cmd.buffer[i], cmd.length[i], &chp_key_pattern_match,
        false, (void*)&cmd);
    cmd.sort_chp_matches();
}

AppId HttpPatternMatchers::scan_chp(ChpMatchDescriptor& cmd, char** version, char** user,
    int* total_found, AppIdHttpSession* hsession, const AppIdModuleConfig* mod_config)
{
    MatchedCHPAction* insert_sweep2 = nullptr;
    bool inhibit_modify = false;
    AppId ret = APP_ID_NONE;
    unsigned pt = cmd.cur_ptype;

    if ( pt > MAX_KEY_PATTERN )
    {
        // There is no previous attempt to match generated by scan_key_chp()
        chp_matchers[pt]->find_all(cmd.buffer[pt], cmd.length[pt], &chp_pattern_match, false,
            (void*)&cmd);
    }

    if ( cmd.chp_matches[pt].empty() )
        return APP_ID_NONE;
    else
        cmd.sort_chp_matches();

    if (!mod_config->safe_search_enabled)
        cmd.chp_rewritten[pt] = nullptr;

    for ( auto& tmp: cmd.chp_matches[pt] )
    {
        CHPAction* match = (CHPAction*)tmp.mpattern;
        if ( match->appIdInstance > hsession->get_chp_candidate() )
            break; // because the list is sorted we know there are no more
        else if ( match->appIdInstance == hsession->get_chp_candidate() )
        {
            switch (match->action)
            {
            case DEFER_TO_SIMPLE_DETECT:
                // Ignore all other patterns; we are done.
                cmd.chp_matches[pt].clear();
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
            if ( !ret )
                ret = hsession->get_chp_candidate();
        }
        else
            continue; // keep looking

        switch ( match->action )
        {
        case COLLECT_VERSION:
            if ( !*version )
                extract_chp(cmd.buffer[pt], cmd.length[pt], tmp.start_match_pos, match->psize,
                    match->action_data, version);
            hsession->set_skip_simple_detect(true);
            break;
        case EXTRACT_USER:
            if ( !*user && !mod_config->chp_userid_disabled )
            {
                extract_chp(cmd.buffer[pt], cmd.length[pt], tmp.start_match_pos, match->psize,
                    match->action_data, user);
                if ( *user )
                    *user = normalize_userid(*user);
            }
            break;
        case REWRITE_FIELD:
            if ( !inhibit_modify && !cmd.chp_rewritten[pt] )
            {
                // The field supports rewrites, and a rewrite hasn't happened.
                rewrite_chp(cmd.buffer[pt], cmd.length[pt], tmp.start_match_pos, match->psize,
                    match->action_data, &cmd.chp_rewritten[pt], 0);
                (*total_found)++;
                inhibit_modify = true;
            }
            break;
        case INSERT_FIELD:
            if ( !inhibit_modify && !insert_sweep2 )
            {
                if (match->action_data)
                {
                    // because this insert is the first one we have come across
                    // we only need to remember this ONE for later.
                    insert_sweep2 = &tmp;
                }
                else
                {
                    // This is an attempt to "insert nothing"; call it a match
                    // The side effect is to set the inhibit_modify true

                    // Note that an attempt to "rewrite with identical string"
                    // is NOT equivalent to an "insert nothing" because of case-
                    //  insensitive pattern matching

                    inhibit_modify = true;
                    (*total_found)++;
                }
            }
            break;

        case ALTERNATE_APPID:
            hsession->set_chp_alt_candidate(strtol(match->action_data, nullptr, 10));
            hsession->set_skip_simple_detect(true);
            break;

        case HOLD_FLOW:
            hsession->set_chp_hold_flow(true);
            break;

        case GET_OFFSETS_FROM_REBUILT:
            hsession->set_rebuilt_offsets(true);
            hsession->set_chp_hold_flow(true);
            break;

        case SEARCH_UNSUPPORTED:
        case NO_ACTION:
            hsession->set_skip_simple_detect(true);
            break;
        default:
            break;
        }
    }

    // non-nullptr insert_sweep2 indicates the insert action we will use.
    if ( !inhibit_modify && insert_sweep2 && !cmd.chp_rewritten[pt] )
    {
        // We will take the first INSERT_FIELD with an action string,
        // which was decided with the setting of insert_sweep2.
        rewrite_chp(cmd.buffer[pt], cmd.length[pt], insert_sweep2->start_match_pos,
            insert_sweep2->mpattern->psize, insert_sweep2->mpattern->action_data,
            &cmd.chp_rewritten[pt], 1);     // insert
        (*total_found)++;
    }

    cmd.chp_matches[pt].clear();
    return ret;
}

static inline int replace_optional_string(char** optionalStr, const char* strToDup)
{
    if (optionalStr)
    {
        if (*optionalStr)
            snort_free(*optionalStr);

        *optionalStr = snort_strdup(strToDup);
    }
    return 0;
}

static inline const char* continue_buffer_scan(const char* start, const char* end,
    MatchedPatterns* mp, DetectorHTTPPattern*)
{
    const char* bp = start + mp->after_match_pos;
    if ( (bp >= end) || (*bp != ' ' && *bp != 0x09 && *bp != '/') )
        return nullptr;
    else
        return ++bp;
}

void HttpPatternMatchers::identify_user_agent(const char* start, int size, AppId& service_id,
    AppId& client_id, char** version)
{
    char temp_ver[MAX_VERSION_SIZE] = { 0 };
    MatchedPatterns* mp = nullptr;

    client_agent_matcher.find_all(start, size, &http_pattern_match, false, (void*)&mp);
    if (mp)
    {
        const char* end = start + size;
        const char* buffPtr = nullptr;
        int skypeDetect = 0;
        int mobileDetect = 0;
        int safariDetect = 0;
        int firefox_detected = 0;
        int android_browser_detected = 0;
        int dominant_pattern_detected = 0;
        bool appleEmailDetect = true;
        unsigned longest_misc_match = 0;
        unsigned i = 0;

        client_id = APP_ID_NONE;
        service_id = APP_ID_HTTP;
        for (MatchedPatterns* tmp = mp; tmp; tmp = tmp->next)
        {
            DetectorHTTPPattern* match = (DetectorHTTPPattern*)tmp->mpattern;
            switch (match->client_id)
            {
            case APP_ID_INTERNET_EXPLORER:
            case APP_ID_FIREFOX:
                if (dominant_pattern_detected)
                    break;
                buffPtr = continue_buffer_scan(start, end, tmp, match);
                if (!buffPtr)
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
                if (match->client_id == APP_ID_INTERNET_EXPLORER
                    && strstr((const char*)buffPtr, "SLCC2"))
                {
                    if ((MAX_VERSION_SIZE-i) >= (sizeof(COMPATIBLE_BROWSER_STRING) - 1))
                    {
                        strncat(temp_ver, COMPATIBLE_BROWSER_STRING, MAX_VERSION_SIZE - i);
                    }
                }
                // Pick firefox over some things, but pick a misc app over Firefox.
                if (match->client_id == APP_ID_FIREFOX)
                    firefox_detected = 1;
                service_id = APP_ID_HTTP;
                client_id = match->client_id;
                break;

            case APP_ID_CHROME:
                if (dominant_pattern_detected)
                    break;
                buffPtr = continue_buffer_scan(start, end, tmp, match);
                if (!buffPtr)
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
                service_id = APP_ID_HTTP;
                client_id = match->client_id;
                break;

            case APP_ID_ANDROID_BROWSER:
                if (dominant_pattern_detected)
                    break;
                buffPtr = continue_buffer_scan(start, end, tmp, match);
                if (!buffPtr)
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
            // fallthrough
            case APP_ID_WINDOWS_MEDIA_PLAYER:
            case APP_ID_BITTORRENT:
                buffPtr = continue_buffer_scan(start, end, tmp, match);
                if (!buffPtr)
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
                service_id = APP_ID_HTTP;
                client_id = match->client_id;
                goto done;

            case APP_ID_GOOGLE_DESKTOP:
                buffPtr = start + tmp->after_match_pos;

                if (buffPtr >= end)
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
                service_id = APP_ID_HTTP;
                client_id = match->client_id;
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
                    buffPtr = strstr(start, (const char*)APPLE_EMAIL_PATTERNS[i]);
                    appleEmailDetect  = (buffPtr && (i != 0 || buffPtr == start));
                }
                if (appleEmailDetect)
                {
                    dominant_pattern_detected = !(buffPtr && strstr((const char*)buffPtr,
                        SAFARI_PATTERN) != nullptr);
                    temp_ver[0] = 0;
                    service_id = APP_ID_HTTP;
                    client_id = match->client_id;
                }
                i = 0;
                break;

            case APP_ID_WGET:
                buffPtr = start + tmp->after_match_pos;
                if (buffPtr >= end)
                    break;
                while (i < MAX_VERSION_SIZE - 1 && buffPtr < end)
                {
                    temp_ver[i++] = *buffPtr++;
                }
                temp_ver[i] = 0;
                service_id = APP_ID_HTTP;
                client_id = match->client_id;
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

                service_id = APP_ID_HTTP;
                client_id = match->client_id;
                goto done;

            case APP_ID_SKYPE:
                skypeDetect  = 1;
                break;

            case APP_ID_HTTP:
                break;

            case APP_ID_OPERA:
                service_id = APP_ID_HTTP;
                client_id = match->client_id;
                break;

            case FAKE_VERSION_APP_ID:
                if (temp_ver[0])
                {
                    temp_ver[0] = 0;
                    i = 0;
                }
                buffPtr = start + tmp->after_match_pos;

                if (buffPtr >= end)
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
                if (match->client_id)
                {
                    dominant_pattern_detected = 1;
                    service_id = APP_ID_HTTP;
                    client_id = match->client_id;

                    if (match->pattern_size <= longest_misc_match)
                        break;
                    longest_misc_match = match->pattern_size;
                    i = 0;
                    /* if we already collected temp_ver information after seeing 'Version', let's
                       use that*/
                    buffPtr = start + tmp->after_match_pos;
                    if (buffPtr >= end)
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
                }
            }
        }

        if (mobileDetect && safariDetect && !dominant_pattern_detected)
        {
            service_id = APP_ID_HTTP;
            client_id = APP_ID_SAFARI_MOBILE;
        }
        else if (safariDetect && !dominant_pattern_detected)
        {
            service_id = APP_ID_HTTP;
            client_id = APP_ID_SAFARI;
        }
        else if (firefox_detected && !dominant_pattern_detected)
        {
            service_id = APP_ID_HTTP;
            client_id = APP_ID_FIREFOX;
        }
        else if (android_browser_detected && !dominant_pattern_detected)
        {
            service_id = APP_ID_HTTP;
            client_id = APP_ID_ANDROID_BROWSER;
        }
        else if (skypeDetect)        // Better to choose Skype over any other ID
        {
            service_id = APP_ID_SKYPE_AUTH;
            client_id = APP_ID_SKYPE;
        }
    }

done:
    replace_optional_string(version, temp_ver);
    free_matched_patterns(mp);
}

int HttpPatternMatchers::get_appid_by_pattern(const char* data, unsigned size, char** version)
{
    MatchedPatterns* mp = nullptr;

    via_matcher.find_all((const char*)data, size, &http_pattern_match, false, (void*)&mp);
    if (mp)
    {
        DetectorHTTPPattern* match = (DetectorHTTPPattern*)mp->mpattern;
        switch (match->service_id)
        {
        case APP_ID_SQUID:
        {
            char temp_ver[MAX_VERSION_SIZE];
            const char* data_ptr = data + mp->after_match_pos;
            const char* end = data + size;
            unsigned i = 0;

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

            temp_ver[i] = 0;
            replace_optional_string(version, temp_ver);
            free_matched_patterns(mp);
            return APP_ID_SQUID;
        }

        default:
            free_matched_patterns(mp);
            return APP_ID_NONE;
        }
    }

    return APP_ID_NONE;
}

#define HTTP_HEADER_WORKINGWITH_ASPROXY "ASProxy/"

AppId HttpPatternMatchers::scan_header_x_working_with(const char* data, uint32_t size,
    char** version)
{
    char temp_ver[MAX_VERSION_SIZE];

    temp_ver[0] = 0;

    if (size >= (sizeof(HTTP_HEADER_WORKINGWITH_ASPROXY) - 1)
        &&  memcmp(data, HTTP_HEADER_WORKINGWITH_ASPROXY,
        sizeof(HTTP_HEADER_WORKINGWITH_ASPROXY) - 1) == 0)
    {
        const char* end = data + size;
        data += sizeof(HTTP_HEADER_WORKINGWITH_ASPROXY) - 1;
        uint32_t i;

        for (i = 0;
            data < end && i < (MAX_VERSION_SIZE - 1) && *data != ')' && isprint(*data);
            data++)
        {
            temp_ver[i++] = (char)*data;
        }
        temp_ver[i] = 0;
        replace_optional_string(version, temp_ver);
        return APP_ID_ASPROXY;
    }
    return APP_ID_NONE;
}

AppId HttpPatternMatchers::get_appid_by_content_type(const char* data, int size)
{
    MatchedPatterns* mp = nullptr;

    content_type_matcher.find_all(data, size, &content_pattern_match, false, (void*)&mp);
    if (!mp)
        return APP_ID_NONE;

    DetectorHTTPPattern* match = mp->mpattern;
    AppId payload_id = match->app_id;

    free_matched_patterns(mp);

    return payload_id;
}

#define RTMP_MEDIA_STREAM_OFFSET    50000000
#define URL_SCHEME_END_PATTERN "://"
#define URL_SCHEME_MAX_LEN     (sizeof("https://")-1)

bool HttpPatternMatchers::get_appid_from_url(char* host, const char* url, char** version,
    const char* referer, AppId* ClientAppId, AppId* serviceAppId, AppId* payloadAppId,
    AppId* referredPayloadAppId, bool from_rtmp)
{
    char* temp_host = nullptr;
    tMlmpPattern patterns[3];
    bool payload_found = false;
    tMlmpTree* matcher = from_rtmp ? rtmp_host_url_matcher : host_url_matcher;

    if (!host && !url)
        return false;

    int url_len = 0;
    if (url)
    {
        size_t scheme_len = strlen(url);
        if (scheme_len > URL_SCHEME_MAX_LEN)
            scheme_len = URL_SCHEME_MAX_LEN;    // only search the first few bytes for scheme
        const char* url_offset = (const char*)service_strstr((const uint8_t*)url, scheme_len,
            (const uint8_t*)URL_SCHEME_END_PATTERN, sizeof(URL_SCHEME_END_PATTERN)-1);
        if (url_offset)
            url_offset += sizeof(URL_SCHEME_END_PATTERN)-1;
        else
            return false;

        url = url_offset;
        url_len = strlen(url);
    }

    int host_len;
    if (!host)
    {
        host = (char*)strchr(url, '/');
        if (host != nullptr)
            host_len = host - url;
        else
            host_len = url_len;
        if (host_len > 0)
        {
            temp_host = snort_strndup(url, host_len);
            if (!temp_host)
            {
                host_len = 0;
                host = nullptr;
            }
            else
                host = temp_host;
        }
    }
    else
        host_len = strlen(host);

    const char* path = nullptr;
    int path_len = 0;
    if (url_len)
    {
        if (url_len < host_len)
        {
            snort_free(temp_host);
            return false;
        }
        path_len = url_len - host_len;
        path = url + host_len;
    }

    patterns[0].pattern = (uint8_t*)host;
    patterns[0].patternSize = host_len;
    patterns[1].pattern = (const uint8_t*)path;
    patterns[1].patternSize = path_len;
    patterns[2].pattern = nullptr;

    HostUrlDetectorPattern* data = (HostUrlDetectorPattern*)mlmpMatchPatternUrl(matcher, patterns);
    if ( data )
    {
        payload_found = true;
        if ( url )
        {
            const char* q = strchr(url, '?');
            if ( q != nullptr )
            {
                tMlpPattern query;
                char temp_ver[MAX_VERSION_SIZE];
                temp_ver[0] = 0;
                query.pattern = (const uint8_t*)++q;
                query.patternSize = strlen(q);

                match_query_elements(&query, &data->query, temp_ver, MAX_VERSION_SIZE);

                if (temp_ver[0] != 0)
                    replace_optional_string(version, temp_ver);
            }
        }

        *ClientAppId = data->client_id;
        *serviceAppId = data->service_id;
        *payloadAppId = data->payload_id;
    }

    snort_free(temp_host);

    /* if referred_id feature id disabled, referer will be null */
    if ( referer and (referer[0] != '\0') and (!payload_found or
        AppInfoManager::get_instance().get_app_info_flags(data->payload_id,
        APPINFO_FLAG_REFERRED)) )
    {
        const char* referer_start = referer;
        size_t ref_len = strlen(referer);

        const char* referer_offset = (const char*)service_strstr((const uint8_t*)referer_start, ref_len,
            (const uint8_t*)URL_SCHEME_END_PATTERN, sizeof(URL_SCHEME_END_PATTERN)-1);

        if ( !referer_offset )
            return payload_found;

        referer_offset += sizeof(URL_SCHEME_END_PATTERN)-1;
        referer_start = referer_offset;
        int referer_len = strlen(referer_start);
        const char* referer_path = strchr(referer_start, '/');
        int referer_path_len = 0;

        if ( referer_path )
        {
            referer_path_len = strlen(referer_path);
            referer_len -= referer_path_len;
        }
        else
        {
            referer_path = "/";
            referer_path_len = 1;
        }

        if ( referer_len > 0 )
        {
            patterns[0].pattern = (const uint8_t*)referer_start;
            patterns[0].patternSize = referer_len;
            patterns[1].pattern = (const uint8_t*)referer_path;
            patterns[1].patternSize = referer_path_len;
            patterns[2].pattern = nullptr;
            HostUrlDetectorPattern* url_pattern_data = (HostUrlDetectorPattern*)mlmpMatchPatternUrl(matcher,
                patterns);
            if ( url_pattern_data != nullptr )
            {
                if ( payload_found )
                    *referredPayloadAppId = *payloadAppId;
                else
                    payload_found = true;
                *payloadAppId = url_pattern_data->payload_id;
            }
        }
    }

    return payload_found;
}

void HttpPatternMatchers::get_server_vendor_version(const char* data, int len, char** version,
    char** vendor, snort::AppIdServiceSubtype** subtype)
{
    int vendor_len = len;

    const char* ver = (const char*)memchr(data, '/', len);
    if ( ver )
    {
        const char* paren = nullptr;
        int version_len = 0;
        const char* subname = nullptr;
        int subname_len = 0;
        const char* subver = nullptr;
        const char* p;
        const char* end = data + len;
        vendor_len = ver - data;
        ver++;

        for (p = ver; *p && p < end; p++)
        {
            if ( *p == '(' )
            {
                subname = nullptr;
                paren = p;
            }
            else if ( *p == ')' )
            {
                subname = nullptr;
                paren = nullptr;
            }
            /* some admins put tags in their http response lines. the anchors will cause problems
             *  for adaptive profiles in snort, so let's just get rid of them */
            else if (*p == '<')
                break;
            else if ( !paren )
            {
                if (*p == ' ' || *p == '\t')
                {
                    if ( subname && subname_len > 0 && subver && *subname )
                    {
                        snort::AppIdServiceSubtype* sub =
                            (snort::AppIdServiceSubtype*)snort_calloc(
                            sizeof(snort::AppIdServiceSubtype));
                        char* tmp = (char*)snort_calloc(subname_len + 1);
                        memcpy(tmp, subname, subname_len);
                        tmp[subname_len] = 0;
                        sub->service = tmp;
                        int subver_len = p - subver;
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
                else if ( *p == '/' && subname )
                {
                    if (version_len <= 0)
                        version_len = subname - ver - 1;
                    subname_len = p - subname;
                    subver = p + 1;
                }
            }
        }

        if ( subname && subname_len > 0 && subver && *subname )
        {
            snort::AppIdServiceSubtype* sub =
                (snort::AppIdServiceSubtype*)snort_calloc(sizeof(snort::AppIdServiceSubtype));
            char* tmp = (char*)snort_calloc(subname_len + 1);
            memcpy(tmp, subname, subname_len);
            tmp[subname_len] = 0;
            sub->service = tmp;

            int subver_len = p - subver;
            if ( subver_len > 0 && *subver )
            {
                tmp = (char*)snort_calloc(subver_len + 1);
                memcpy(tmp, subver, subver_len);
                tmp[subver_len] = 0;
                sub->version = tmp;
            }
            sub->next = *subtype;
            *subtype = sub;
        }

        if ( version_len <= 0 )
            version_len = p - ver;
        if ( version_len >= MAX_VERSION_SIZE )
            version_len = MAX_VERSION_SIZE - 1;
        *version = (char*)snort_calloc(sizeof(char) * (version_len + 1));
        memcpy(*version, ver, version_len);
        *(*version + version_len) = '\0';
    }

    if ( vendor_len >= MAX_VERSION_SIZE )
        vendor_len = MAX_VERSION_SIZE - 1;
    *vendor = (char*)snort_calloc(sizeof(char) * (vendor_len + 1));
    memcpy(*vendor, data, vendor_len);
    *(*vendor + vendor_len) = '\0';
}

uint32_t HttpPatternMatchers::parse_multiple_http_patterns(const char* pattern,
    tMlmpPattern* parts, uint32_t numPartLimit, int level)
{
    uint32_t partNum = 0;

    if ( !pattern )
        return 0;

    const char* tmp = pattern;
    while (tmp && (partNum < numPartLimit))
    {
        const char* tmp2 = strstr(tmp, FP_OPERATION_AND);
        if ( tmp2 )
        {
            parts[partNum].pattern = (uint8_t*)snort_strndup(tmp, tmp2-tmp);
            parts[partNum].patternSize = strlen((const char*)parts[partNum].pattern);
            tmp = tmp2 + strlen(FP_OPERATION_AND);
        }
        else
        {
            parts[partNum].pattern = (uint8_t*)snort_strdup(tmp);
            parts[partNum].patternSize = strlen((const char*)parts[partNum].pattern);
            tmp = nullptr;
        }
        parts[partNum].level = level;

        if ( !parts[partNum].pattern )
        {
            for (unsigned i = 0; i <= partNum; i++)
                snort_free((void*)parts[i].pattern);

            snort::ErrorMessage("Failed to allocate memory");
            return 0;
        }
        partNum++;
    }

    return partNum;
}

