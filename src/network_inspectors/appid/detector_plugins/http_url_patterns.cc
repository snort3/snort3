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

// http_url_patterns.cc author Sourcefire Inc.

#include "http_url_patterns.h"

#include <string.h>

#include "log/messages.h"

#include "application_ids.h"
#include "http_common.h"
#include "util/sf_multi_mpse.h"
#include "util/sf_mlmp.h"
#include "utils/util.h"

static const char* const FP_OPERATION_AND = "%&%";
static const unsigned PATTERN_PART_MAX = 10;

static void destroyHosUrlDetectorPattern(HosUrlDetectorPattern* pattern)
{
    if (!pattern)
        return;

    destroyHosUrlDetectorPattern(pattern->next);

    if (pattern->host.pattern)
        snort_free(*(void**)&pattern->host.pattern);
    if (pattern->path.pattern)
        snort_free(*(void**)&pattern->path.pattern);
    if (pattern->query.pattern)
        snort_free(*(void**)&pattern->query.pattern);
    snort_free(pattern);
}

static int addHosUrlPatternToList(HosUrlDetectorPattern* detector,
    HosUrlPatternsList** hosUrlPatternsList)
{
    if (!detector)
        return -1;

    if (!(*hosUrlPatternsList))
    {
        *hosUrlPatternsList = (HosUrlPatternsList*)snort_calloc(sizeof(HosUrlPatternsList));
        (*hosUrlPatternsList)->head = detector;
        (*hosUrlPatternsList)->tail = detector;
    }
    else
    {
        (*hosUrlPatternsList)->tail->next = detector;
        (*hosUrlPatternsList)->tail = detector;
    }

    return 0;
}

void destroyHosUrlPatternList(HosUrlPatternsList** pHosUrlPatternsList)
{
    if (!(*pHosUrlPatternsList))
        return;

    destroyHosUrlDetectorPattern((*pHosUrlPatternsList)->head);
    snort_free(*pHosUrlPatternsList);
    *pHosUrlPatternsList = nullptr;
}

int addMlmpPattern(void* hosUrlMatcher, HosUrlPatternsList** hosUrlPatternsList,
    const uint8_t* host_pattern, int host_pattern_size,
    const uint8_t* path_pattern, int path_pattern_size, const uint8_t* query_pattern, int
    query_pattern_size,
    AppId appId, uint32_t payload_id, uint32_t service_id, uint32_t client_id, DHPSequence seq)
{
    static tMlmpPattern patterns[PATTERN_PART_MAX];
    int num_patterns;

    if (!host_pattern)
        return -1;

    if (!hosUrlMatcher)
        return -1;

    HosUrlDetectorPattern* detector = (HosUrlDetectorPattern*)snort_calloc(
        sizeof(HosUrlDetectorPattern));
    detector->host.pattern = (uint8_t*)snort_strdup((char*)host_pattern);

    if (path_pattern)
        detector->path.pattern = (uint8_t*)snort_strdup((char*)path_pattern);
    else
        detector->path.pattern = nullptr;

    if (query_pattern)
        detector->query.pattern = (uint8_t*)snort_strdup((char*)query_pattern);
    else
        detector->query.pattern = nullptr;

    detector->host.patternSize = host_pattern_size;
    detector->path.patternSize = path_pattern_size;
    detector->query.patternSize = query_pattern_size;
    detector->payload_id = payload_id;
    detector->service_id = service_id;
    detector->client_id = client_id;
    detector->seq = seq;
    detector->next = nullptr;
    if (appId > APP_ID_NONE)
        detector->appId = appId;
    else if (payload_id > APP_ID_NONE)
        detector->appId = payload_id;
    else if (client_id > APP_ID_NONE)
        detector->appId = client_id;
    else
        detector->appId = service_id;

    num_patterns = parseMultipleHTTPPatterns((const char*)host_pattern, patterns,
        PATTERN_PART_MAX, 0);
    if (path_pattern)
        num_patterns += parseMultipleHTTPPatterns((const char*)path_pattern, patterns+num_patterns,
            PATTERN_PART_MAX-num_patterns, 1);

    patterns[num_patterns].pattern = nullptr;

    if (addHosUrlPatternToList(detector, hosUrlPatternsList))
        return -1;

    return mlmpAddPattern((tMlmpTree*)hosUrlMatcher, patterns, detector);
}

uint32_t parseMultipleHTTPPatterns(const char* pattern, tMlmpPattern* parts, uint32_t
    numPartLimit, int level)
{
    uint32_t partNum = 0;
    const char* tmp;
    uint32_t i;

    if (!pattern)
        return 0;

    tmp = pattern;
    while (tmp && (partNum < numPartLimit))
    {
        const char* tmp2 = strstr(tmp, FP_OPERATION_AND);
        if (tmp2)
        {
            parts[partNum].pattern = (uint8_t*)strndup(tmp, tmp2-tmp);
            if (parts[partNum].pattern)
            {
                parts[partNum].patternSize = strlen((const char*)parts[partNum].pattern);
                tmp = tmp2+strlen(FP_OPERATION_AND);
            }
        }
        else
        {
            parts[partNum].pattern = (uint8_t*)snort_strdup(tmp);
            parts[partNum].patternSize = strlen((const char*)parts[partNum].pattern);
            tmp = nullptr;
        }
        parts[partNum].level = level;

        if (!parts[partNum].pattern)
        {
            for (i = 0; i <= partNum; i++)
                snort_free((void*)parts[i].pattern);

            ErrorMessage("Failed to allocate memory");
            return 0;
        }
        partNum++;
    }

    return partNum;
}

/**recursively destroy matcher.
 */
void destroyHosUrlMatcher(tMlmpTree** hosUrlMatcher)
{
    if (hosUrlMatcher && *hosUrlMatcher)
    {
        mlmpDestroy(*hosUrlMatcher);
        *hosUrlMatcher = nullptr;
    }
}

int matchQueryElements(
    tMlpPattern* packetData,
    tMlpPattern* userPattern,
    char* appVersion,
    size_t appVersionSize
    )
{
    const uint8_t* index;
    const uint8_t* endKey;
    const uint8_t* queryEnd;
    uint32_t extractedSize;
    uint32_t copySize = 0;

    if (appVersion == nullptr)
        return 0;

    appVersion[0] = '\0';

    if (!userPattern->pattern || !packetData->pattern)
        return 0;

    // queryEnd is 1 past the end.  key1=value1&key2=value2
    queryEnd = packetData->pattern + packetData->patternSize;
    for (index = packetData->pattern; index < queryEnd; index = endKey + 1)
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
                extractedSize = (endKey - index);
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

