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

// appid_stats.cc author Sourcefire Inc.

#include "appid_stats.h"

#include <cerrno>
#include <cstdio>
#include <ctime>
#include <cstdint>

#include "log/messages.h"
#include "loggers/unified2_common.h"
#include "utils/sflsq.h"
#include "utils/util.h"

#include "appid_api.h"
#include "appid_flow_data.h"
#include "fw_appid.h"
#include "util/fw_avltree.h"
#include "util/output_file.h"

#define URLCATBUCKETS   100
#define URLREPBUCKETS   5

// FIXIT - find out where this is defined in snort 2.x and define appropriately here
#if 1
#define UNIFIED2_IDS_EVENT_APPSTAT 1
#endif

static time_t bucketStart;
static time_t bucketInterval;
static time_t bucketEnd;

struct AppIdStatRecord
{
    uint32_t app_id;
    uint32_t initiatorBytes;
    uint32_t responderBytes;
};

#ifdef WIN32
#pragma pack(push,app_stats,1)
#else
#pragma pack(1)
#endif

struct AppIdStatOutputRecord
{
    char appName[MAX_EVENT_APPNAME_LEN];
    uint32_t initiatorBytes;
    uint32_t responderBytes;
};

#ifdef WIN32
#pragma pack(pop,app_stats)
#else
#pragma pack()
#endif

struct StatsBucket
{
    uint32_t startTime;
    FwAvlTree* appsTree;
    struct
    {
        size_t txByteCnt;
        size_t rxByteCnt;
    } totalStats;
    uint32_t appRecordCnt;
};

static SF_LIST* currBuckets;
static SF_LIST* logBuckets;

static const char* appFilePath;

static FILE* appfp;

static size_t appSize;

static time_t appTime;

Serial_Unified2_Header header;

static size_t rollSize;
static time_t rollPeriod;
static bool enableAppStats;

static void endStats2Period(void);
static void startStats2Period(time_t startTime);
static struct StatsBucket* getStatsBucket(time_t startTime);
static void dumpStats2(void);

static void deleteRecord(void* record)
{ snort_free(record); }

static inline time_t get_time()
{
    auto now = time(nullptr);
    return now - (now % bucketInterval);
}

void appIdStatsUpdate(AppIdData* session)
{
    if ( !enableAppStats )
        return;

    time_t now = get_time();

    if (now >= bucketEnd)
    {
        endStats2Period();
        dumpStats2();
        startStats2Period(now);
    }

    time_t bucketTime = session->stats.firstPktsecond -
        (session->stats.firstPktsecond % bucketInterval);

    StatsBucket* bucket = getStatsBucket(bucketTime);
    if ( !bucket )
        return;

    bucket->totalStats.txByteCnt += session->stats.initiatorBytes;
    bucket->totalStats.rxByteCnt += session->stats.responderBytes;

    const uint32_t web_app_id = pickPayloadId(session);
    if (web_app_id > APP_ID_NONE)
    {
        const uint32_t app_id = web_app_id;
        AppIdStatRecord* record = (AppIdStatRecord*)fwAvlLookup(app_id, bucket->appsTree);
        if ( !record )
        {
            record = (AppIdStatRecord*)snort_calloc(sizeof(struct AppIdStatRecord));
            if (fwAvlInsert(app_id, record, bucket->appsTree) == 0)
            {
                record->app_id = app_id;
                bucket->appRecordCnt += 1;
#ifdef DEBUG_STATS
                fprintf(SF_DEBUG_FILE, "New App: %u Count %u\n", record->app_id,
                    bucket->appRecordCnt);
#endif
            }
            else
            {
                // FIXIT-M really? we just silently ignore an allocation failure?
                snort_free(record);
                record = nullptr;
            }
        }

        if (record)
        {
            record->initiatorBytes += session->stats.initiatorBytes;
            record->responderBytes += session->stats.responderBytes;
        }
    }

    const uint32_t service_app_id = pickServiceAppId(session);
    if ((service_app_id) &&
        (service_app_id != web_app_id))
    {
        const uint32_t app_id = service_app_id;
        AppIdStatRecord* record = (AppIdStatRecord*)fwAvlLookup(app_id, bucket->appsTree);
        if ( !record )
        {
            record = (AppIdStatRecord*)snort_calloc(sizeof(struct AppIdStatRecord));
            if (fwAvlInsert(app_id, record, bucket->appsTree) == 0)
            {
                record->app_id = app_id;
                bucket->appRecordCnt += 1;
#ifdef DEBUG_STATS
                fprintf(SF_DEBUG_FILE, "New App: %u Count %u\n", record->app_id,
                    bucket->appRecordCnt);
#endif
            }
            else
            {
                // FIXIT-M really? don't ignore insert failure? add a stat here
                snort_free(record);
                record = nullptr;
            }
        }

        if (record)
        {
            record->initiatorBytes += session->stats.initiatorBytes;
            record->responderBytes += session->stats.responderBytes;
        }
    }

    const uint32_t client_app_id = pickClientAppId(session);
    if (client_app_id > APP_ID_NONE
        && client_app_id != service_app_id
        && client_app_id != web_app_id)
    {
        const uint32_t app_id = client_app_id;

        AppIdStatRecord* record = (AppIdStatRecord*)fwAvlLookup(app_id, bucket->appsTree);
        if ( !record )
        {
            record = (AppIdStatRecord*)snort_calloc(sizeof(struct AppIdStatRecord));
            if (fwAvlInsert(app_id, record, bucket->appsTree) == 0)
            {
                record->app_id = app_id;
                bucket->appRecordCnt += 1;
#ifdef DEBUG_STATS
                fprintf(SF_DEBUG_FILE, "New App: %u Count %u\n", record->app_id,
                    bucket->appRecordCnt);
#endif
            }
            else
            {
                // FIXIT-M really? we just silently ignore an allocation failure?
                snort_free(record);
                record = nullptr;
            }
        }

        if (record)
        {
            record->initiatorBytes += session->stats.initiatorBytes;
            record->responderBytes += session->stats.responderBytes;
        }
    }
}

void appIdStatsInit(AppIdModuleConfig* config)
{
    if (config->app_stats_filename)
    {
        enableAppStats = true;
        appFilePath = config->app_stats_filename;

        rollPeriod = config->app_stats_rollover_time;
        rollSize = config->app_stats_rollover_size;
        bucketInterval = config->app_stats_period;

        time_t now = get_time();
        startStats2Period(now);
        appfp = nullptr;
    }
    else
        enableAppStats = false;
}

static void appIdStatsCloseFiles()
{
    if (appfp)
    {
        fclose(appfp);
        appfp = nullptr;
    }
}

void appIdStatsReinit()
{
    // FIXIT-L J really should something like:
    // if ( !stats_files_are_open() )
    //      return;
    if (!enableAppStats)
        return;

    appIdStatsCloseFiles();
}

void appIdStatsIdleFlush()
{
    if (!enableAppStats)
        return;

    time_t now = get_time();
    if (now >= bucketEnd)
    {
        endStats2Period();
        dumpStats2();
        startStats2Period(now);
    }
}

static void startStats2Period(time_t startTime)
{
    bucketStart = startTime;
    bucketEnd = bucketStart + bucketInterval;
}

static void endStats2Period(void)
{
    SF_LIST* bucketList = logBuckets;
    logBuckets = currBuckets;
    currBuckets = bucketList;
}

static StatsBucket* getStatsBucket(time_t startTime)
{
    StatsBucket* bucket = nullptr;

    if ( !currBuckets )
    {
        currBuckets = sflist_new();
#       ifdef DEBUG_STATS
        fprintf(SF_DEBUG_FILE, "New Stats Bucket List\n");
#       endif
    }

    if ( !currBuckets )
        return nullptr;

    SF_LNODE* lNode = nullptr;
    StatsBucket* lBucket = nullptr;

    for ( lBucket = (StatsBucket*)sflist_first(currBuckets, &lNode); lNode && lBucket;
        lBucket = (StatsBucket*)sflist_next(&lNode) )
    {
        if (startTime == lBucket->startTime)
        {
            bucket = lBucket;
            break;
        }
        else if (startTime < lBucket->startTime)
        {
            bucket = (StatsBucket*)snort_calloc(sizeof(StatsBucket));
            bucket->startTime = startTime;
            bucket->appsTree = fwAvlInit();
            sflist_add_before(currBuckets, lNode, bucket);

#ifdef DEBUG_STATS
            fprintf(SF_DEBUG_FILE, "New Bucket Time: %u before %u\n",
                bucket->startTime, lBucket->startTime);
#endif
            break;
        }
    }

    if ( !lNode )
    {
        bucket = (StatsBucket*)snort_calloc(sizeof(StatsBucket));
        bucket->startTime = startTime;
        bucket->appsTree = fwAvlInit();
        sflist_add_tail(currBuckets, bucket);

#ifdef DEBUG_STATS
        fprintf(SF_DEBUG_FILE, "New Bucket Time: %u at tail\n", bucket->startTime);
#endif
    }

    return bucket;
}

static void dumpStats2()
{
    struct StatsBucket* bucket = nullptr;
    uint8_t* buffer;
    uint32_t* buffPtr;
    struct    FwAvlNode* node;
    struct AppIdStatRecord* record;
    size_t buffSize;
    time_t currTime = time(nullptr);

    if (logBuckets == nullptr)
        return;

    while ((bucket = (struct StatsBucket*)sflist_remove_head(logBuckets)) != nullptr)
    {
        if (bucket->appRecordCnt)
        {
            buffSize = bucket->appRecordCnt * sizeof(struct AppIdStatOutputRecord) +
                4 * sizeof(uint32_t);
            header.type = UNIFIED2_IDS_EVENT_APPSTAT;
            header.length = buffSize - 2*sizeof(uint32_t);
            buffer = (uint8_t*)snort_calloc(buffSize);
#           ifdef DEBUG_STATS
            fprintf(SF_DEBUG_FILE, "Write App Records %u Size: %lu\n",
                bucket->appRecordCnt, buffSize);
#           endif
        }
        else
            buffer = nullptr;

        if (buffer)
        {
            buffPtr = (uint32_t*)buffer;
            *buffPtr++ = htonl(header.type);
            *buffPtr++ = htonl(header.length);
            *buffPtr++ = htonl(bucket->startTime);
            *buffPtr++ = htonl(bucket->appRecordCnt);

            for (node = fwAvlFirst(bucket->appsTree); node != nullptr; node = fwAvlNext(node))
            {
                struct AppIdStatOutputRecord* recBuffPtr;
                const char* appName;
                bool cooked_client = false;
                AppId app_id;
                char tmpBuff[MAX_EVENT_APPNAME_LEN];

                record = (struct AppIdStatRecord*)node->data;
                app_id = record->app_id;

                recBuffPtr = (struct AppIdStatOutputRecord*)buffPtr;

                if (app_id >= 2000000000)
                {
                    cooked_client = true;
                    app_id -= 2000000000;
                }

                AppInfoTableEntry* entry = appInfoEntryGet(app_id, pAppidActiveConfig);
                if (entry)
                {
                    appName = entry->appName;
                    if (cooked_client)
                    {
                        snprintf(tmpBuff, MAX_EVENT_APPNAME_LEN, "_cl_%s",appName);
                        tmpBuff[MAX_EVENT_APPNAME_LEN-1] = 0;
                        appName = tmpBuff;
                    }
                }
                else if (app_id == APP_ID_UNKNOWN || app_id == APP_ID_UNKNOWN_UI)
                    appName = "__unknown";
                else if (app_id == APP_ID_NONE)
                    appName = "__none";
                else
                {
                    ErrorMessage("invalid appid in appStatRecord (%u)\n", record->app_id);
                    if (cooked_client)
                    {
                        snprintf(tmpBuff, MAX_EVENT_APPNAME_LEN, "_err_cl_%u",app_id);
                    }
                    else
                    {
                        snprintf(tmpBuff, MAX_EVENT_APPNAME_LEN, "_err_%u",app_id); // ODP out of
                                                                                    // sync?
                    }
                    tmpBuff[MAX_EVENT_APPNAME_LEN-1] = 0;
                    appName = tmpBuff;
                }

                memcpy(recBuffPtr->appName, appName, MAX_EVENT_APPNAME_LEN);

                /**buffPtr++ = htonl(record->app_id); */
                recBuffPtr->initiatorBytes = htonl(record->initiatorBytes);
                recBuffPtr->responderBytes = htonl(record->responderBytes);

                buffPtr += sizeof(*recBuffPtr)/sizeof(*buffPtr);
            }

            if (appFilePath)
            {
                if (!appfp)
                {
                    appfp = openOutputFile(appFilePath, currTime);
                    appTime = currTime;
                    appSize = 0;
                }
                else if (((currTime - appTime) > rollPeriod) ||
                    ((appSize + buffSize) > rollSize))
                {
                    appfp = rolloverOutputFile(appFilePath, appfp, currTime);
                    appTime = currTime;
                    appSize = 0;
                }
                if (appfp)
                {
                    if ((fwrite(buffer, buffSize, 1, appfp) == 1) && (fflush(appfp) == 0))
                    {
                        appSize += buffSize;
                    }
                    else
                    {
                        ErrorMessage(
                            "NGFW Rule Engine Failed to write to statistics file (%s): %s\n",
                            appFilePath, strerror(errno));
                        fclose(appfp);
                        appfp = nullptr;
                    }
                }
            }
            snort_free(buffer);
        }
        fwAvlDeleteTree(bucket->appsTree, deleteRecord);
        snort_free(bucket);
    }
}

void appIdStatsFini()
{
    if (!enableAppStats)
        return;

    /*flush the last stats period. */
    endStats2Period();
    dumpStats2();

    if (!currBuckets)
        return;

    while (auto bucket = (StatsBucket*)sflist_remove_head(currBuckets))
    {
        fwAvlDeleteTree(bucket->appsTree, deleteRecord);
        snort_free(bucket);
    }

    snort_free(currBuckets);

    if (logBuckets)
        snort_free(logBuckets);

    appIdStatsCloseFiles();
}

