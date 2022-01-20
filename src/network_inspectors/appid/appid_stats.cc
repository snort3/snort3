//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_stats.h"

#include "log/text_log.h"
#include "log/unified2.h"
#include "time/packet_time.h"

#include "appid_config.h"
#include "app_info_table.h"
#include "appid_inspector.h"
#include "appid_session.h"

using namespace snort;

#define URLCATBUCKETS   100
#define URLREPBUCKETS   5

static const char appid_stats_filename[] = "appid_stats.log";

static THREAD_LOCAL AppIdStatistics* appid_stats_manager = nullptr;

void AppIdStatistics::end_stats_period()
{
    SF_LIST* bucketList = log_buckets;
    log_buckets = curr_buckets;
    curr_buckets = bucketList;
}

StatsBucket* AppIdStatistics::get_stats_bucket(time_t start_time)
{
    StatsBucket* bucket = nullptr;

    if ( !curr_buckets )
        curr_buckets = sflist_new();

    SF_LNODE* l_node = nullptr;
    StatsBucket* l_bucket = nullptr;

    for ( l_bucket = (StatsBucket*)sflist_first(curr_buckets, &l_node); l_node && l_bucket;
        l_bucket = (StatsBucket*)sflist_next(&l_node) )
    {
        if (start_time == l_bucket->start_time)
        {
            bucket = l_bucket;
            break;
        }
        else if (start_time < l_bucket->start_time)
        {
            bucket = new StatsBucket;
            bucket->start_time = start_time;
            sflist_add_before(curr_buckets, l_node, bucket);
            break;
        }
    }

    if ( !l_node )
    {
        bucket = new StatsBucket;
        bucket->start_time = start_time;
        sflist_add_tail(curr_buckets, bucket);
    }

    return bucket;
}

void AppIdStatistics::open_stats_log_file()
{
    log = TextLog_Init(appid_stats_filename, 4096, roll_size);
}

void AppIdStatistics::dump_statistics()
{
    if ( !log_buckets )
        return;

    if ( !log )
        open_stats_log_file();

    struct StatsBucket* bucket = nullptr;

    while ((bucket = (struct StatsBucket*)sflist_remove_head(log_buckets)) != nullptr)
    {
        if ( bucket->app_record_cnt )
        {
            for (auto it : bucket->apps_tree)
            {
                struct AppIdStatRecord& record = it.second;

                // FIXIT-M %lu won't do time_t on 32-bit systems
                TextLog_Print(log, "%lu,%s," STDu64 "," STDu64 "\n",
                    packet_time(), record.app_name.c_str(), record.initiator_bytes, record.responder_bytes);
            }
        }
        delete bucket;
    }
}

AppIdStatistics::AppIdStatistics(const AppIdConfig& config)
{
    enabled = true;

    roll_size = config.app_stats_rollover_size;
    bucket_interval = config.app_stats_period;

    time_t now = get_time();
    start_stats_period(now);
}

AppIdStatistics::~AppIdStatistics()
{
    if ( !enabled )
        return;

    /*flush the last stats period. */
    end_stats_period();
    dump_statistics();

    if ( log )
        TextLog_Term(log);

    if ( log_buckets )
        snort_free(log_buckets);

    if ( curr_buckets )
    {
        while (auto bucket = (StatsBucket*)sflist_remove_head(curr_buckets))
        {
            delete bucket;
        }
        snort_free(curr_buckets);
    }
}

AppIdStatistics* AppIdStatistics::initialize_manager(const AppIdConfig& config)
{
    if ( !config.log_stats )
        return nullptr;

    appid_stats_manager = new AppIdStatistics(config);
    return appid_stats_manager;
}

AppIdStatistics* AppIdStatistics::get_stats_manager()
{ return appid_stats_manager; }

void AppIdStatistics::cleanup()
{ delete appid_stats_manager; }

static void update_stats(const AppIdSession& asd, AppId app_id, StatsBucket* bucket)
{
    auto it = bucket->apps_tree.find(app_id);
    if ( it == bucket->apps_tree.end() )
    {
        bool cooked_client = false;

        if ( app_id >= 2000000000 )
            cooked_client = true;

        // Skip stats for sessions using old odp context after reload detectors
        if (!pkt_thread_odp_ctxt or
            (pkt_thread_odp_ctxt->get_version() != asd.get_odp_ctxt_version()))
            return;

        OdpContext& odp_ctxt = asd.get_odp_ctxt();
        AppInfoTableEntry* entry
            = odp_ctxt.get_app_info_mgr().get_app_info_entry(app_id);

        const char* app_name;
        char tmp_buff[MAX_EVENT_APPNAME_LEN];
        if ( entry )
        {
            if (cooked_client)
            {
                snprintf(tmp_buff, MAX_EVENT_APPNAME_LEN, "_cl_%s", entry->app_name);
                tmp_buff[MAX_EVENT_APPNAME_LEN-1] = '\0';
                app_name = tmp_buff;
            }
            else
                app_name = entry->app_name;
        }
        else if ( app_id == APP_ID_UNKNOWN )
            app_name = "__unknown";
        else if ( app_id == APP_ID_NONE )
            app_name = "__none";
        else
        {
            if (cooked_client)
                snprintf(tmp_buff, MAX_EVENT_APPNAME_LEN, "_err_cl_%d",app_id);
            else
                snprintf(tmp_buff, MAX_EVENT_APPNAME_LEN, "_err_%d",app_id);

            tmp_buff[MAX_EVENT_APPNAME_LEN - 1] = '\0';
            app_name = tmp_buff;
        }

        bucket->apps_tree.emplace(app_id, AppIdStatRecord(app_name, asd.stats.initiator_bytes,
            asd.stats.responder_bytes));
        bucket->app_record_cnt += 1;
    }
    else
    {
        auto& record = it->second;
        record.initiator_bytes += asd.stats.initiator_bytes;
        record.responder_bytes += asd.stats.responder_bytes;
    }
}

void AppIdStatistics::update(const AppIdSession& asd)
{
    time_t now = get_time();

    if ( now >= bucket_end )
    {
        end_stats_period();
        dump_statistics();
        start_stats_period(now);
    }

    time_t bucketTime = asd.stats.first_packet_second -
        (asd.stats.first_packet_second % bucket_interval);

    StatsBucket* bucket = get_stats_bucket(bucketTime);
    if ( !bucket )
        return;

    bucket->totalStats.tx_byte_cnt += asd.stats.initiator_bytes;
    bucket->totalStats.rx_byte_cnt += asd.stats.responder_bytes;

    AppId web_app_id, service_id, client_id;
    asd.get_api().get_first_stream_app_ids(service_id, client_id, web_app_id);

    if ( web_app_id > APP_ID_NONE )
        update_stats(asd, web_app_id, bucket);

    if ( service_id && ( service_id != web_app_id ) )
        update_stats(asd, service_id, bucket);

    if ( client_id > APP_ID_NONE && client_id != service_id
        && client_id != web_app_id )
        update_stats(asd, client_id, bucket);
}

void AppIdStatistics::flush()
{
    if ( !enabled )
        return;

    time_t now = get_time();
    if (now >= bucket_end)
    {
        end_stats_period();
        dump_statistics();
        start_stats_period(now);
    }
}

