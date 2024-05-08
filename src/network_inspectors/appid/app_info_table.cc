//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// app_info_table.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "app_info_table.h"

#include <climits>
#include <fstream>
#include <string>
#include <unistd.h>

#include "log/messages.h"
#include "log/unified2.h"
#include "main/snort_config.h"
#include "target_based/snort_protocols.h"
#include "utils/util_cstring.h"

#include "appid_api.h"
#include "appid_config.h"
#include "appid_debug.h"
#include "appid_inspector.h"
#include "appid_peg_counts.h"

using namespace snort;

#define MAX_TABLE_LINE_LEN      1024
static const int MIN_MAX_TP_FLOW_DEPTH = 1;
static const int MAX_MAX_TP_FLOW_DEPTH = 1000000;
static const int MIN_HOST_PORT_APP_CACHE_LOOKUP_INTERVAL = 1;
static const int MAX_HOST_PORT_APP_CACHE_LOOKUP_INTERVAL = 1000000;
static const int MIN_HOST_PORT_APP_CACHE_LOOKUP_RANGE = 1;
static const int MAX_HOST_PORT_APP_CACHE_LOOKUP_RANGE = 1000000;
static const char* APP_CONFIG_FILE = "appid.conf";
static const char* USR_CONFIG_FILE = "userappid.conf";
const char* APP_MAPPING_FILE = "appMapping.data";

AppInfoTableEntry::AppInfoTableEntry(AppId id, char* name)
    : appId(id), serviceId(id), clientId(id), payloadId(id), app_name(name)
{
    app_name_key = AppInfoManager::strdup_to_lower(name);
}

AppInfoTableEntry::AppInfoTableEntry(AppId id, char* name, AppId sid, AppId cid, AppId pid) :
    appId(id), serviceId(sid), clientId(cid), payloadId(pid), app_name(name)
{
    app_name_key = AppInfoManager::strdup_to_lower(name);
}

AppInfoTableEntry::~AppInfoTableEntry()
{
    if (app_name)
        snort_free(app_name);
    if (app_name_key)
        snort_free(app_name_key);
}

bool AppInfoManager::is_existing_entry(AppInfoTableEntry* entry)
{
    AppInfoNameTable::iterator app;

    app = app_info_name_table.find(entry->app_name_key);
    return app != app_info_name_table.end();
}

AppInfoTableEntry* AppInfoManager::find_app_info_by_name(const char* app_name)
{
    AppInfoTableEntry* entry = nullptr;
    AppInfoNameTable::iterator app;
    const char* search_name = AppInfoManager::strdup_to_lower(app_name);

    app = app_info_name_table.find(search_name);
    if (app != app_info_name_table.end())
        entry = app->second;

    snort_free((void*)search_name);
    return entry;
}

bool AppInfoManager::add_entry_to_app_info_name_table(const char* app_name,
    AppInfoTableEntry* entry)
{
    bool added = true;

    if (!is_existing_entry(entry))
        app_info_name_table[app_name] = entry;
    else
    {
        appid_log(nullptr, TRACE_WARNING_LEVEL, "App name, \"%s\" is a duplicate entry will be shared by "
            "each detector.\n", app_name);
        added = false;
    }
    return added;
}

AppId AppInfoManager::get_static_app_info_entry(AppId appid)
{
    if (appid > 0 && appid < SF_APPID_BUILDIN_MAX)
        return appid;
    if ((appid >= SF_APPID_CSD_MIN) &&
        appid < (SF_APPID_CSD_MIN + (SF_APPID_MAX - SF_APPID_BUILDIN_MAX)))
        return (SF_APPID_BUILDIN_MAX + appid - SF_APPID_CSD_MIN);
    return 0;
}

char* AppInfoManager::strdup_to_lower(const char* source)
{
    char* dest = snort_strdup(source);
    char* lcd = dest;

    while (*lcd)
    {
        *lcd = tolower(*lcd);
        lcd++;
    }
    return dest;
}

bool AppInfoManager::configured()
{
    return !app_info_table.empty();
}

AppInfoTableEntry* AppInfoManager::get_app_info_entry(AppId appId,
    const AppInfoTable& lookup_table)
{
    AppId tmp;
    AppInfoTable::const_iterator app;
    AppInfoTableEntry* entry = nullptr;

    if ((tmp = get_static_app_info_entry(appId)))
    {
        app = lookup_table.find(tmp);
        if (app != lookup_table.end())
            entry = app->second;
    }
    else
    {
        app = custom_app_info_table.find(appId);
        if (app != custom_app_info_table.end())
            entry = app->second;
    }
    return entry;
}

AppInfoTableEntry* AppInfoManager::get_app_info_entry(AppId appId)
{
    return get_app_info_entry(appId, app_info_table);
}

AppInfoTableEntry* AppInfoManager::add_dynamic_app_entry(const char* app_name)
{
    if (!app_name || strlen(app_name) >= MAX_EVENT_APPNAME_LEN)
    {
        appid_log(nullptr, TRACE_ERROR_LEVEL, "Appname invalid or too long: %s\n", app_name);
        return nullptr;
    }

    AppInfoTableEntry* entry = find_app_info_by_name(app_name);
    if (!entry)
    {
        entry = new AppInfoTableEntry(next_custom_appid++, snort_strdup(app_name));
        custom_app_info_table[entry->appId] = entry;

        if (!add_entry_to_app_info_name_table(entry->app_name_key, entry))
        {
            delete entry;
            return nullptr;
        }
    }
    return entry;
}

void AppInfoManager::cleanup_appid_info_table()
{
    for (const auto& kv: app_info_table)
        delete(kv.second);
    app_info_table.erase(app_info_table.begin(), app_info_table.end());

    for (const auto& kv: custom_app_info_table)
        delete(kv.second);

    custom_app_info_table.erase(custom_app_info_table.begin(), custom_app_info_table.end());
    app_info_name_table.erase(app_info_name_table.begin(), app_info_name_table.end());
}

void AppInfoManager::dump_app_info_table()
{
    appid_log(nullptr, TRACE_INFO_LEVEL, "Cisco provided detectors:\n");
    for (auto& kv: app_info_table)
        appid_log(nullptr, TRACE_INFO_LEVEL, "%s\t%d\t%s\n", kv.second->app_name, kv.second->appId,
            (kv.second->flags & APPINFO_FLAG_ACTIVE) ? "active" : "inactive");

    appid_log(nullptr, TRACE_INFO_LEVEL, "User provided detectors:\n");
    for (auto& kv: custom_app_info_table)
        appid_log(nullptr, TRACE_INFO_LEVEL, "%s\t%d\t%s\n", kv.second->app_name, kv.second->appId,
            (kv.second->flags & APPINFO_FLAG_ACTIVE) ? "active" : "inactive");
}

AppId AppInfoManager::get_appid_by_service_id(uint32_t id)
{
    AppInfoTableEntry* entry = get_app_info_entry(id, app_info_service_table);
    return entry ? entry->appId : APP_ID_NONE;
}

AppId AppInfoManager::get_appid_by_client_id(uint32_t id)
{
    AppInfoTableEntry* entry = get_app_info_entry(id, app_info_client_table);
    return entry ? entry->appId : APP_ID_NONE;
}

AppId AppInfoManager::get_appid_by_payload_id(uint32_t id)
{
    AppInfoTableEntry* entry = get_app_info_entry(id, app_info_payload_table);
    return entry ? entry->appId : APP_ID_NONE;
}

const char* AppInfoManager::get_app_name(int32_t id)
{
    AppInfoTableEntry* entry = get_app_info_entry(id);
    return entry ? entry->app_name : nullptr;
}

const char* AppInfoManager::get_app_name_key(int32_t id)
{
    AppInfoTableEntry* entry = get_app_info_entry(id);
    return entry ? entry->app_name_key : nullptr;
}

AppId AppInfoManager::get_appid_by_name(const char* app_name)
{
    AppInfoTableEntry* entry = find_app_info_by_name(app_name);
    return entry ? entry->appId : APP_ID_NONE;
}

void AppInfoManager::set_app_info_active(AppId appId)
{
    if (appId == APP_ID_NONE)
        return;

    AppInfoTableEntry* entry = get_app_info_entry(appId);
    if (entry)
        entry->flags |= APPINFO_FLAG_ACTIVE;
    else
        ParseWarning(WARN_PLUGINS, "appid: no entry in %s for %d", APP_MAPPING_FILE, appId);
}

void AppInfoManager::load_odp_config(OdpContext& odp_ctxt, const char* path)
{
    char buf[MAX_TABLE_LINE_LEN];
    unsigned line = 0;
    const char* CONF_SEPARATORS = "\t\n\r ";

    FILE* config_file = fopen(path, "r");
    if (config_file == nullptr)
        return;

    while (fgets(buf, sizeof(buf), config_file) != nullptr)
    {
        char* context;

        line++;
        char* token = strtok_r(buf, CONF_SEPARATORS, &context);
        if (token == nullptr)
        {
            ParseWarning(WARN_CONF, "appid: No 'conf_type' value at line %s:%u\n", path, line);
            continue;
        }
        char* conf_type = token;

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (token == nullptr)
        {
            ParseWarning(WARN_CONF, "appid: No 'conf_key' value at line %s:%u\n", path, line);
            continue;
        }
        char* conf_key = token;

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (token == nullptr)
        {
            ParseWarning(WARN_CONF, "appid: No 'conf_val' value at line %s:%u\n", path, line);
            continue;
        }
        char* conf_val = token;

        /* APPID configurations are for anything else - currently we only have ssl_reinspect */
        if (!(strcasecmp(conf_type, "appid")))
        {
            if (!(strcasecmp(conf_key, "max_tp_flow_depth")))
            {
                int max_tp_flow_depth = atoi(conf_val);
                if (max_tp_flow_depth < MIN_MAX_TP_FLOW_DEPTH
                    || max_tp_flow_depth > MAX_MAX_TP_FLOW_DEPTH)
                {
                    ParseWarning(WARN_CONF,
                        "appid: invalid max_tp_flow_depth %d, must be between %d and %d\n.",
                        max_tp_flow_depth, MIN_MAX_TP_FLOW_DEPTH, MAX_MAX_TP_FLOW_DEPTH);
                }
                else
                {
                    odp_ctxt.max_tp_flow_depth = max_tp_flow_depth;
                }
            }
            else if (!(strcasecmp(conf_key, "host_port_app_cache_lookup_interval")))
            {
                int host_port_app_cache_lookup_interval = atoi(conf_val);
                if (host_port_app_cache_lookup_interval <
                    MIN_HOST_PORT_APP_CACHE_LOOKUP_INTERVAL ||
                    host_port_app_cache_lookup_interval >
                    MAX_HOST_PORT_APP_CACHE_LOOKUP_INTERVAL)
                {
                    ParseWarning(WARN_CONF,
                        "appid: invalid host_port_app_cache_lookup_interval %d, "
                        "must be between %d and %d\n.",
                        host_port_app_cache_lookup_interval,
                        MIN_HOST_PORT_APP_CACHE_LOOKUP_INTERVAL,
                        MAX_HOST_PORT_APP_CACHE_LOOKUP_INTERVAL);
                }
                else
                {
                    odp_ctxt.host_port_app_cache_lookup_interval =
                        host_port_app_cache_lookup_interval;
                }
            }
            else if (!(strcasecmp(conf_key, "host_port_app_cache_lookup_range")))
            {
                int host_port_app_cache_lookup_range = atoi(conf_val);
                if (host_port_app_cache_lookup_range < MIN_HOST_PORT_APP_CACHE_LOOKUP_RANGE
                    || host_port_app_cache_lookup_range > MAX_HOST_PORT_APP_CACHE_LOOKUP_RANGE)
                {
                     ParseWarning(WARN_CONF,
                        "appid: invalid host_port_app_cache_lookup_range %d, "
                        "must be between %d and %d\n.", host_port_app_cache_lookup_range,
                        MIN_HOST_PORT_APP_CACHE_LOOKUP_RANGE,
                        MAX_HOST_PORT_APP_CACHE_LOOKUP_RANGE);
                }
                else
                {
                    odp_ctxt.host_port_app_cache_lookup_range = host_port_app_cache_lookup_range;
                }
            }
            else if (!(strcasecmp(conf_key, "is_host_port_app_cache_runtime")))
            {
                if (!(strcasecmp(conf_val, "enabled")))
                {
                    odp_ctxt.is_host_port_app_cache_runtime = true;
                }
            }
            else if (!(strcasecmp(conf_key, "check_host_port_app_cache")))
            {
                if (!(strcasecmp(conf_val, "enabled")))
                {
                    odp_ctxt.check_host_port_app_cache = true;
                }
            }
            else if (!(strcasecmp(conf_key, "check_host_cache_unknown_ssl")))
            {
                if (!(strcasecmp(conf_val, "enabled")))
                {
                    odp_ctxt.check_host_cache_unknown_ssl = true;
                }
            }
            else if (!(strcasecmp(conf_key, "allow_port_wildcard_host_cache")))
            {
                if (!(strcasecmp(conf_val, "enabled")))
                {
                    odp_ctxt.allow_port_wildcard_host_cache = true;
                }
            }
            else if (!(strcasecmp(conf_key, "recheck_for_portservice_appid")))
            {
                if (!(strcasecmp(conf_val, "enabled")))
                {
                    odp_ctxt.recheck_for_portservice_appid = true;
                }
            }
            else if (!(strcasecmp(conf_key, "bittorrent_aggressiveness")))
            {
                int aggressiveness = atoi(conf_val);
                appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: bittorrent_aggressiveness %d\n", aggressiveness);
                if (aggressiveness >= 50)
                {
                    odp_ctxt.host_port_app_cache_lookup_interval = 5;
                    odp_ctxt.recheck_for_portservice_appid = true;
                    set_app_info_flags(APP_ID_BITTORRENT, APPINFO_FLAG_DEFER);
                    set_app_info_flags(APP_ID_BITTORRENT, APPINFO_FLAG_DEFER_PAYLOAD);
                    odp_ctxt.max_tp_flow_depth = 25;
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: host_port_app_cache_lookup_interval %d\n",
                        odp_ctxt.host_port_app_cache_lookup_interval);
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: recheck_for_portservice_appid enabled\n");
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: defer_to_thirdparty %d\n", APP_ID_BITTORRENT);
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: defer_payload_to_thirdparty %d\n", APP_ID_BITTORRENT);
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: max_tp_flow_depth %d\n", odp_ctxt.max_tp_flow_depth);
                }
                if (aggressiveness >= 80)
                {
                    odp_ctxt.allow_port_wildcard_host_cache = true;
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: allow_port_wildcard_host_cache enabled\n");
                }
            }
            else if (!(strcasecmp(conf_key, "ultrasurf_aggressiveness")))
            {
                int aggressiveness = atoi(conf_val);
                appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: ultrasurf_aggressiveness %d\n", aggressiveness);
                if (aggressiveness >= 50)
                {
                    odp_ctxt.check_host_cache_unknown_ssl = true;
                    set_app_info_flags(APP_ID_ULTRASURF, APPINFO_FLAG_DEFER);
                    set_app_info_flags(APP_ID_ULTRASURF, APPINFO_FLAG_DEFER_PAYLOAD);
                    odp_ctxt.max_tp_flow_depth = 25;
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: check_host_cache_unknown_ssl enabled\n");
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: defer_to_thirdparty %d\n", APP_ID_ULTRASURF);
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: defer_payload_to_thirdparty %d\n", APP_ID_ULTRASURF);
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: max_tp_flow_depth %d\n", odp_ctxt.max_tp_flow_depth);
                }
                if (aggressiveness >= 80)
                {
                    odp_ctxt.allow_port_wildcard_host_cache = true;
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: allow_port_wildcard_host_cache enabled\n");
                }
            }
            else if (!(strcasecmp(conf_key, "psiphon_aggressiveness")))
            {
                int aggressiveness = atoi(conf_val);
                appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: psiphon_aggressiveness %d\n", aggressiveness);
                if (aggressiveness >= 50)
                {
                    odp_ctxt.check_host_cache_unknown_ssl = true;
                    set_app_info_flags(APP_ID_PSIPHON, APPINFO_FLAG_DEFER);
                    set_app_info_flags(APP_ID_PSIPHON, APPINFO_FLAG_DEFER_PAYLOAD);
                    odp_ctxt.max_tp_flow_depth = 25;
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: check_host_cache_unknown_ssl enabled\n");
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: defer_to_thirdparty %d\n", APP_ID_PSIPHON);
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: defer_payload_to_thirdparty %d\n", APP_ID_PSIPHON);
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: max_tp_flow_depth %d\n", odp_ctxt.max_tp_flow_depth);
                }
                if (aggressiveness >= 80)
                {
                    odp_ctxt.allow_port_wildcard_host_cache = true;
                    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: allow_port_wildcard_host_cache enabled\n");
                }
            }
            else if (!(strcasecmp(conf_key, "tp_allow_probes")))
            {
                if (!(strcasecmp(conf_val, "enabled")))
                {
                    odp_ctxt.tp_allow_probes = true;
                }
            }
            else if (!(strcasecmp(conf_key, "tp_client_app")))
            {
                set_app_info_flags(atoi(conf_val), APPINFO_FLAG_TP_CLIENT);
            }
            else if (!(strcasecmp(conf_key, "ssl_reinspect")))
            {
                set_app_info_flags(atoi(conf_val), APPINFO_FLAG_SSL_INSPECT);
            }
            else if (!(strcasecmp(conf_key, "defer_to_thirdparty")))
            {
                set_app_info_flags(atoi(conf_val), APPINFO_FLAG_DEFER);
            }
            else if (!(strcasecmp(conf_key, "defer_payload_to_thirdparty")))
            {
                set_app_info_flags(atoi(conf_val), APPINFO_FLAG_DEFER_PAYLOAD);
            }
            else if (!(strcasecmp(conf_key, "chp_userid")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    odp_ctxt.chp_userid_disabled = true;
                    continue;
                }
            }
            else if (!(strcasecmp(conf_key, "chp_body_collection")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    odp_ctxt.chp_body_collection_disabled = true;
                    continue;
                }
            }
            else if (!(strcasecmp(conf_key, "ftp_userid")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    odp_ctxt.ftp_userid_disabled = true;
                    continue;
                }
            }
            else if (!(strcasecmp(conf_key, "max_bytes_before_service_fail")))
            {
                uint64_t max_bytes_before_service_fail = atoi(conf_val);
                if (max_bytes_before_service_fail < MIN_MAX_BYTES_BEFORE_SERVICE_FAIL)
                {
                    appid_log(nullptr, TRACE_WARNING_LEVEL, "appid: invalid max_bytes_before_service_fail "
                        "%" PRIu64 " must be greater than %u.\n", max_bytes_before_service_fail,
                        MIN_MAX_BYTES_BEFORE_SERVICE_FAIL);
                }
                else
                {
                    odp_ctxt.max_bytes_before_service_fail = max_bytes_before_service_fail;
                }
            }
            else if (!(strcasecmp(conf_key, "max_packet_before_service_fail")))
            {
                uint16_t max_packet_before_service_fail = atoi(conf_val);
                if (max_packet_before_service_fail < MIN_MAX_PKTS_BEFORE_SERVICE_FAIL)
                {
                    appid_log(nullptr, TRACE_WARNING_LEVEL, "appid: invalid max_packet_before_service_fail "
                        "%" PRIu16 ", must be greater than %u.\n", max_packet_before_service_fail,
                        MIN_MAX_PKTS_BEFORE_SERVICE_FAIL);
                }
                else
                {
                    odp_ctxt.max_packet_before_service_fail = max_packet_before_service_fail;
                }
            }
            else if (!(strcasecmp(conf_key, "max_packet_service_fail_ignore_bytes")))
            {
                uint16_t max_packet_service_fail_ignore_bytes = atoi(conf_val);
                if (max_packet_service_fail_ignore_bytes <
                    MIN_MAX_PKT_BEFORE_SERVICE_FAIL_IGNORE_BYTES)
                {
                    appid_log(nullptr, TRACE_WARNING_LEVEL, "appid: invalid max_packet_service_fail_ignore_bytes"
                        "%" PRIu16 ", must be greater than %u.\n",
                        max_packet_service_fail_ignore_bytes,
                        MIN_MAX_PKT_BEFORE_SERVICE_FAIL_IGNORE_BYTES);
                }
                else
                {
                    odp_ctxt.max_packet_service_fail_ignore_bytes =
                        max_packet_service_fail_ignore_bytes;
                }
            }
            /* App Priority bit set*/
            else if (!(strcasecmp(conf_key, "app_priority")))
            {
                int temp_appid;
                temp_appid = strtol(conf_val, nullptr, 10);
                token = strtok_r(nullptr, CONF_SEPARATORS, &context);
                if (token == nullptr)
                {
                    ParseWarning(WARN_CONF, "appid: Could not read app_priority at line %u\n", line);
                    continue;
                }
                conf_val = token;
                uint8_t temp_val;
                temp_val = strtol(conf_val, nullptr, 10);
                set_app_info_priority (temp_appid, temp_val);
            }
            else if (!(strcasecmp(conf_key, "referred_appId")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    odp_ctxt.referred_appId_disabled = true;
                    continue;
                }
                else if (!odp_ctxt.referred_appId_disabled)
                {
                    char referred_app_list[4096];
                    int referred_app_index = safe_snprintf(referred_app_list, 4096, "%d ",
                        atoi(conf_val));
                    set_app_info_flags(atoi(conf_val), APPINFO_FLAG_REFERRED);

                    while ((token = strtok_r(nullptr, CONF_SEPARATORS, &context)) != nullptr)
                    {
                        AppId id = atoi(token);
                        referred_app_index += safe_snprintf(referred_app_list + referred_app_index,
                            sizeof(referred_app_list) - referred_app_index, "%d ", id);
                        set_app_info_flags(id, APPINFO_FLAG_REFERRED);
                    }
                }
            }
            else if (!(strcasecmp(conf_key, "rtmp_max_packets")))
            {
                odp_ctxt.rtmp_max_packets = atoi(conf_val);
            }
            else if (!(strcasecmp(conf_key, "mdns_user_report")))
            {
                odp_ctxt.mdns_user_reporting = atoi(conf_val) ? true : false;
            }
            else if (!(strcasecmp(conf_key, "dns_host_report")))
            {
                odp_ctxt.dns_host_reporting = atoi(conf_val) ? true : false;
            }
            else if (!(strcasecmp(conf_key, "chp_body_max_bytes")))
            {
                odp_ctxt.chp_body_collection_max = atoi(conf_val);
            }
            else if (!(strcasecmp(conf_key, "ignore_thirdparty_appid")))
            {
                set_app_info_flags(atoi(conf_val), APPINFO_FLAG_IGNORE);
            }
            else if (!(strcasecmp(conf_key, "eve_http_client")))
            {
                odp_ctxt.eve_http_client = atoi(conf_val) ? true : false;
            }
            else if (!(strcasecmp(conf_key, "appid_cpu_profiling")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    odp_ctxt.appid_cpu_profiler = false;
                }
                else if (!(strcasecmp(conf_val, "enabled")))
                {
                    odp_ctxt.appid_cpu_profiler = true;
                }
            }
            else
                ParseWarning(WARN_CONF, "appid: unsupported configuration: %s\n", conf_key);
        }
    }

    fclose(config_file);
}

void AppInfoManager::dump_appid_configurations(const std::string& file_path) const
{
    std::ifstream conf_file(file_path);
    if (!conf_file.is_open())
        return;

    appid_log(nullptr, TRACE_INFO_LEVEL, "AppId: Configuration file %s\n", file_path.c_str());
    std::string line;
    while (getline(conf_file, line))
        appid_log(nullptr, TRACE_INFO_LEVEL, "%s\n", line.c_str());

    conf_file.close();
}

SnortProtocolId AppInfoManager::add_appid_protocol_reference(const char* protocol,
    SnortConfig* sc)
{
    SnortProtocolId snort_protocol_id = sc->proto_ref->add(protocol);
    return snort_protocol_id;
}

void AppInfoManager::init_appid_info_table(const AppIdConfig& config,
    SnortConfig* sc, OdpContext& odp_ctxt)
{
    if (!config.app_detector_dir)
    {
        return;  // no lua detectors, no rule support, already warned
    }

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/odp/%s", config.app_detector_dir,
        APP_MAPPING_FILE);

    FILE* tableFile = fopen(filepath, "r");

    if (!tableFile)
    {
        ParseError("appid: could not open %s", filepath);
    }
    else
    {
        char buf[MAX_TABLE_LINE_LEN];
        const char* CONF_SEPARATORS = "\t\n\r";
        while (fgets(buf, sizeof(buf), tableFile))
        {
            AppId app_id;
            uint32_t client_id, service_id, payload_id;
            char* app_name;
            char* context;

            const char* token = strtok_r(buf, CONF_SEPARATORS, &context);
            if (!token)
            {
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Could not read id for AppId\n");
                continue;
            }
            app_id = strtol(token, nullptr, 10);

            token = strtok_r(nullptr, CONF_SEPARATORS, &context);
            if (!token)
            {
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Could not read app_name. Line %s\n", buf);
                continue;
            }
            app_name = snort_strdup(token);

            token = strtok_r(nullptr, CONF_SEPARATORS, &context);
            if (!token)
            {
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Could not read service id for AppId\n");
                snort_free(app_name);
                continue;
            }
            service_id = strtoul(token, nullptr, 10);

            token = strtok_r(nullptr, CONF_SEPARATORS, &context);
            if (!token)
            {
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Could not read client id for AppId\n");
                snort_free(app_name);
                continue;
            }
            client_id = strtoul(token, nullptr, 10);

            token = strtok_r(nullptr, CONF_SEPARATORS, &context);
            if (!token)
            {
                appid_log(nullptr, TRACE_ERROR_LEVEL, "Could not read payload id for AppId\n");
                snort_free(app_name);
                continue;
            }
            payload_id = strtoul(token, nullptr, 10);

            AppInfoTableEntry* entry = new AppInfoTableEntry(app_id, app_name, service_id,
                client_id, payload_id);

            /* snort service key, if it exists */
            token = strtok_r(nullptr, CONF_SEPARATORS, &context);

            // FIXIT-RC: Sometimes the token is "~". Should we ignore those?
            if (token)
                entry->snort_protocol_id = add_appid_protocol_reference(token, sc);

            if (!add_entry_to_app_info_name_table(entry->app_name_key, entry))
                delete entry;
            else
            {
                if ((app_id = get_static_app_info_entry(entry->appId)))
                {
                    app_info_table[app_id] = entry;
                    AppIdPegCounts::add_app_peg_info(entry->app_name_key, app_id);
                }
                if ((app_id = get_static_app_info_entry(entry->serviceId)))
                    app_info_service_table[app_id] = entry;
                if ((app_id = get_static_app_info_entry(entry->clientId)))
                    app_info_client_table[app_id] = entry;
                if ((app_id = get_static_app_info_entry(entry->payloadId)))
                    app_info_payload_table[app_id] = entry;
            }
        }
        fclose(tableFile);

        snprintf(filepath, sizeof(filepath), "%s/odp/%s", config.app_detector_dir,
            APP_CONFIG_FILE);
        load_odp_config(odp_ctxt, filepath);
        snprintf(filepath, sizeof(filepath), "%s/custom/%s", config.app_detector_dir,
            USR_CONFIG_FILE);
        if (access (filepath, F_OK))
            snprintf(filepath, sizeof(filepath), "%s/../%s", config.app_detector_dir,
                USR_CONFIG_FILE);
        load_odp_config(odp_ctxt, filepath);
    }
}
 
