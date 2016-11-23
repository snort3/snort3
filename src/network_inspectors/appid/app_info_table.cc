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

// app_info_table.cc author Sourcefire Inc.

#include "app_info_table.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "application_ids.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "utils/util.h"
#include "service_plugins/service_util.h"

#define MAX_TABLE_LINE_LEN      1024
#define CONF_SEPARATORS         "\t\n\r"
#define MIN_MAX_TP_FLOW_DEPTH   1
#define MAX_MAX_TP_FLOW_DEPTH   1000000

static AppInfoTable app_info_table;
static AppInfoTable app_info_service_table;
static AppInfoTable app_info_client_table;
static AppInfoTable app_info_payload_table;
static AppInfoNameTable app_info_name_table;
static AppId next_custom_appid = SF_APPID_DYNAMIC_MIN;
static AppInfoTable custom_app_info_table;

static inline char* strdupToLower(const char* source)
{
    char* dest = snort_strdup(source);
    char* lcd = dest;

    while(*lcd)
    {
        *lcd = tolower(*lcd);
        lcd++;
    }

    return dest;
}

static bool is_existing_entry(AppInfoTableEntry* entry)
{
    AppInfoNameTable::iterator app;

    app = app_info_name_table.find(entry->app_name_key);
    return app != app_info_name_table.end();
}

static AppInfoTableEntry* find_app_info_by_name(const char* app_name)
{
    AppInfoTableEntry* entry = nullptr;
    AppInfoNameTable::iterator app;
    const char* search_name = strdupToLower(app_name);

    app = app_info_name_table.find(search_name);
    if( app != app_info_name_table.end() )
        entry = app->second;

    snort_free((void*)search_name);
    return entry;
}

static void add_entry_to_app_info_hash(const char* app_name, AppInfoTableEntry* entry)
{
    if( !is_existing_entry(entry) )
        app_info_name_table[app_name] = entry;
    else
        WarningMessage("App name, \"%s\"is a duplicate existing entry will be shared by each detector.\n",
            app_name);
}

static AppId get_static_app_info_entry(AppId appid)
{
    if (appid > 0 && appid < SF_APPID_BUILDIN_MAX)
        return appid;
    if (appid >= SF_APPID_CSD_MIN && appid < SF_APPID_CSD_MIN + (SF_APPID_MAX - SF_APPID_BUILDIN_MAX))
        return (SF_APPID_BUILDIN_MAX + appid - SF_APPID_CSD_MIN);
    return 0;
}

AppInfoTableEntry* AppInfoManager::get_app_info_entry(AppId appId, const AppInfoTable& lookup_table)
{
    AppId tmp;
    AppInfoTable::const_iterator app;
    AppInfoTableEntry* entry = nullptr;

    std::lock_guard<std::mutex> lock(app_info_tables_rw_mutex);
    if ((tmp = get_static_app_info_entry(appId)))
    {
        app = lookup_table.find(tmp);
        if( app != lookup_table.end() )
            entry = app->second;
    }
    else
    {
        app = custom_app_info_table.find(appId);
        if( app != custom_app_info_table.end() )
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
        ErrorMessage("Appname invalid or too long: %s\n", app_name);
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(app_info_tables_rw_mutex);
    AppInfoTableEntry* entry = find_app_info_by_name(app_name);
    if (!entry)
    {
        entry = new AppInfoTableEntry(next_custom_appid++, snort_strdup(app_name));
        entry->app_name_key = strdupToLower(app_name);
        entry->serviceId = entry->appId;
        entry->clientId = entry->appId;
        entry->payloadId = entry->appId;
        custom_app_info_table[entry->appId] = entry;
        add_entry_to_app_info_hash(entry->app_name_key, entry);
    }

    return entry;
}

void AppInfoManager::cleanup_appid_info_table()
{
    for (auto& kv: app_info_table)
        delete(kv.second);

    app_info_table.erase(app_info_table.begin(), app_info_table.end());

    for (auto& kv: custom_app_info_table)
        delete(kv.second);

    custom_app_info_table.erase(custom_app_info_table.begin(), custom_app_info_table.end());
    app_info_name_table.erase(app_info_name_table.begin(), app_info_name_table.end());
}

void AppInfoManager::dump_app_info_table()
{
    LogMessage("Cisco provided detectors:\n");
    for (auto& kv: app_info_table)
        LogMessage("%s\t%d\t%s\n", kv.second->app_name, kv.second->appId,
                   (kv.second->flags & APPINFO_FLAG_ACTIVE) ? "active" : "inactive");

    LogMessage("User provided detectors:\n");
    for (auto& kv: custom_app_info_table)
        LogMessage("%s\t%d\t%s\n", kv.second->app_name, kv.second->appId,
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

int32_t AppInfoManager::get_appid_by_name(const char* app_name)
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
        WarningMessage("AppInfo: AppId %d has no entry in application info table\n", appId);
}

void AppInfoManager::load_appid_config(const char* path)
{
    char buf[1024];
    unsigned line = 0;

    FILE* config_file = fopen(path, "r");
    if (config_file == nullptr)
        return;

    DebugFormat(DEBUG_APPID, "Loading configuration file %s\n", path);

    while (fgets(buf, sizeof(buf), config_file) != nullptr)
    {
        char* context;

        line++;
        char* token = strtok_r(buf, CONF_SEPARATORS, &context);
        if (token == nullptr)
        {
            ParseWarning(WARN_CONF, "No 'conf_type' value at line %s:%u\n", path, line);
            continue;
        }
        char* conf_type = token;

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (token == nullptr)
        {
            ParseWarning(WARN_CONF, "No 'conf_key' value at line %s:%u\n", path, line);
            continue;
        }
        char* conf_key = token;

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (token == nullptr)
        {
            ParseWarning(WARN_CONF, "No 'conf_val' value at line %s:%u\n", path, line);
            continue;
        }
        char* conf_val = token;

        /* APPID configurations are for anything else - currently we only have ssl_reinspect */
        if (!(strcasecmp(conf_type, "appid")))
        {
            if (!(strcasecmp(conf_key, "max_tp_flow_depth")))
            {
                int max_tp_flow_depth = atoi(conf_val);
                if (max_tp_flow_depth < MIN_MAX_TP_FLOW_DEPTH || max_tp_flow_depth >
                    MAX_MAX_TP_FLOW_DEPTH)
                {
                    ParseWarning(WARN_CONF,
                        "AppId: invalid max_tp_flow_depth %d, must be between %d and %d\n.",
                        max_tp_flow_depth, MIN_MAX_TP_FLOW_DEPTH, MAX_MAX_TP_FLOW_DEPTH);
                }
                else
                {
                    DebugFormat(DEBUG_APPID,
                        "AppId: setting max thirdparty inspection flow depth to %d packets.\n",
                        max_tp_flow_depth);
                    AppIdConfig::get_appid_config()->mod_config->max_tp_flow_depth = max_tp_flow_depth;
                }
            }
            else if (!(strcasecmp(conf_key, "tp_allow_probes")))
            {
                if (!(strcasecmp(conf_val, "enabled")))
                {
                    DebugMessage(DEBUG_APPID,
                        "AppId: TCP probes will be analyzed by NAVL.\n");

                    AppIdConfig::get_appid_config()->mod_config->tp_allow_probes = 1;
                }
            }
            else if (!(strcasecmp(conf_key, "tp_client_app")))
            {
                DebugFormat(DEBUG_APPID,
                    "AppId: if thirdparty reports app %d, we will use it as a client.\n",
                    atoi(conf_val));
                set_app_info_flags(atoi(conf_val), APPINFO_FLAG_TP_CLIENT);
            }
            else if (!(strcasecmp(conf_key, "ssl_reinspect")))
            {
                DebugFormat(DEBUG_APPID,
                    "AppId: adding app %d to list of SSL apps that get more granular inspection.\n",
                    atoi(conf_val));
                set_app_info_flags(atoi(conf_val), APPINFO_FLAG_SSL_INSPECT);
            }
            else if (!(strcasecmp(conf_key, "disable_safe_search")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    DebugMessage(DEBUG_APPID, "AppId: disabling safe search enforcement.\n");
                    AppIdConfig::get_appid_config()->mod_config->disable_safe_search = 1;
                }
            }
            else if (!(strcasecmp(conf_key, "ssl_squelch")))
            {
                DebugFormat(DEBUG_APPID,
                    "AppId: adding app %d to list of SSL apps that may open a second SSL connection.\n",
                    atoi(conf_val));
                set_app_info_flags(atoi(conf_val), APPINFO_FLAG_SSL_SQUELCH);
            }
            else if (!(strcasecmp(conf_key, "defer_to_thirdparty")))
            {
                DebugFormat(DEBUG_APPID,
                    "AppId: adding app %d to list of apps where we should take thirdparty ID over the NDE's.\n",
                    atoi(conf_val));
                set_app_info_flags(atoi(conf_val), APPINFO_FLAG_DEFER);
            }
            else if (!(strcasecmp(conf_key, "defer_payload_to_thirdparty")))
            {
                DebugFormat(DEBUG_APPID,
                    "AppId: adding app %d to list of apps where we should take "
                    "thirdparty payload ID over the NDE's.\n",
                    atoi(conf_val));
                set_app_info_flags(atoi(conf_val), APPINFO_FLAG_DEFER_PAYLOAD);
            }
            else if (!(strcasecmp(conf_key, "chp_userid")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    DebugMessage(DEBUG_APPID,
                        "AppId: HTTP UserID collection disabled.\n");
                    AppIdConfig::get_appid_config()->mod_config->chp_userid_disabled = 1;
                    continue;
                }
            }
            else if (!(strcasecmp(conf_key, "chp_body_collection")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    DebugMessage(DEBUG_APPID,
                        "AppId: HTTP Body header reading disabled.\n");
                    AppIdConfig::get_appid_config()->mod_config->chp_body_collection_disabled = 1;
                    continue;
                }
            }
            else if (!(strcasecmp(conf_key, "ftp_userid")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    DebugMessage(DEBUG_APPID, "AppId: FTP userID disabled.\n");
                    AppIdConfig::get_appid_config()->mod_config->ftp_userid_disabled = 1;
                    continue;
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
                    ParseWarning(WARN_CONF, "Could not read app_priority at line %u\n", line);
                    continue;
                }
                conf_val = token;
                uint8_t temp_val;
                temp_val = strtol(conf_val, nullptr, 10);
                set_app_info_priority (temp_appid, temp_val);
                DebugFormat(DEBUG_APPID,"AppId: %d Setting priority bit %d .\n",
                    temp_appid, temp_val);
            }
            else if (!(strcasecmp(conf_key, "referred_appId")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    AppIdConfig::get_appid_config()->mod_config->referred_appId_disabled = 1;
                    continue;
                }
                else if (!AppIdConfig::get_appid_config()->mod_config->referred_appId_disabled)
                {
                    char referred_app_list[4096];
                    int referred_app_index = snprintf(referred_app_list, 4096, "%d ", atoi(conf_val));
                    set_app_info_flags(atoi(conf_val), APPINFO_FLAG_REFERRED);

                    while ((token = strtok_r(nullptr, CONF_SEPARATORS, &context)) != nullptr)
                    {
                        AppId id = atoi(token);
                        referred_app_index += snprintf(referred_app_list + referred_app_index,
                                                      4096 - referred_app_index, "%d ", id);
                        set_app_info_flags(id, APPINFO_FLAG_REFERRED);
                    }
                    DebugFormat(DEBUG_APPID,
                        "AppId: adding appIds to list of referred web apps: %s\n",
                        referred_app_list);
                }
            }
            else if (!(strcasecmp(conf_key, "rtmp_max_packets")))
            {
                AppIdConfig::get_appid_config()->mod_config->rtmp_max_packets = atoi(conf_val);
            }
            else if (!(strcasecmp(conf_key, "mdns_user_report")))
            {
                AppIdConfig::get_appid_config()->mod_config->mdns_user_reporting = atoi(conf_val);
            }
            else if (!(strcasecmp(conf_key, "dns_host_report")))
            {
                AppIdConfig::get_appid_config()->mod_config->dns_host_reporting = atoi(conf_val);
            }
            else if (!(strcasecmp(conf_key, "chp_body_max_bytes")))
            {
                AppIdConfig::get_appid_config()->mod_config->chp_body_collection_max = atoi(conf_val);
            }
            else if (!(strcasecmp(conf_key, "ignore_thirdparty_appid")))
            {
                DebugFormat(DEBUG_APPID, "AppId: adding app %d to list of ignore thirdparty apps.\n",
                             atoi(conf_val));
                set_app_info_flags(atoi(conf_val), APPINFO_FLAG_IGNORE);
            }
            else if (!(strcasecmp(conf_key, "http2_detection")))
            {
                // This option will control our own HTTP/2 detection.  We can
                // still be told externally, though, that it's HTTP/2 (either
                // from HTTP Inspect or 3rd Party).  This is intended to be
                // used to ask AppID to detect unencrypted HTTP/2 on non-std
                // ports.
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    DebugMessage(DEBUG_APPID, "AppId: disabling internal HTTP/2 detection.\n");
                    AppIdConfig::get_appid_config()->mod_config->http2_detection_enabled = false;
                }
                else if (!(strcasecmp(conf_val, "enabled")))
                {
                    DebugMessage(DEBUG_APPID, "AppId: enabling internal HTTP/2 detection.\n");
                    AppIdConfig::get_appid_config()->mod_config->http2_detection_enabled = true;
                }
                else
                {
                    ParseWarning(WARN_CONF, "AppId: ignoring invalid option for http2_detection: %s\n",
                        conf_val);
                }
            }
        }
    }

    fclose(config_file);
}

void AppInfoManager::init_appid_info_table(const char* path)
{
    FILE* tableFile;
    const char* token;
    char buf[MAX_TABLE_LINE_LEN];
    AppInfoTableEntry* entry;
    AppId appId;
    uint32_t clientId, serviceId, payloadId;
    char filepath[PATH_MAX];
    char* app_name;
    char* snortName = nullptr;
    char* context;

    snprintf(filepath, sizeof(filepath), "%s/odp/%s", path, APP_MAPPING_FILE);

    tableFile = fopen(filepath, "r");
    if (tableFile == nullptr)
    {
        ParseWarning(WARN_RULES,
                     "Could not open AppMapping Table file: %s, no AppId rule support", filepath);
        return;
    }

    DebugFormat(DEBUG_APPID, "AppInfo read from %s\n", filepath);

    while (fgets(buf, sizeof(buf), tableFile))
    {
        token = strtok_r(buf, CONF_SEPARATORS, &context);
        if (!token)
        {
            ErrorMessage("Could not read id for AppId\n");
            continue;
        }

        appId = strtol(token, nullptr, 10);

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (!token)
        {
            ErrorMessage("Could not read app_name. Line %s\n", buf);
            continue;
        }

        app_name = snort_strdup(token);
        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (!token)
        {
            ErrorMessage("Could not read service id for AppId\n");
            snort_free(app_name);
            continue;
        }

        serviceId = strtol(token, nullptr, 10);

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (!token)
        {
            ErrorMessage("Could not read client id for AppId\n");
            snort_free(app_name);
            continue;
        }

        clientId = strtol(token, nullptr, 10);

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (!token)
        {
            ErrorMessage("Could not read payload id for AppId\n");
            snort_free(app_name);
            continue;
        }

        payloadId = strtol(token, nullptr, 10);

        /* snort service key, if it exists */
        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (token)
            snortName = snort_strdup(token);

        entry = new AppInfoTableEntry(appId, app_name);
        entry->snortId = add_appid_protocol_reference(snortName);
        snort_free(snortName);
        snortName = nullptr;
        entry->app_name_key = strdupToLower(app_name);
        entry->serviceId = serviceId;
        entry->clientId = clientId;
        entry->payloadId = payloadId;

        if ((appId = get_static_app_info_entry(entry->appId)))
            app_info_table[appId] = entry;
        if ((appId = get_static_app_info_entry(entry->serviceId)))
            app_info_service_table[appId] = entry;
        if ((appId = get_static_app_info_entry(entry->clientId)))
            app_info_client_table[appId] = entry;
        if ((appId = get_static_app_info_entry(entry->payloadId)))
            app_info_payload_table[appId] = entry;

        add_entry_to_app_info_hash(entry->app_name_key, entry);
    }
    fclose(tableFile);

    /* Configuration defaults. */
    AppIdConfig::get_appid_config()->mod_config->rtmp_max_packets = 15;
    AppIdConfig::get_appid_config()->mod_config->mdns_user_reporting = 1;
    AppIdConfig::get_appid_config()->mod_config->dns_host_reporting = 1;
    AppIdConfig::get_appid_config()->mod_config->max_tp_flow_depth = 5;
    AppIdConfig::get_appid_config()->mod_config->http2_detection_enabled = false;

    snprintf(filepath, sizeof(filepath), "%s/odp/%s", path, APP_CONFIG_FILE);
    load_appid_config (filepath);
    snprintf(filepath, sizeof(filepath), "%s/custom/%s", path, USR_CONFIG_FILE);
    load_appid_config (filepath);
}

