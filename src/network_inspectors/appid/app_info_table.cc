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
#include "hash/sfghash.h"
#include "main/snort_debug.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#define APP_MAPPING_FILE "appMapping.data"
#define APP_CONFIG_FILE "appid.conf"
#define USR_CONFIG_FILE "userappid.conf"

#define MAX_TABLE_LINE_LEN      1024
#define CONF_SEPARATORS         "\t\n\r"
#define MIN_MAX_TP_FLOW_DEPTH   1
#define MAX_MAX_TP_FLOW_DEPTH   1000000

struct DynamicArray
{
    AppInfoTableEntry** table;
    size_t indexStart;
    size_t indexCurrent;
    size_t usedCount;
    size_t allocatedCount;
    size_t stepSize;
};

static inline DynamicArray* dynamicArrayCreate(unsigned indexStart)
{
    DynamicArray* array;

    array = (DynamicArray*)snort_calloc(sizeof(DynamicArray));
    array->stepSize = 1;
    array->indexStart = indexStart;
    return array;
}

static inline void dynamicArrayDestroy(DynamicArray* array)
{
    unsigned i;
    AppInfoTableEntry* entry;

    if (!array)
        return;
    for (i = 0; i < array->usedCount; i++)
    {
        entry = array->table[i];
        snort_free(entry->appName);
        snort_free(entry);
    }

    // FIXIT - array table is still alloc'ed with calloc/realloc
    free(array->table);
    snort_free(array);
}

static inline void dynamicArraySetIndex(DynamicArray* array, unsigned index,
    AppInfoTableEntry* data)
{
    if (index >= array->indexStart && index < (array->indexStart + array->usedCount))
        array->table[index - array->indexStart] = data;
}

static inline AppInfoTableEntry* dynamicArrayGetIndex(DynamicArray* array, unsigned index)
{
    if (index >= array->indexStart && index < (array->indexStart + array->usedCount))
        return array->table[index - array->indexStart];
    return nullptr;
}

static inline bool dynamicArrayCreateIndex(DynamicArray* array, unsigned* index)
{
    if (array->usedCount == array->allocatedCount)
    {
        AppInfoTableEntry** tmp =
            (AppInfoTableEntry**)realloc(array->table,
            (array->allocatedCount + array->stepSize) * sizeof(*tmp));
        if (!tmp)
        {
            return false;
        }
        array->table = tmp;
        array->allocatedCount += array->stepSize;
    }
    *index = array->indexStart + (array->usedCount++);
    return true;
}

static inline void* dynamicArrayGetFirst(DynamicArray* array)
{
    AppInfoTableEntry* entry;
    for (array->indexCurrent = 0; array->indexCurrent < array->usedCount; array->indexCurrent++)
    {
        if ((entry = array->table[array->indexCurrent]))
            return entry;
    }
    return nullptr;
}

static inline void* dynamicArrayGetNext(DynamicArray* array)
{
    AppInfoTableEntry* entry;
    for (array->indexCurrent++; array->indexCurrent < array->usedCount; array->indexCurrent++)
    {
        if ((entry = array->table[array->indexCurrent]))
            return entry;
    }
    return nullptr;
}

// End of Dynamic array
SFGHASH* appNameHashInit()
{
    SFGHASH* appNameHash;
    appNameHash = sfghash_new(65, 0, 0 /* alloc copies of lowercased keys */, nullptr);
    if (!appNameHash)
    {
        FatalError("AppNameHash: Failed to Initialize\n");
    }
    return appNameHash;
}

void appNameHashFini(SFGHASH* appNameHash)
{
    if (appNameHash)
    {
        sfghash_delete(appNameHash);
    }
}

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

void appNameHashAdd(SFGHASH* appNameHash, const char* appName, void* data)
{
    char* searchName;
    int errCode;

    if (!appName || !appNameHash)
        return;

    searchName = strdupToLower(appName);
    if (!searchName)
        return;

    if (SFGHASH_OK == (errCode = sfghash_add(appNameHash, searchName, data)))
    {
        DebugFormat(DEBUG_INSPECTOR, "App name added for %s\n", appName);
    }
    else if (SFGHASH_INTABLE == errCode)
    {
        /* Note that, although this entry is not placed in the hash table,
           being a duplicate, it remains in the list of allocated entries
           for cleanup by appInfoTableFini() */

        // Rediscover the existing, hashed entry for the purpose of a complete error message.
        AppInfoTableEntry* tableEntry = (AppInfoTableEntry*)sfghash_find(appNameHash, searchName);

        if (tableEntry)
        {
            ErrorMessage("App name, \"%s\", is a duplicate of \"%s\" and has been ignored.\n",
                appName, tableEntry->appName);
        }
        else
        {
            ErrorMessage("App name, \"%s\", has been ignored. Hash key \"%s\" is not unique.\n",
                appName, searchName);
        }
    }
    snort_free(searchName);
}

void* appNameHashFind(SFGHASH* appNameHash, const char* appName)
{
    void* data;
    char* searchName;

    if (!appName || !appNameHash)
        return nullptr;

    searchName = strdupToLower(appName);
    if (!searchName)
        return nullptr;

    data = sfghash_find(appNameHash, searchName);

    snort_free(searchName);

    return data;
}

// End of appName hash

static void appIdConfLoad(const char* path);

static unsigned int getAppIdStaticIndex(AppId appid)
{
    if (appid > 0 && appid < SF_APPID_BUILDIN_MAX)
        return appid;
    if (appid >= SF_APPID_CSD_MIN && appid < SF_APPID_CSD_MIN+(SF_APPID_MAX-SF_APPID_BUILDIN_MAX))
        return (SF_APPID_BUILDIN_MAX + appid - SF_APPID_CSD_MIN);
    return 0;
}

AppInfoTableEntry* appInfoEntryGet(AppId appId, const AppIdConfig* pConfig)
{
    AppId tmp;
    if ((tmp = getAppIdStaticIndex(appId)))
        return pConfig->AppInfoTable[tmp];
    return dynamicArrayGetIndex(pConfig->AppInfoTableDyn, appId);
}

AppInfoTableEntry* appInfoEntryCreate(const char* appName, AppIdConfig* pConfig)
{
    AppId appId;
    AppInfoTableEntry* entry;

    if (!appName || strlen(appName) >= MAX_EVENT_APPNAME_LEN)
    {
        ErrorMessage("Appname invalid or too long: %s\n", appName);
        return nullptr;
    }

    entry = static_cast<decltype(entry)>(appNameHashFind(pConfig->AppNameHash, appName));

    if (!entry)
    {
        if (!dynamicArrayCreateIndex(pConfig->AppInfoTableDyn, (uint32_t*)&appId))
            return nullptr;

        entry = static_cast<decltype(entry)>(snort_calloc(sizeof(AppInfoTableEntry)));
        entry->appId = appId;
        entry->serviceId = entry->appId;
        entry->clientId = entry->appId;
        entry->payloadId = entry->appId;
        entry->appName = snort_strdup(appName);
        dynamicArraySetIndex(pConfig->AppInfoTableDyn, appId, entry);
    }
    return entry;
}

void appInfoTableInit(const char* path, AppIdConfig* pConfig)
{
    FILE* tableFile;
    const char* token;
    char buf[MAX_TABLE_LINE_LEN];
    AppInfoTableEntry* entry;
    AppId appId;
    uint32_t clientId, serviceId, payloadId;
    char filepath[PATH_MAX];
    char* appName;
    char* snortName=nullptr;
    char* context;

    pConfig->AppInfoTableDyn = dynamicArrayCreate(SF_APPID_DYNAMIC_MIN);

    snprintf(filepath, sizeof(filepath), "%s/odp/%s", path, APP_MAPPING_FILE);

    tableFile = fopen(filepath, "r");
    if (tableFile == nullptr)
    {
        ErrorMessage("Could not open RnaAppMapping Table file: %s\n", filepath);
        return;
    }

    DebugFormat(DEBUG_INSPECTOR, "AppInfo read from %s\n", filepath);

    while (fgets(buf, sizeof(buf), tableFile))
    {
        token = strtok_r(buf, CONF_SEPARATORS, &context);
        if (!token)
        {
            ErrorMessage("Could not read id for Rna Id\n");
            continue;
        }

        appId = strtol(token, nullptr, 10);

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (!token)
        {
            ErrorMessage("Could not read appName. Line %s\n", buf);
            continue;
        }

        appName = snort_strdup(token);
        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (!token)
        {
            ErrorMessage("Could not read service id for Rna Id\n");
            snort_free(appName);
            continue;
        }

        serviceId = strtol(token, nullptr, 10);

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (!token)
        {
            ErrorMessage("Could not read client id for Rna Id\n");
            snort_free(appName);
            continue;
        }

        clientId = strtol(token, nullptr, 10);

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (!token)
        {
            ErrorMessage("Could not read payload id for Rna Id\n");
            snort_free(appName);
            continue;
        }

        payloadId = strtol(token, nullptr, 10);

        /* snort service key, if it exists */
        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (token)
            snortName = snort_strdup(token);

        entry = static_cast<decltype(entry)>(snort_calloc(sizeof(AppInfoTableEntry)));
        entry->next = pConfig->AppInfoList;
        pConfig->AppInfoList = entry;
        entry->snortId = AddProtocolReference(snortName);
        snort_free(snortName);
        snortName = nullptr;
        entry->appName = appName;
        entry->appId = appId;
        entry->serviceId = serviceId;
        entry->clientId = clientId;
        entry->payloadId = payloadId;
        entry->priority = APP_PRIORITY_DEFAULT;

        if ((appId = getAppIdStaticIndex(entry->appId)))
            pConfig->AppInfoTable[appId] = entry;
        if ((appId = getAppIdStaticIndex(entry->serviceId)))
            pConfig->AppInfoTableByService[appId] = entry;
        if ((appId = getAppIdStaticIndex(entry->clientId)))
            pConfig->AppInfoTableByClient[appId] = entry;
        if ((appId = getAppIdStaticIndex(entry->payloadId)))
            pConfig->AppInfoTableByPayload[appId] = entry;

        if (!pConfig->AppNameHash)
        {
            pConfig->AppNameHash = appNameHashInit();
        }
        appNameHashAdd(pConfig->AppNameHash, appName, entry);
    }
    fclose(tableFile);

    /* Configuration defaults. */
    pAppidActiveConfig->mod_config->rtmp_max_packets = 15;
    pAppidActiveConfig->mod_config->mdns_user_reporting = 1;
    pAppidActiveConfig->mod_config->dns_host_reporting = 1;
    pAppidActiveConfig->mod_config->max_tp_flow_depth = 5;
    pAppidActiveConfig->mod_config->http2_detection_enabled = 0;

    snprintf(filepath, sizeof(filepath), "%s/odp/%s", path, APP_CONFIG_FILE);
    appIdConfLoad (filepath);
    snprintf(filepath, sizeof(filepath), "%s/custom/%s", path, USR_CONFIG_FILE);
    appIdConfLoad (filepath);
}

void appInfoTableFini(AppIdConfig* pConfig)
{
    AppInfoTableEntry* entry;

    while ((entry = pConfig->AppInfoList))
    {
        pConfig->AppInfoList = entry->next;
        snort_free(entry->appName);
        snort_free(entry);
    }

    dynamicArrayDestroy(pConfig->AppInfoTableDyn);
    pConfig->AppInfoTableDyn = nullptr;

    appNameHashFini(pConfig->AppNameHash);
}

void appInfoTableDump(AppIdConfig* pConfig)
{
    AppInfoTableEntry* entry;
    AppId appId;

    ErrorMessage("Cisco provided detectors:\n");
    for (appId = 1; appId < SF_APPID_MAX; appId++)
    {
        entry = pConfig->AppInfoTable[appId];
        if (entry)
            ErrorMessage("%s\t%d\t%s\n", entry->appName, entry->appId, (entry->flags &
                APPINFO_FLAG_ACTIVE) ? "active" : "inactive");
    }
    ErrorMessage("User provided detectors:\n");
    for (entry = (decltype(entry))dynamicArrayGetFirst(pConfig->AppInfoTableDyn); entry; entry =
        (decltype(entry))dynamicArrayGetNext(pConfig->AppInfoTableDyn))
    {
        ErrorMessage("%s\t%d\t%s\n", entry->appName, entry->appId, (entry->flags &
            APPINFO_FLAG_ACTIVE) ? "active" : "inactive");
    }
}

AppId appGetAppFromServiceId(uint32_t appId, AppIdConfig* pConfig)
{
    AppInfoTableEntry* entry;
    AppId tmp;

    if ((tmp = getAppIdStaticIndex(appId)))
        entry = pConfig->AppInfoTableByService[tmp];
    else
        entry = dynamicArrayGetIndex(pConfig->AppInfoTableDyn, appId);

    return entry ? entry->appId : APP_ID_NONE;
}

AppId appGetAppFromClientId(uint32_t appId, AppIdConfig* pConfig)
{
    AppInfoTableEntry* entry;
    AppId tmp;

    if ((tmp = getAppIdStaticIndex(appId)))
        entry = pConfig->AppInfoTableByClient[tmp];
    else
        entry = dynamicArrayGetIndex(pConfig->AppInfoTableDyn, appId);

    return entry ? entry->appId : APP_ID_NONE;
}

AppId appGetAppFromPayloadId(uint32_t appId, AppIdConfig* pConfig)
{
    AppInfoTableEntry* entry;
    AppId tmp;

    if ((tmp = getAppIdStaticIndex(appId)))
        entry = pConfig->AppInfoTableByPayload[tmp];
    else
        entry = dynamicArrayGetIndex(pConfig->AppInfoTableDyn, appId);

    return entry ? entry->appId : APP_ID_NONE;
}

const char* appGetAppName(int32_t appId)
{
    AppInfoTableEntry* entry;
    AppIdConfig* pConfig = pAppidActiveConfig;
    AppId tmp;

    if ((tmp = getAppIdStaticIndex(appId)))
        entry = pConfig->AppInfoTable[tmp];
    else
        entry = dynamicArrayGetIndex(pConfig->AppInfoTableDyn, appId);

    return entry ? entry->appName : nullptr;
}

int32_t appGetAppId(const char* appName)
{
    AppInfoTableEntry* entry;
    AppIdConfig* pConfig = pAppidActiveConfig;

    entry = (decltype(entry))appNameHashFind(pConfig->AppNameHash, appName);
    return entry ? entry->appId : 0;
}

void appInfoSetActive(AppId appId, bool active)
{
    AppInfoTableEntry* entry = nullptr;
    AppIdConfig* pConfig = pAppidActiveConfig;
    AppId tmp;

    if (appId == APP_ID_NONE)
        return;

    if ((tmp = getAppIdStaticIndex(appId)))
        entry =  pConfig->AppInfoTable[tmp];
    else
        entry = dynamicArrayGetIndex(pConfig->AppInfoTableDyn, appId);

    if (entry)
    {
        if (active)
            entry->flags |= APPINFO_FLAG_ACTIVE;
        else
            entry->flags &= ~APPINFO_FLAG_ACTIVE;
    }
    else
    {
        ErrorMessage("AppInfo: AppId %d is UNKNOWN\n", appId);
    }
}

static void appIdConfLoad(const char* path)
{
    FILE* config_file;
    char* token;
    char buf[1024];
    char referred_app_list[4096];
    int referred_app_index;
    char* conf_type;
    char* conf_key;
    char* conf_val;
    unsigned line = 0;
    AppIdConfig* pConfig = pAppidActiveConfig;
    int max_tp_flow_depth;
    char* context;

    config_file = fopen(path, "r");
    if (config_file == nullptr)
        return;

    DebugFormat(DEBUG_INSPECTOR, "Loading configuration file %s\n", path);

    while (fgets(buf, sizeof(buf), config_file) != nullptr)
    {
        line++;
        token = strtok_r(buf, CONF_SEPARATORS, &context);
        if (token == nullptr)
        {
            ErrorMessage("Could not read configuration at line %s:%u\n", path, line);
            continue;
        }
        conf_type = token;

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (token == nullptr)
        {
            ErrorMessage("Could not read configuration value at line %s:%u\n", path, line);
            continue;
        }
        conf_key = token;

        token = strtok_r(nullptr, CONF_SEPARATORS, &context);
        if (token == nullptr)
        {
            ErrorMessage("Could not read configuration value at line %s:%u\n", path, line);
            continue;
        }
        conf_val = token;

        /* APPID configurations are for anything else - currently we only have ssl_reinspect */
        if (!(strcasecmp(conf_type, "appid")))
        {
            if (!(strcasecmp(conf_key, "max_tp_flow_depth")))
            {
                max_tp_flow_depth = atoi(conf_val);
                if (max_tp_flow_depth < MIN_MAX_TP_FLOW_DEPTH || max_tp_flow_depth >
                    MAX_MAX_TP_FLOW_DEPTH)
                {
                    DebugFormat(DEBUG_INSPECTOR,
                        "AppId: invalid max_tp_flow_depth %d, must be between %d and %d\n.",
                        max_tp_flow_depth, MIN_MAX_TP_FLOW_DEPTH, MAX_MAX_TP_FLOW_DEPTH);
                }
                else
                {
                    DebugFormat(DEBUG_INSPECTOR,
                        "AppId: setting max thirdparty inspection flow depth to %d packets.\n",
                        max_tp_flow_depth);
                    pAppidActiveConfig->mod_config->max_tp_flow_depth = max_tp_flow_depth;
                }
            }
            else if (!(strcasecmp(conf_key, "tp_allow_probes")))
            {
                if (!(strcasecmp(conf_val, "enabled")))
                {
                    DebugMessage(DEBUG_INSPECTOR,
                        "AppId: TCP probes will be analyzed by NAVL.\n");

                    pAppidActiveConfig->mod_config->tp_allow_probes = 1;
                }
            }
            else if (!(strcasecmp(conf_key, "tp_client_app")))
            {
                DebugFormat(DEBUG_INSPECTOR,
                    "AppId: if thirdparty reports app %d, we will use it as a client.\n",
                    atoi(conf_val));
                appInfoEntryFlagSet(atoi(conf_val), APPINFO_FLAG_TP_CLIENT, pConfig);
            }
            else if (!(strcasecmp(conf_key, "ssl_reinspect")))
            {
                DebugFormat(DEBUG_INSPECTOR,
                    "AppId: adding app %d to list of SSL apps that get more granular inspection.\n",
                    atoi(conf_val));
                appInfoEntryFlagSet(atoi(conf_val), APPINFO_FLAG_SSL_INSPECT, pConfig);
            }
            else if (!(strcasecmp(conf_key, "disable_safe_search")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_INSPECTOR,
                        "AppId: disabling safe search enforcement.\n"); );
                    pAppidActiveConfig->mod_config->disable_safe_search = 1;
                }
            }
            else if (!(strcasecmp(conf_key, "ssl_squelch")))
            {
                DebugFormat(DEBUG_INSPECTOR,
                    "AppId: adding app %d to list of SSL apps that may open a second SSL connection.\n",
                    atoi(conf_val));
                appInfoEntryFlagSet(atoi(conf_val), APPINFO_FLAG_SSL_SQUELCH, pConfig);
            }
            else if (!(strcasecmp(conf_key, "defer_to_thirdparty")))
            {
                DebugFormat(DEBUG_INSPECTOR,
                    "AppId: adding app %d to list of apps where we should take thirdparty ID over the NDE's.\n",
                    atoi(conf_val));
                appInfoEntryFlagSet(atoi(conf_val), APPINFO_FLAG_DEFER, pConfig);
            }
            else if (!(strcasecmp(conf_key, "defer_payload_to_thirdparty")))
            {
                DebugFormat(DEBUG_INSPECTOR,
                    "AppId: adding app %d to list of apps where we should take "
                    "thirdparty payload ID over the NDE's.\n",
                    atoi(conf_val));
                appInfoEntryFlagSet(atoi(conf_val), APPINFO_FLAG_DEFER_PAYLOAD, pConfig);
            }
            else if (!(strcasecmp(conf_key, "chp_userid")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    DebugMessage(DEBUG_INSPECTOR,
                        "AppId: HTTP UserID collection disabled.\n");
                    pAppidActiveConfig->mod_config->chp_userid_disabled = 1;
                    continue;
                }
            }
            else if (!(strcasecmp(conf_key, "chp_body_collection")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    DebugMessage(DEBUG_INSPECTOR,
                        "AppId: HTTP Body header reading disabled.\n");
                    pAppidActiveConfig->mod_config->chp_body_collection_disabled = 1;
                    continue;
                }
            }
            else if (!(strcasecmp(conf_key, "chp_fflow")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_INSPECTOR,
                        "AppId: HTTP future flow creation disabled.\n"); );
                    pAppidActiveConfig->mod_config->chp_fflow_disabled = 1;
                    continue;
                }
            }
            else if (!(strcasecmp(conf_key, "ftp_userid")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_INSPECTOR, "AppId: FTP userID disabled.\n"); );
                    pAppidActiveConfig->mod_config->ftp_userid_disabled = 1;
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
                    ErrorMessage("Could not read app_priority at line %u\n", line);
                    continue;
                }
                conf_val = token;
                uint8_t temp_val;
                temp_val = strtol(conf_val, nullptr, 10);
                appInfoEntryPrioritySet (temp_appid, temp_val, pConfig);
                DebugFormat(DEBUG_INSPECTOR,"AppId: %d Setting priority bit %d .\n",
                    temp_appid, temp_val);
            }
            else if (!(strcasecmp(conf_key, "referred_appId")))
            {
                if (!(strcasecmp(conf_val, "disabled")))
                {
                    pAppidActiveConfig->mod_config->referred_appId_disabled = 1;
                    continue;
                }
                else if (!pAppidActiveConfig->mod_config->referred_appId_disabled)
                {
                    referred_app_index=0;
                    referred_app_index += sprintf(referred_app_list, "%d ", atoi(conf_val));
                    appInfoEntryFlagSet(atoi(conf_val), APPINFO_FLAG_REFERRED, pConfig);

                    while ((token = strtok_r(nullptr, CONF_SEPARATORS, &context)) != nullptr)
                    {
                        referred_app_index += sprintf(referred_app_list+referred_app_index, "%d ",
                            atoi(token));
                        appInfoEntryFlagSet(atoi(token), APPINFO_FLAG_REFERRED, pConfig);
                    }
                    DebugFormat(DEBUG_INSPECTOR,
                        "AppId: adding appIds to list of referred web apps: %s\n",
                        referred_app_list);
                }
            }
            else if (!(strcasecmp(conf_key, "rtmp_max_packets")))
            {
                pAppidActiveConfig->mod_config->rtmp_max_packets = atoi(conf_val);
            }
            else if (!(strcasecmp(conf_key, "mdns_user_report")))
            {
                pAppidActiveConfig->mod_config->mdns_user_reporting = atoi(conf_val);
            }
            else if (!(strcasecmp(conf_key, "dns_host_report")))
            {
                pAppidActiveConfig->mod_config->dns_host_reporting = atoi(conf_val);
            }
            else if (!(strcasecmp(conf_key, "chp_body_max_bytes")))
            {
                pAppidActiveConfig->mod_config->chp_body_collection_max = atoi(conf_val);
            }
            else if (!(strcasecmp(conf_key, "ignore_thirdparty_appid")))
            {
                LogMessage("AppId: adding app %d to list of ignore thirdparty apps.\n", atoi(
                    conf_val));
                appInfoEntryFlagSet(atoi(conf_val), APPINFO_FLAG_IGNORE, pConfig);
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
                    LogMessage("AppId: disabling internal HTTP/2 detection.\n");
                    pAppidActiveConfig->mod_config->http2_detection_enabled = 0;
                }
                else if (!(strcasecmp(conf_val, "enabled")))
                {
                    LogMessage("AppId: enabling internal HTTP/2 detection.\n");
                    pAppidActiveConfig->mod_config->http2_detection_enabled = 1;
                }
                else
                {
                    LogMessage("AppId: ignoring invalid option for http2_detection: %s\n",
                        conf_val);
                }
            }
        }
    }
    fclose(config_file);
}

