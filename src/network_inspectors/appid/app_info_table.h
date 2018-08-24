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

// app_info_table.h author Sourcefire Inc.

#ifndef APP_INFO_TABLE_H
#define APP_INFO_TABLE_H

#include <unordered_map>
#include <vector>

#include "application_ids.h"

#include "flow/flow.h"
#include "framework/counts.h"
#include "main/thread.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#define APP_PRIORITY_DEFAULT 2
#define SF_APPID_MAX            40000
#define SF_APPID_BUILDIN_MAX    30000
#define SF_APPID_CSD_MIN        1000000
#define SF_APPID_DYNAMIC_MIN    2000000

class AppIdModuleConfig;
class ClientDetector;
class ServiceDetector;

enum AppInfoFlags
{
    APPINFO_FLAG_SERVICE_ADDITIONAL   = (1<<0),
    APPINFO_FLAG_SERVICE_UDP_REVERSED = (1<<1),
    APPINFO_FLAG_CLIENT_ADDITIONAL    = (1<<2),
    APPINFO_FLAG_CLIENT_USER          = (1<<3),
    APPINFO_FLAG_ACTIVE               = (1<<4),
    APPINFO_FLAG_SSL_INSPECT          = (1<<5),
    APPINFO_FLAG_REFERRED             = (1<<6),
    APPINFO_FLAG_DEFER                = (1<<7),

    APPINFO_FLAG_IGNORE               = (1<<8),
    APPINFO_FLAG_SSL_SQUELCH          = (1<<9),
    APPINFO_FLAG_PERSISTENT           = (1<<10),
    APPINFO_FLAG_TP_CLIENT            = (1<<11),
    APPINFO_FLAG_DEFER_PAYLOAD        = (1<<12),
    APPINFO_FLAG_SEARCH_ENGINE        = (1<<13),
    APPINFO_FLAG_SUPPORTED_SEARCH     = (1<<14)
};

class AppInfoTableEntry
{
public:
    AppInfoTableEntry(AppId id, char* name);
    AppInfoTableEntry(AppId id, char* name, AppId sid, AppId cid, AppId pid);
    ~AppInfoTableEntry();

    AppId appId;
    uint32_t serviceId;
    uint32_t clientId;
    uint32_t payloadId;
    SnortProtocolId snort_protocol_id = UNKNOWN_PROTOCOL_ID;
    uint32_t flags = 0;
    uint32_t priority = APP_PRIORITY_DEFAULT;
    ClientDetector* client_detector = nullptr;
    ServiceDetector* service_detector = nullptr;
    char* app_name = nullptr;
    char* app_name_key = nullptr;
};

typedef std::unordered_map<AppId, AppInfoTableEntry*> AppInfoTable;
typedef std::unordered_map<std::string, AppInfoTableEntry*> AppInfoNameTable;

class AppInfoManager
{
public:
    static inline AppInfoManager& get_instance()
    {
        static AppInfoManager instance;
        return instance;
    }

    AppInfoTableEntry* get_app_info_entry(AppId);
    AppInfoTableEntry* add_dynamic_app_entry(const char* app_name);
    AppId get_appid_by_service_id(uint32_t);
    AppId get_appid_by_client_id(uint32_t);
    AppId get_appid_by_payload_id(uint32_t);
    void set_app_info_active(AppId);
    const char* get_app_name(AppId);
    const char* get_app_name_key(AppId);
    static char * strdup_to_lower(const char *app_name);
    int32_t get_appid_by_name(const char* app_name);
    bool configured();

    void set_app_info_flags(AppId appId, unsigned flags)
    {
        AppInfoTableEntry* entry = get_app_info_entry(appId);
        if ( entry )
            entry->flags |= flags;
    }

    void clear_app_info_flags(AppId appId, unsigned flags)
    {
        AppInfoTableEntry* entry = get_app_info_entry(appId);
        if ( entry )
            entry->flags &= (~flags);
    }

    unsigned get_app_info_flags(AppId app_id, unsigned flags)
    {
        AppInfoTableEntry* entry = get_app_info_entry(app_id);
        return entry ? entry->flags & flags : 0;
    }

    void set_app_info_priority(AppId appId, unsigned priority)
    {
        AppInfoTableEntry* entry = get_app_info_entry(appId);
        if ( entry )
            entry->priority |= priority;
    }

    unsigned get_priority(AppId app_id)
    {
        AppInfoTableEntry* entry = get_app_info_entry(app_id);
        return entry ? entry->priority : 0;
    }

    void init_appid_info_table(AppIdModuleConfig*, snort::SnortConfig*);
    void cleanup_appid_info_table();
    void dump_app_info_table();
    SnortProtocolId add_appid_protocol_reference(const char* protocol, snort::SnortConfig*);

private:
    inline AppInfoManager() = default;
    void load_appid_config(AppIdModuleConfig*, const char* path);
    AppInfoTableEntry* get_app_info_entry(AppId appId, const AppInfoTable&);
};

#endif

