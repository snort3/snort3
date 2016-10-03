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

// app_info_table.h author Sourcefire Inc.

#ifndef APP_INFO_TABLE_H
#define APP_INFO_TABLE_H

#include <cstdint>

#include "appid_api.h"
#include "appid_config.h"

#define APP_PRIORITY_DEFAULT 2

struct RNAClientAppModule;
struct RNAServiceElement;

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

struct AppInfoTableEntry
{
    AppInfoTableEntry* next;
    AppId appId;
    uint32_t serviceId;
    uint32_t clientId;
    uint32_t payloadId;
    int16_t snortId;
    uint32_t flags;
    const RNAClientAppModule* clntValidator;
    const RNAServiceElement* svrValidator;
    uint32_t priority;
    char* appName;
};

void appNameHashFini();

void init_appid_info_table(const char* path);
void cleanup_appid_info_table();
void init_dynamic_app_info_table();
void free_dynamic_app_info_table();

AppInfoTableEntry* appInfoEntryGet(AppId);
AppInfoTableEntry* appInfoEntryCreate(const char* appName);
AppId appGetSnortIdFromAppId(AppId);
AppId get_appid_by_service_id(uint32_t appId);
AppId get_appid_by_client_id(uint32_t appId);
AppId get_appid_by_payload_id(uint32_t appId);
void AppIdDumpStats(int exit_flag);
void dump_app_info_table();
void set_app_info_active(AppId);
const char* get_app_name(int32_t appId);
int32_t get_appid_by_name(const char* appName);

inline void appInfoEntryFlagSet(AppId appId, unsigned flags)
{
    AppInfoTableEntry* entry = appInfoEntryGet(appId);
    if ( entry )
        entry->flags |= flags;
}

inline void appInfoEntryFlagClear(AppId appId, unsigned flags)
{
    AppInfoTableEntry* entry = appInfoEntryGet(appId);
    if ( entry )
        entry->flags &= (~flags);
}

inline unsigned appInfoEntryFlagGet(AppId app_id, unsigned flags)
{
    AppInfoTableEntry* entry = appInfoEntryGet(app_id);
    return entry ? entry->flags & flags : 0;
}

inline void appInfoEntryPrioritySet(AppId appId, unsigned priority)
{
    AppInfoTableEntry* entry = appInfoEntryGet(appId);
    if ( entry )
        entry->priority |= priority;
}

inline unsigned appInfoEntryPriorityGet(AppId app_id)
{
    AppInfoTableEntry* entry = appInfoEntryGet(app_id);
    return entry ? entry->priority : 0;
}

#endif

