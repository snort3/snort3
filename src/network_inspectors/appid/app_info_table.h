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

void appInfoTableInit(const char* path, AppIdConfig*);
void appInfoTableFini(AppIdConfig*);

AppInfoTableEntry* appInfoEntryGet(AppId, const AppIdConfig*);
AppInfoTableEntry* appInfoEntryCreate(const char* appName, AppIdConfig*);
AppId appGetSnortIdFromAppId(AppId);
void AppIdDumpStats(int exit_flag);
void appInfoTableDump(AppIdConfig*);
void appInfoSetActive(AppId, bool active);
const char* appGetAppName(int32_t appId);
int32_t appGetAppId(const char* appName);

inline void appInfoEntryFlagSet(AppId appId, unsigned flags, AppIdConfig* pConfig)
{
    AppInfoTableEntry* entry = appInfoEntryGet(appId, pConfig);
    if ( entry )
        entry->flags |= flags;
}

inline void appInfoEntryFlagClear(AppId appId, unsigned flags, AppIdConfig* pConfig)
{
    AppInfoTableEntry* entry = appInfoEntryGet(appId, pConfig);
    if ( entry )
        entry->flags &= (~flags);
}

inline unsigned appInfoEntryFlagGet(AppId app_id, unsigned flags, AppIdConfig* pConfig)
{
    AppInfoTableEntry* entry = appInfoEntryGet(app_id, pConfig);
    return entry ? entry->flags & flags : 0;
}

inline void appInfoEntryPrioritySet(AppId appId, unsigned priority, AppIdConfig* pConfig)
{
    AppInfoTableEntry* entry = appInfoEntryGet(appId, pConfig);
    if ( entry )
        entry->priority |= priority;
}

inline unsigned appInfoEntryPriorityGet(AppId app_id, AppIdConfig* pConfig)
{
    AppInfoTableEntry* entry = appInfoEntryGet(app_id, pConfig);
    return entry ? entry->priority : 0;
}

#endif

