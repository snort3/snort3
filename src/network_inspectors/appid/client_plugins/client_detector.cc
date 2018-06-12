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

// client_detector.cc author davis mcpherson

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_detector.h"

#include "appid_config.h"
#include "app_info_table.h"
#include "appid_session.h"
#include "lua_detector_api.h"
#include "protocols/packet.h"
#include "log/messages.h"

static THREAD_LOCAL unsigned client_module_index = 0;

ClientDetector::ClientDetector()
{
    flow_data_index = client_module_index++ | APPID_SESSION_DATA_CLIENT_MODSTATE_BIT;
    client = true;
}

void ClientDetector::register_appid(AppId appId, unsigned extractsInfo)
{
    AppInfoTableEntry* pEntry = AppInfoManager::get_instance().get_app_info_entry(appId);
    if (!pEntry)
    {
        if ( AppInfoManager::get_instance().configured() )
        {
            snort::ParseWarning(WARN_RULES,
                "appid: no entry for %d in appMapping.data; no rule support for this ID.",
                appId);
        }
        return;
    }
    extractsInfo &= (APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER);
    if (!extractsInfo)
        return;

    pEntry->client_detector = this;
    pEntry->flags |= extractsInfo;
}

