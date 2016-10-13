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

// fw_appid.cc author Sourcefire Inc.

#include "fw_appid.h"

#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/tcp.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#include "appid_stats.h"
#include "appid_config.h"
#include "appid_module.h"
#include "app_forecast.h"
#include "app_info_table.h"
#include "appid_api.h"
#include "host_port_app_cache.h"
#include "lua_detector_module.h"
#include "client_plugins/client_app_base.h"
#include "detector_plugins/detector_dns.h"
#include "service_plugins/service_base.h"
#include "service_plugins/service_ssl.h"
#include "service_plugins/service_util.h"
#include "appid_utils/common_util.h"
#include "appid_utils/ip_funcs.h"
#include "appid_utils/network_set.h"
#include "time/packet_time.h"
#include "sfip/sf_ip.h"

#define HTTP_PATTERN_MAX_LEN    1024
#define PORT_MAX 65535

#ifdef APPID_UNUSED_CODE
void reset_appid_stats(int, void*)
{
    if (thirdparty_appid_module)
        thirdparty_appid_module->reset_stats();
}
#endif

void AppIdAddUser(AppIdSession* asd, const char* username, AppId appId, int success)
{
    if (asd->username)
        snort_free(asd->username);
    asd->username = snort_strdup(username);
    asd->username_service = appId;
    if (success)
        asd->set_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
    else
        asd->clear_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
}

void AppIdAddPayload(AppIdSession* asd, AppId payload_id)
{
    if (AppIdConfig::get_appid_config()->mod_config->instance_id)
        checkSandboxDetection(payload_id);
    asd->payload_app_id = payload_id;
}

void checkSandboxDetection(AppId appId)
{
    AppInfoTableEntry* entry;

    if (AppIdConfig::get_appid_config()->mod_config->instance_id)
    {
        entry = AppInfoManager::get_instance().get_app_info_entry(appId);
        if ( entry && ( entry->flags & APPINFO_FLAG_ACTIVE ) )
            fprintf(SF_DEBUG_FILE, "Detected AppId %d\n", entry->appId);
        else if( appId != 0 )
            fprintf(SF_DEBUG_FILE, "No Entry For AppId %d\n", appId);
    }
}
