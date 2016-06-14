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

// thirdparty_appid_utils.cc author Sourcefire Inc.

#include "thirdparty_appid_utils.h"

#include <dlfcn.h>

#include "main/snort_debug.h"
#include "log/messages.h"
#include "appid_config.h"
#include "thirdparty_appid_api.h"

#define MODULE_SYMBOL "thirdparty_appid_impl_module"

THREAD_LOCAL void* module_handle = nullptr;
THREAD_LOCAL struct ThirdPartyConfig thirdpartyConfig;
THREAD_LOCAL ThirdPartyAppIDModule* thirdparty_appid_module = nullptr;

// FIXIT - these need to be define or otherwise obtained...
static char* defaultXffFields[] = { nullptr /* HTTP_XFF_FIELD_X_FORWARDED_FOR, */
                                    /* HTTP_XFF_FIELD_TRUE_CLIENT_IP */ };

int LoadCallback(const char* const path, int /* indent */)
{
    void* handle;
    ThirdPartyAppIDModule* tp_module;

    if (thirdparty_appid_module != nullptr)
    {
        ErrorMessage("Ignoring additional 3rd party AppID module (%s)!\n", path);
        return 0;
    }

    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr)
    {
        ErrorMessage("Failed to load 3rd party AppID module: %s - %s\n", path, dlerror());
        return 0;
    }

    tp_module = (ThirdPartyAppIDModule*)dlsym(handle, MODULE_SYMBOL);
    if (tp_module == nullptr)
    {
        ErrorMessage("Failed to fine symbol %s in library %s\n", MODULE_SYMBOL, path);
        dlclose(handle);
        return 0;
    }

    if ( (tp_module->api_version != THIRD_PARTY_APP_ID_API_VERSION)
        || ((tp_module->module_name == nullptr) || (tp_module->module_name[0] == 0))
        || (tp_module->init == nullptr)
        || (tp_module->fini == nullptr)
        || (tp_module->session_create == nullptr)
        || (tp_module->session_delete == nullptr)
        || (tp_module->session_process == nullptr)
        || (tp_module->print_stats == nullptr)
        || (tp_module->reset_stats == nullptr)
        || (tp_module->disable_flags == nullptr) )
    {
        ErrorMessage("Ignoring incomplete 3rd party AppID module (%s)!\n", path);
        dlclose(handle);
        return 0;
    }

    DEBUG_WRAP(DebugFormat(DEBUG_APPID, "Found 3rd party AppID module (%s).\n",
        tp_module->module_name ? tp_module->module_name : ""); );
    module_handle = handle;
    thirdparty_appid_module = tp_module;
    return 0;
}

void ThirdPartyAppIDInit(AppIdModuleConfig* appidStaticConfig)
{
    const char* thirdparty_appid_dir = appidStaticConfig->thirdparty_appid_dir;
    int ret;
    struct ThirdPartyUtils thirdpartyUtils;

    if ( ( thirdparty_appid_module != nullptr ) || ( thirdparty_appid_dir == nullptr )
        || ( thirdparty_appid_dir[0] == 0 ) )
        return;

    // FIXIT - need to port loadAllLibs function to snort3
    // _dpd.loadAllLibs(thirdparty_appid_dir, LoadCallback);
    if (thirdparty_appid_module == nullptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_APPID, "No 3rd party AppID module loaded.\n"); );
        return;
    }

    memset(&thirdpartyConfig, 0, sizeof(thirdpartyConfig));
    thirdpartyConfig.chp_body_collection_max = appidStaticConfig->chp_body_collection_max;
    thirdpartyConfig.ftp_userid_disabled = appidStaticConfig->ftp_userid_disabled;
    thirdpartyConfig.chp_body_collection_disabled =
        appidStaticConfig->chp_body_collection_disabled;
    thirdpartyConfig.tp_allow_probes = appidStaticConfig->tp_allow_probes;
    if (appidStaticConfig->http2_detection_enabled)
        thirdpartyConfig.http_upgrade_reporting_enabled = 1;
    else
        thirdpartyConfig.http_upgrade_reporting_enabled = 0;
    thirdpartyConfig.appid_tp_dir[0] = '\0';    // use default path

    // FIXIT - need to provide log function and getSnortInstance function to 3rd party utils
#ifdef REMOVED_WHILE_NOT_IN_USE
    thirdpartyUtils.logMsg           = &DebugFormat;
    thirdpartyUtils.getSnortInstance = _dpd.getSnortInstance;

    // FIXIT - need to get xff fields from http config
    thirdpartyConfig.xffFields = _dpd.getHttpXffFields(&thirdpartyConfig.numXffFields);
#endif

    if (!thirdpartyConfig.xffFields)
    {
        thirdpartyConfig.xffFields = defaultXffFields;
        thirdpartyConfig.numXffFields = sizeof(defaultXffFields) / sizeof(defaultXffFields[0]);
    }

    ret = thirdparty_appid_module->init(&thirdpartyConfig, &thirdpartyUtils);
    if (ret != 0)
    {
        ErrorMessage("Unable to initialize 3rd party AppID module (%d)!\n", ret);
        dlclose(module_handle);
        module_handle = nullptr;
        thirdparty_appid_module = nullptr;
        return;
    }

    DEBUG_WRAP(DebugFormat(DEBUG_APPID,
        "3rd party AppID module loaded and initialized OK (%s).\n",
        thirdparty_appid_module->module_name ? thirdparty_appid_module->module_name : ""); );
}

void ThirdPartyAppIDReconfigure(void)
{
    int ret;

    if (thirdparty_appid_module == nullptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_APPID, "No 3rd party AppID module loaded.\n"); );
        return;
    }

    thirdpartyConfig.oldNumXffFields = thirdpartyConfig.numXffFields;
    thirdpartyConfig.oldXffFields = thirdpartyConfig.xffFields;

    // FIXIT - need to get xff fields from http config
    // thirdpartyConfig.xffFields = _dpd.getHttpXffFields(&thirdpartyConfig.numXffFields);
    if (!thirdpartyConfig.xffFields)
    {
        thirdpartyConfig.xffFields = defaultXffFields;
        thirdpartyConfig.numXffFields = sizeof(defaultXffFields) / sizeof(defaultXffFields[0]);
    }

    ret = thirdparty_appid_module->reconfigure(&thirdpartyConfig);
    if (ret != 0)
    {
        ErrorMessage("Unable to reconfigure 3rd party AppID module (%d)!\n", ret);
        return;
    }

    DEBUG_WRAP(DebugFormat(DEBUG_APPID, "3rd party AppID module reconfigured OK (%s).\n",
        thirdparty_appid_module->module_name ? thirdparty_appid_module->module_name : ""); );
}

void ThirdPartyAppIDFini(void)
{
    int ret;

    if (thirdparty_appid_module != nullptr)
    {
        ret = thirdparty_appid_module->fini();
        if (ret != 0)
        {
            ErrorMessage("Could not finalize 3rd party AppID module (%d)!\n", ret);
        }

        dlclose(module_handle);
        module_handle = nullptr;
        thirdparty_appid_module = nullptr;

        DEBUG_WRAP(DebugMessage(DEBUG_APPID,
            "3rd party AppID module finalized and unloaded OK.\n"); );
    }
}

