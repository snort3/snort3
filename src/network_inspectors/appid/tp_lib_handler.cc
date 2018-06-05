//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

// tp_lib_handler.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <dlfcn.h>

#include "appid_config.h"

#include "main/snort_debug.h"
#include "log/messages.h"

#include "tp_lib_handler.h"

using namespace std;
using namespace snort;

#define TP_APPID_MODULE_SYMBOL "create_third_party_appid_module"
#define TP_APPID_SESSION_SYMBOL "create_third_party_appid_session"

TPLibHandler* TPLibHandler::self = nullptr;

int TPLibHandler::LoadCallback(const char* const path, int /* indent */)
{
    void* handle = 0;
    ThirdPartyAppIDModule* tp_module = 0;
    const char* error = nullptr;

    if (tp_appid_module != nullptr)
    {
        ErrorMessage("Ignoring additional 3rd party AppID module (%s)!\n", path);
        return 0;
    }

    // Load the tp library and get function pointers to the module and
    // session object factories.
    dlerror();
    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr)
    {
        ErrorMessage("Failed to load 3rd party AppID library: %s - %s\n", path, dlerror());
        return 0;
    }

    CreateThirdPartyAppIDModule_t createThirdPartyAppIDModule=
        (CreateThirdPartyAppIDModule_t)dlsym(handle, TP_APPID_MODULE_SYMBOL);
    if ((error=dlerror()) != nullptr)
    {
        ErrorMessage(
            "Failed to get 3rd party AppID module object factory: %s - %s\n",
            TP_APPID_MODULE_SYMBOL, error);
        dlclose(handle);
        return 0;
    }

    createThirdPartyAppIDSession=(CreateThirdPartyAppIDSession_t)dlsym(
        handle,TP_APPID_SESSION_SYMBOL);
    if ((error=dlerror()) != nullptr)
    {
        ErrorMessage(
            "Failed to get 3rd party AppID session object factory: %s - %s\n",
            TP_APPID_SESSION_SYMBOL, error);
        dlclose(handle);
        return 0;
    }

    // The tp module object is a singleton and gets created here in main thread.
    // TP session objects get created per worker thread.
    tp_module=createThirdPartyAppIDModule();
    if (tp_module == nullptr)
    {
        ErrorMessage("Failed to create third party appId module.\n");
        dlclose(handle);
        return 0;
    }

    if ( (tp_module->api_version() != THIRD_PARTY_APP_ID_API_VERSION)
        || (tp_module->module_name().empty()) )
    {
        ErrorMessage("Ignoring incomplete 3rd party AppID module (%s, %u, %s)!\n",
            path, tp_module->api_version(),
            tp_module->module_name().empty() ? "empty" : tp_module->module_name().c_str());

        dlclose(handle);
        delete tp_module;
        return 0;
    }

    this->tp_so_handle = handle;
    tp_appid_module = tp_module;
    return 0;
}

void TPLibHandler::pinit(const AppIdModuleConfig* config)
{
    int ret;

    if (self->tp_so_handle or config->tp_appid_path.empty())
        return;

    self->tp_config.tp_appid_config=config->tp_appid_config;

    self->LoadCallback(config->tp_appid_path.c_str(),1);

    if (self->tp_appid_module == nullptr)
    {
        ErrorMessage("Ignoring third party AppId library\n");
        return;
    }

    self->tp_config.chp_body_collection_max = config->chp_body_collection_max;
    self->tp_config.ftp_userid_disabled = config->ftp_userid_disabled;
    self->tp_config.chp_body_collection_disabled =
        config->chp_body_collection_disabled;
    self->tp_config.tp_allow_probes = config->tp_allow_probes;
    if (config->http2_detection_enabled)
        self->tp_config.http_upgrade_reporting_enabled = 1;
    else
        self->tp_config.http_upgrade_reporting_enabled = 0;

    self->tp_config.http_response_version_enabled = config->http_response_version_enabled;

    ret = self->tp_appid_module->pinit(self->tp_config);
    if (ret != 0)
    {
        ErrorMessage("Unable to initialize 3rd party AppID module (%d)!\n", ret);
        delete self->tp_appid_module;
        dlclose(self->tp_so_handle);
        self->tp_so_handle = nullptr;
        self->tp_appid_module = nullptr;
        return;
    }
}

void TPLibHandler::pfini(bool print_stats_flag)
{
    if (self and self->tp_appid_module != nullptr)
    {
        if (print_stats_flag)
            self->tp_appid_module->print_stats();

        int ret = self->tp_appid_module->pfini();

        if (ret != 0)
            ErrorMessage("Could not finalize 3rd party AppID module (%d)!\n", ret);

        delete self->tp_appid_module;
        self->tp_appid_module = nullptr;

        dlclose(self->tp_so_handle); // after delete, otherwise tpam will be dangling
        self->tp_so_handle = nullptr;
    }

    if ( self ) {
        delete self;
        self = nullptr;
    }
}
