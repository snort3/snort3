//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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
#include "appid_debug.h"

#include "trace/trace_api.h"

#include "tp_lib_handler.h"

using namespace std;
using namespace snort;

TPLibHandler* TPLibHandler::self = nullptr;
uint32_t ThirdPartyAppIdContext::next_version = 0;

bool TPLibHandler::load_callback(const char* const path)
{
    dlerror();
    self->tp_so_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (self->tp_so_handle == nullptr)
    {
        appid_log(nullptr, TRACE_ERROR_LEVEL, "Failed to load 3rd party AppID library: %s - %s\n", path, dlerror());
        return false;
    }

    typedef void (*dummyFunc)();
    struct funcBinding
    {
        const char* lib_sym;
        dummyFunc* local_sym;
    } bindings[] =
    {
        { "tp_appid_create_ctxt", (dummyFunc*)&tp_appid_create_ctxt },
        { "tp_appid_create_session", (dummyFunc*)&tp_appid_create_session },
        { "tp_appid_pfini", (dummyFunc*)&tp_appid_pfini },
        { "tp_appid_tfini", (dummyFunc*)&tp_appid_tfini },
        { nullptr, nullptr }
    };

    funcBinding* index;

    for (index = bindings; index->lib_sym; index++)
    {
        *(void**)index->local_sym  = dlsym(self->tp_so_handle, index->lib_sym);
        if (*(index->local_sym) == nullptr)
        {
            char* error;
            appid_log(nullptr, TRACE_ERROR_LEVEL, "AppId: Failed to resolve symbol: %s %s\n", index->lib_sym,
                (error = dlerror()) ? error : "");
            dlclose(self->tp_so_handle);
            self->tp_so_handle = nullptr;
            return false;
        }
    }

    return true;
}

ThirdPartyAppIdContext* TPLibHandler::create_tp_appid_ctxt(const AppIdConfig& config,
    const OdpContext& odp_ctxt)
{
    assert(self != nullptr);

    if (!self->tp_so_handle)
    {
        if (config.tp_appid_path.empty())
            return nullptr;

        if (!self->load_callback(config.tp_appid_path.c_str()))
            return nullptr;
    }

    ThirdPartyConfig tp_config;
    tp_config.tp_appid_config = config.tp_appid_config;
    tp_config.tp_appid_stats_enable = config.tp_appid_stats_enable;
    tp_config.tp_appid_config_dump = config.tp_appid_config_dump;
    tp_config.chp_body_collection_max = odp_ctxt.chp_body_collection_max;
    tp_config.ftp_userid_disabled = odp_ctxt.ftp_userid_disabled;
    tp_config.chp_body_collection_disabled =
        odp_ctxt.chp_body_collection_disabled;
    tp_config.tp_allow_probes = odp_ctxt.tp_allow_probes;
    tp_config.tp_appid_profiler_functions = get_tp_appid_profiler_functions();

    ThirdPartyAppIdContext* tp_appid_ctxt = self->tp_appid_create_ctxt(tp_config);
    if (tp_appid_ctxt == nullptr)
    {
        appid_log(nullptr, TRACE_ERROR_LEVEL, "Failed to create third party appId context.\n");
        dlclose(self->tp_so_handle);
        self->tp_so_handle = nullptr;
        return nullptr;
    }

    if ( (tp_appid_ctxt->get_api_version() != THIRD_PARTY_APPID_API_VERSION)
        || (tp_appid_ctxt->module_name().empty()) )
    {
        appid_log(nullptr, TRACE_ERROR_LEVEL, "Ignoring incomplete 3rd party AppID module (%s, %u, %s)!\n",
            config.tp_appid_path.c_str(), tp_appid_ctxt->get_api_version(),
            tp_appid_ctxt->module_name().empty() ? "empty" : tp_appid_ctxt->module_name().c_str());

        delete tp_appid_ctxt;
        dlclose(self->tp_so_handle);
        self->tp_so_handle = nullptr;
        return nullptr;
    }

    return tp_appid_ctxt;
}

void TPLibHandler::tfini()
{
    assert(self != nullptr);

    int ret = 0;

    if (self->tp_appid_tfini)
        ret = self->tp_appid_tfini();

    if (ret != 0)
        appid_log(nullptr, TRACE_ERROR_LEVEL, "Could not terminate packet thread in 3rd party AppID module (%d)!\n", ret);
}

void TPLibHandler::pfini()
{
    assert(self != nullptr);

    int ret = 0;

    if (self->tp_appid_pfini)
        ret = self->tp_appid_pfini();

    if (ret != 0)
        appid_log(nullptr, TRACE_ERROR_LEVEL, "Could not terminate 3rd party AppID module (%d)!\n", ret);

    AppIdContext::delete_tp_appid_ctxt();

    // FIXIT-L: Find the right place to dlclose self->tp_so_handle. dlclose here was causing
    // segfault

    if ( self ) {
        delete self;
        self = nullptr;
    }
}
