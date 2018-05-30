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

// tp_lib_handler.h author Silviu Minut <sminut@cisco.com>

#ifndef TP_LIB_HANDLER_H
#define TP_LIB_HANDLER_H

#include "tp_appid_module_api.h"
#include "tp_appid_session_api.h"

class AppIdModuleConfig;

// Class responsible for loading/reloading the thirdparty.so library and
// for holding pointers to objects that live inside thirdparty.so.
class TPLibHandler
{
public:

    static bool have_tp()
    {
        return self and self->tp_appid_module != nullptr;
    }

    static TPLibHandler* get()
    {
        if (self)
            return self;
        else
            return (self=new TPLibHandler());
    }

    // called from appid_inspector.cc appid_inspector_pinit() / pterm()
    static void pinit(const AppIdModuleConfig* config);
    static void pfini(bool print_stats_flag=0);

    // called from AppIdInspector tinit/tterm via
    // AppIdConfig::tp_appid_module_tinit/tterm.
    static void tinit() { if ( have_tp() ) self->tp_appid_module->tinit(); }
    static void tterm() { if ( have_tp() ) self->tp_appid_module->tfini(); }

    CreateThirdPartyAppIDSession_t tpsession_factory() const
    {
        return createThirdPartyAppIDSession;
    }

private:

    TPLibHandler() = default;
    ~TPLibHandler() = default;

    static TPLibHandler* self;
    void* tp_so_handle = nullptr;   // output of dlopen(thirdparty.so)
    ThirdPartyAppIDModule* tp_appid_module = nullptr;
    CreateThirdPartyAppIDSession_t createThirdPartyAppIDSession;

    ThirdPartyConfig tp_config;

    int LoadCallback(const char* path, int);
};

#endif
