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

    bool have_tp() const
    {
	return tp_appid_module != nullptr;
    }

    static TPLibHandler* get()
    {
        if (handler)
            return handler;
        else
            return (handler=new TPLibHandler());
    }

    static void destroy(TPLibHandler* tph)
    {
        delete tph->handler;
        tph->handler=nullptr;
    }

    // called from AppIdConfig::init_appid() and cleanup(), respectively.
    void pinit(const AppIdModuleConfig* config);
    void pfini(bool print_stats_flag=0);

    // called from AppIdInspector tinit/tterm via
    // AppIdConfig::tp_appid_module_tinit/tterm.
    void tinit() { if ( tp_appid_module ) tp_appid_module->tinit(); }
    void tterm() { if ( tp_appid_module ) tp_appid_module->tfini(); }

    CreateThirdPartyAppIDSession_t tpsession_factory() const
    {
        return createThirdPartyAppIDSession;
    }

private:

    TPLibHandler() { }
    ~TPLibHandler() { }

    static TPLibHandler* handler;
    void* tp_so_handle = nullptr;   // output of dlopen(thirdparty.so)
    ThirdPartyAppIDModule* tp_appid_module = nullptr;
    CreateThirdPartyAppIDSession_t createThirdPartyAppIDSession;

    ThirdPartyConfig tp_config;

    int LoadCallback(const char* path, int);
};

#endif

