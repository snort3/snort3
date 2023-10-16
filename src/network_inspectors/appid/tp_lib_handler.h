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

// tp_lib_handler.h author Silviu Minut <sminut@cisco.com>

#ifndef TP_LIB_HANDLER_H
#define TP_LIB_HANDLER_H

#include "tp_appid_module_api.h"
#include "tp_appid_session_api.h"

class AppIdConfig;
class OdpContext;

// This needs to be exported by any third party .so library.
// Must return null if it fails to create the object.
typedef ThirdPartyAppIdContext* (* TpAppIdCreateCtxt)(ThirdPartyConfig& );
typedef ThirdPartyAppIdSession* (* TpAppIdCreateSession)(ThirdPartyAppIdContext& ctxt);
typedef int (* TpAppIdPfini)();
typedef int (* TpAppIdTfini)();

// Class responsible for loading/reloading the thirdparty.so library
class TPLibHandler
{
public:
    static TPLibHandler* get()
    {
        if (self)
            return self;
        else
            return (self = new TPLibHandler());
    }

    static ThirdPartyAppIdContext* create_tp_appid_ctxt(const AppIdConfig& config,
        const OdpContext& odp_ctxt);
    static void tfini();
    static void pfini();

    TpAppIdCreateSession tpsession_factory() const
    {
        return tp_appid_create_session;
    }

private:
    TPLibHandler() = default;
    ~TPLibHandler() = default;

    static TPLibHandler* self;
    void* tp_so_handle = nullptr;   // output of dlopen(thirdparty.so)
    TpAppIdCreateCtxt tp_appid_create_ctxt = nullptr;
    TpAppIdCreateSession tp_appid_create_session = nullptr;
    TpAppIdPfini tp_appid_pfini = nullptr;
    TpAppIdTfini tp_appid_tfini = nullptr;

    bool load_callback(const char* path);
};

#endif
