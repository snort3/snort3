//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// thirdparty_appid_utils.h author Sourcefire Inc.

#ifndef THIRDPARTY_APPID_UTILS_H
#define THIRDPARTY_APPID_UTILS_H

#include "thirdparty_appid_api.h"

#include "main/thread.h"
#include "flow/flow.h"
#include "protocols/protocol_ids.h"
#include "sfip/sf_ip.h"

class AppIdModuleConfig;
class AppIdSession;
struct ThirdPartyAppIDModule;
struct ThirdPartyAppIDAttributeData;
struct Packet;

extern THREAD_LOCAL ThirdPartyAppIDModule* thirdparty_appid_module;    // nullptr means no 3rd
                                                                       // party AppID module
void ThirdPartyAppIDInit(AppIdModuleConfig*);
void ThirdPartyAppIDReconfigure();
void ThirdPartyAppIDFini();
void ProcessThirdPartyResults(Packet*, int, AppId*, ThirdPartyAppIDAttributeData*);
void checkTerminateTpModule(AppIdSession*, uint16_t tpPktCount);
bool do_third_party_discovery(AppIdSession*, IpProtocol, const SfIp*,  Packet*, int&);
void pickHttpXffAddress(AppIdSession*, Packet*, ThirdPartyAppIDAttributeData*);

inline bool is_third_party_appid_done(void* tp_session)
{
    if (thirdparty_appid_module)
    {
        unsigned state;

        if (tp_session)
            state = thirdparty_appid_module->session_state_get(tp_session);
        else
            state = TP_STATE_INIT;

        return (state  == TP_STATE_CLASSIFIED || state == TP_STATE_TERMINATED
               || state == TP_STATE_HA);
    }

    return true;
}

inline bool is_third_party_appid_available(void* tp_session)
{
    if (thirdparty_appid_module)
    {
        unsigned state;

        if (tp_session)
            state = thirdparty_appid_module->session_state_get(tp_session);
        else
            state = TP_STATE_INIT;

        return (state == TP_STATE_CLASSIFIED || state == TP_STATE_TERMINATED
               || state == TP_STATE_MONITORING);
    }

    return true;
}

#endif

