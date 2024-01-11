//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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

// tp_appid_session_api.h author Silviu Minut <sminut@cisco.com>

#ifndef TP_APPID_SESSION_API_H
#define TP_APPID_SESSION_API_H

#include <vector>
#include <string>
#include "appid_types.h"
#include "application_ids.h"
#include "tp_appid_types.h"

namespace snort
{
struct Packet;
}

class ThirdPartyAppIdContext;

class ThirdPartyAppIdSession
{
public:
    ThirdPartyAppIdSession(const ThirdPartyAppIdContext& ctxt)
        : appid(APP_ID_NONE), confidence(100), state(TP_STATE_INIT), ctxt(ctxt)
    {
        ctxt_version = ctxt.get_version();
    }

    virtual ~ThirdPartyAppIdSession() = default;

    virtual void reset() = 0;            // just reset state
    virtual void delete_with_ctxt() = 0;
    virtual TPState process(const snort::Packet&,
        AppidSessionDirection direction,
        std::vector<AppId>& proto_list,
        ThirdPartyAppIDAttributeData& attribute_data) = 0;

    virtual int disable_flags(uint32_t session_flags) = 0;
    virtual TPState get_state() { return state; }
    virtual void set_state(TPState) = 0;
    virtual void clear_attr(TPSessionAttr) = 0;
    virtual void set_attr(TPSessionAttr) = 0;
    virtual unsigned get_attr(TPSessionAttr) = 0;
    virtual AppId get_appid(int& conf) { conf=confidence; return appid; }
    virtual const ThirdPartyAppIdContext& get_ctxt() const
    { return ctxt; }
    uint32_t get_ctxt_version() { return ctxt_version; }

protected:
    AppId appid;
    int confidence;
    TPState state;
    const ThirdPartyAppIdContext& ctxt;
    uint32_t ctxt_version;
};

#endif

