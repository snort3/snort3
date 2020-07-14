//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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

// app_forecast.h author Sourcefire Inc.

#ifndef APP_FORECAST_H
#define APP_FORECAST_H

#include <ctime>

#include "flow/flow.h"
#include "protocols/packet.h"
#include "utils/cpp_macros.h"

#include "appid_types.h"
#include "application_ids.h"

class AppIdSession;
class OdpContext;
namespace snort
{
struct Packet;
}

// indicator - the appId that indicates there may be subsequent flows to look for,
// from the same host
// forecast - the appId in the subsequent flow that we are looking for
// target - the appId we want to set in that subsequent flow
//
// for now, indicator and target are WEB APPLICATIONS. The forecast is APP PROTOCOL.
// We can change this later by adding app type info for each, if we find a use case.

struct AFElement
{
    AFElement(AppId forecast, AppId target) : forecast(forecast), target(target) { }

    AppId forecast;
    AppId target;
};

PADDING_GUARD_BEGIN
class AFActKey
{
    public:
        AFActKey(snort::Packet* p, AppidSessionDirection dir, AppId forecast) :
            forecast(forecast)
        {
            const snort::SfIp* src = dir ? p->ptrs.ip_api.get_dst() : p->ptrs.ip_api.get_src();

            memcpy(ip, src->get_ip6_ptr(), sizeof(ip));
        }

        bool operator<(const AFActKey &key) const
        {
            return (forecast < key.forecast || ip[0] < key.ip[0] ||
                   ip[1] < key.ip[1] || ip[2] < key.ip[2] || ip[3] < key.ip[3]);
        }
    private:
        uint32_t ip[4];
        AppId forecast;
};
PADDING_GUARD_END

struct AFActVal
{
    AFActVal(AppId target, time_t last) : target(target), last(last) { }

    AppId target;
    time_t last;
};

void check_session_for_AF_indicator(snort::Packet*, AppidSessionDirection, AppId, const OdpContext&);
AppId check_session_for_AF_forecast(AppIdSession&, snort::Packet*, AppidSessionDirection, AppId);

#endif

