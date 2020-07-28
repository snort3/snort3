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

// app_forecast.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "app_forecast.h"
#include "appid_inspector.h"

#include "log/messages.h"
#include "time/packet_time.h"
#include "appid_session.h"

using namespace snort;

void check_session_for_AF_indicator(Packet* p, AppidSessionDirection dir, AppId indicator, const OdpContext& odp_ctxt)
{
    const std::unordered_map<int, AFElement>& AF_indicators = odp_ctxt.get_af_indicators();
    auto af_indicator_entry = AF_indicators.find(indicator);

    if (af_indicator_entry == AF_indicators.end())
        return;

    AFElement ind_element = af_indicator_entry->second;
    AFActKey master_key(p, dir, ind_element.forecast);

    AFActVal new_active_value = AFActVal(ind_element.target, packet_time());

    odp_thread_local_ctxt->add_af_actives(master_key, new_active_value);
}

AppId check_session_for_AF_forecast(AppIdSession& asd, Packet* p, AppidSessionDirection dir, AppId forecast)
{
    AFActKey master_key(p, dir, forecast);

    //get out if there is no value
    std::map<AFActKey, AFActVal>* AF_actives = odp_thread_local_ctxt->get_af_actives();
    assert(AF_actives);
    auto check_act_val = AF_actives->find(master_key);
    if (check_act_val == AF_actives->end())
        return APP_ID_UNKNOWN;

    //if the value is older than 5 minutes, remove it and get out
    time_t age = packet_time() - check_act_val->second.last;
    if (age < 0 || age > 300)
    {
        odp_thread_local_ctxt->erase_af_actives(master_key);
        return APP_ID_UNKNOWN;
    }
    asd.set_payload_id(check_act_val->second.target);
    return forecast;
}

