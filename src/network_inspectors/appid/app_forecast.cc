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

// app_forecast.cc author Sourcefire Inc.

#include "app_forecast.h"

#include "hash/sfxhash.h"
#include "time/packet_time.h"

#include "application_ids.h"

static AFActKey master_key;

static inline void rekeyMasterAFActKey(Packet* p, int dir, ApplicationId forecast)
{
    const sfip_t* src = dir ? p->ptrs.ip_api.get_dst() : p->ptrs.ip_api.get_src();

    for (int i = 0; i < 4; i++)
        master_key.ip[i] = src->ip32[i];

    master_key.forecast = forecast;
}

void checkSessionForAFIndicator(
    Packet* p, int dir, const AppIdConfig* pConfig, ApplicationId indicator)
{
    AFElement* ind_element;
    if (!(ind_element = (AFElement*)sfxhash_find(pConfig->AF_indicators, &indicator)))
        return;

    rekeyMasterAFActKey(p, dir, ind_element->forecast);

    AFActVal* test_active_value;
    if ((test_active_value = (AFActVal*)sfxhash_find(pConfig->AF_actives, &master_key)))
    {
        test_active_value->last = packet_time();
        test_active_value->target = ind_element->target;
        return;
    }

    AFActVal new_active_value;
    new_active_value.target = ind_element->target;
    new_active_value.last = packet_time();

    sfxhash_add(pConfig->AF_actives, &master_key, &new_active_value);
}

AppId checkSessionForAFForecast(
    AppIdData* session, Packet* p, int dir, const AppIdConfig* pConfig, ApplicationId forecast)
{
    AFActVal* check_act_val;

    rekeyMasterAFActKey(p, dir, forecast);

    //get out if there is no value
    if (!(check_act_val = (AFActVal*)sfxhash_find(pConfig->AF_actives, &master_key)))
        return APP_ID_UNKNOWN;

    //if the value is older than 5 minutes, remove it and get out
    time_t age;
    age = packet_time() - check_act_val->last;
    if (age < 0 || age > 300)
    {
        sfxhash_remove(pConfig->AF_actives, &master_key);
        return APP_ID_UNKNOWN;
    }

    session->payloadAppId = check_act_val->target;
    return forecast;
}

