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

// app_forecast.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "app_forecast.h"

#include "hash/sfxhash.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "time/packet_time.h"
#include "appid_session.h"

static THREAD_LOCAL AFActKey master_key;
static THREAD_LOCAL SFXHASH* AF_indicators = nullptr;     // list of "indicator apps"
static THREAD_LOCAL SFXHASH* AF_actives = nullptr;        // list of hosts to watch

int init_appid_forecast()
{
    if (!(AF_indicators = sfxhash_new(1024, sizeof(AppId), sizeof(AFElement),
            0, 0, nullptr, nullptr, 0)))
    {
        ErrorMessage("Config: failed to allocate memory for an AF Indicators hash.");
        return 0;
    }

    if (!(AF_actives = sfxhash_new(1024, sizeof(AFActKey), sizeof(AFActVal),
            (sizeof(SFXHASH_NODE)*2048), 1, nullptr,  nullptr, 1)))
    {
        sfxhash_delete(AF_indicators);
        ErrorMessage("Config: failed to allocate memory for an AF Actives hash.");
        return 0;
    }
    else
        return 1;
}

void clean_appid_forecast()
{
    if (AF_indicators)
    {
        sfxhash_delete(AF_indicators);
        AF_indicators = nullptr;
    }

    if (AF_actives)
    {
        sfxhash_delete(AF_actives);
        AF_actives = nullptr;
    }
}

void add_af_indicator(ApplicationId indicator, ApplicationId forecast, ApplicationId target)
{
    if (sfxhash_find(AF_indicators, &indicator))
    {
        ErrorMessage("LuaDetectorApi:Attempt to add more than one AFElement per appId %d",
            indicator);
        return;
    }

    AFElement val;
    val.indicator = indicator;
    val.forecast = forecast;
    val.target = target;
    if (sfxhash_add(AF_indicators, &indicator, &val))
        ErrorMessage("LuaDetectorApi:Failed to add AFElement for appId %d", indicator);
}

static inline void rekey_master_AF_key(Packet* p, int dir, ApplicationId forecast)
{
    const SfIp* src = dir ? p->ptrs.ip_api.get_dst() : p->ptrs.ip_api.get_src();

    for (int i = 0; i < 4; i++)
        master_key.ip[i] = src->get_ip6_ptr()[i];

    master_key.forecast = forecast;
}

void check_session_for_AF_indicator(Packet* p, int dir, ApplicationId indicator)
{
    AFElement* ind_element;
    if (!(ind_element = (AFElement*)sfxhash_find(AF_indicators, &indicator)))
        return;

    rekey_master_AF_key(p, dir, ind_element->forecast);

    AFActVal* test_active_value;
    if ((test_active_value = (AFActVal*)sfxhash_find(AF_actives, &master_key)))
    {
        test_active_value->last = packet_time();
        test_active_value->target = ind_element->target;
        return;
    }

    AFActVal new_active_value;
    new_active_value.target = ind_element->target;
    new_active_value.last = packet_time();

    sfxhash_add(AF_actives, &master_key, &new_active_value);
}

AppId check_session_for_AF_forecast(AppIdSession* asd, Packet* p, int dir, ApplicationId forecast)
{
    AFActVal* check_act_val;

    rekey_master_AF_key(p, dir, forecast);

    //get out if there is no value
    if (!(check_act_val = (AFActVal*)sfxhash_find(AF_actives, &master_key)))
        return APP_ID_UNKNOWN;

    //if the value is older than 5 minutes, remove it and get out
    time_t age;
    age = packet_time() - check_act_val->last;
    if (age < 0 || age > 300)
    {
        sfxhash_remove(AF_actives, &master_key);
        return APP_ID_UNKNOWN;
    }

    asd->payload_app_id = check_act_val->target;
    return forecast;
}

