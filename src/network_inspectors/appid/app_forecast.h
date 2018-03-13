//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "application_ids.h"

class AppIdSession;
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
    AppId indicator;
    AppId forecast;
    AppId target;
};

struct AFActKey
{
    uint32_t ip[4];
    AppId forecast;
};

struct AFActVal
{
    AppId target;
    time_t last;
};

int init_appid_forecast();
void clean_appid_forecast();
void add_af_indicator(AppId, AppId, AppId);
void check_session_for_AF_indicator(snort::Packet*, int, AppId);
AppId check_session_for_AF_forecast(AppIdSession&, snort::Packet*, int, AppId);

#endif

