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

// app_forecast.h author Sourcefire Inc.

#ifndef APP_FORECAST_H
#define APP_FORECAST_H

//  AppId flow forcasting data structures and methods
//

#include <time.h>
#include "appid_api.h"
#include "appid_config.h"
#include "protocols/packet.h"

#include "appid_flow_data.h"

// indicator - the appId that indicates there may be subsequent flows to look for, from the same host
// forecast - the appId in the subsequent flow that we are looking for
// target - the appId we want to set in that subsequent flow
//
// for now, indicator and target are WEB APPLICATIONS. The forecast is APP PROTOCOL. We can change this
// later by adding app type info for each, if we find a use case.

class AppIdConfig;
enum ApplicationId : int32_t;

struct AFElement
{
    ApplicationId indicator;
    ApplicationId forecast;
    ApplicationId target;
};

struct AFActKey
{
    uint32_t ip[4];
    ApplicationId forecast;
};

struct AFActVal
{
    ApplicationId target;
    time_t last;
};

void checkSessionForAFIndicator(Packet*, int, const AppIdConfig*, ApplicationId);
AppId checkSessionForAFForecast(AppIdData*, Packet*, int, const AppIdConfig*, ApplicationId);

#endif

