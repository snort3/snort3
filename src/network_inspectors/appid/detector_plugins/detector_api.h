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

// detector_api.h author Sourcefire Inc.

#ifndef DETECTOR_API_H
#define DETECTOR_API_H

#include "appid_flow_data.h"

struct RNAServiceValidationModule;
struct RNAClientAppModule;
struct StreamAPI;

using DetectorFlowdataGet = void*(*)(AppIdData*, unsigned);
using DetectorFlowdataAdd = int(*)(AppIdData*, void*, unsigned, AppIdFreeFCN);

struct DetectorApi
{
    DetectorFlowdataGet data_get;
    DetectorFlowdataAdd data_add;
};

// compound detector with both service and client side.
struct RNADetectorValidationModule
{
    /**service side.*/
    RNAServiceValidationModule* service;

    /**client side.*/
    RNAClientAppModule* client;

    const DetectorApi* api;
    unsigned flow_data_index;
    StreamAPI* streamAPI;
};

#endif
