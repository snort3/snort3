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

// client_app_api.h author Sourcefire Inc.

#ifndef CLIENT_APP_API_H
#define CLIENT_APP_API_H

#include <cstdint>

#include "appid_api.h"
#include "appid_flow_data.h"

struct Packet;
struct Detector;

// Forward declaration for AppId config. Cannot include appIdConfig.h because of
// circular dependency
class AppIdConfig;

enum CLIENT_APP_RETCODE
{
    CLIENT_APP_SUCCESS = 0,
    CLIENT_APP_INPROCESS = 10,
    CLIENT_APP_ENULL = -10,
    CLIENT_APP_EINVALID = -11,
    CLIENT_APP_ENOMEM = -12
};

struct RNAClientAppModuleConfig
{
    const char* name;
    SF_LIST items;
};

struct RNAClientAppModuleConfigItem
{
    const char* name;
    const char* value;
};

using RNAClientAppFCN = CLIENT_APP_RETCODE(*)(
    const uint8_t* data,
    uint16_t size,
    const int dir,
    AppIdData*,
    Packet*,
    Detector*,
    const AppIdConfig*
);

struct IniClientAppAPI
{
    void (* RegisterPattern)(
        RNAClientAppFCN, IpProtocol proto, const uint8_t* const pattern,
        unsigned size, int position, AppIdConfig*);

    void (* RegisterPatternEx)(
        RNAClientAppFCN, IpProtocol proto, const uint8_t* const pattern,
        unsigned size, int position, Detector*);

    void (* RegisterPatternNoCase)(
        RNAClientAppFCN, IpProtocol proto, const uint8_t* const pattern,
        unsigned size, int position, AppIdConfig*);

    void (* RegisterAppId)(
        RNAClientAppFCN, AppId, uint32_t additionalInfo, AppIdConfig*);

    int debug;
    uint32_t instance_id;
    AppIdConfig* pAppidConfig;  ///< AppId context for which this API should be used
};

struct CleanClientAppAPI
{
    AppIdConfig* pAppidConfig = nullptr;  ///< AppId context for which this API should be used
};

struct FinalizeClientAppAPI
{
    void* data = nullptr;
};

using RNAClientAppInitFCN = CLIENT_APP_RETCODE(*)(const IniClientAppAPI* const, SF_LIST* config);
using RNAClientAppFinalizeFCN = CLIENT_APP_RETCODE (*)(const FinalizeClientAppAPI* const);
using RNAClientAppCleanFCN = void(*)(const CleanClientAppAPI* const);

using ClientAppFlowdataGet = void*(*)(AppIdData*, unsigned);
using ClientAppFlowdataAdd = int(*)(AppIdData*, void*, unsigned, AppIdFreeFCN);
using ClientAppAddApp = void(*)(AppIdData*, AppId, AppId, const char*);
using ClientAppAddInfo = void(*)(AppIdData*, const char*);
using ClientAppAddUser = void(*)(AppIdData*, const char*, AppId, int);
using ClientAppAddPayload = void(*)(AppIdData*, AppId);

struct ClientAppApi
{
    ClientAppFlowdataGet data_get;
    ClientAppFlowdataAdd data_add;
    ClientAppAddApp add_app;
    ClientAppAddInfo add_info;
    ClientAppAddUser add_user;
    ClientAppAddPayload add_payload;
};

struct RNAClientAppRecord
{
    RNAClientAppRecord* next;
    const struct RNAClientAppModule* module;
};

struct RNAClientAppModule
{
    const char* name;
    IpProtocol proto;
    RNAClientAppInitFCN init;
    RNAClientAppCleanFCN clean;
    RNAClientAppFCN validate;
    unsigned minimum_matches;
    const ClientAppApi* api;
    Detector* userData;

    /**precedence of this detector.*/
    unsigned int precedence;
    RNAClientAppFinalizeFCN finalize;

    int provides_user;
    unsigned flow_data_index;
};

struct RNAClientAppFlowState
{
    RNAClientAppFlowState* next;
    const RNAClientAppModule* ca;
};

#endif
