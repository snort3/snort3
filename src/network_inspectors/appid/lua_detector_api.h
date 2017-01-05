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

// lua_detector_api.h author Sourcefire Inc.

#ifndef LUA_DETECTOR_API_H
#define LUA_DETECTOR_API_H

// This module supports basic API towards Lua detectors.

#include "client_plugins/client_app_api.h"
#include "service_plugins/service_api.h"

struct Packet;
struct ProfileStats;
struct ServiceValidationArgs;
struct lua_State;
class AppIdConfig;
class AppIdSession;
struct RNAServiceElement;

#define DETECTOR "Detector"
#define DETECTORFLOW "DetectorFlow"

struct DetectorPackageInfo
{
    struct UniInfo
    {
        std::string initFunctionName;
        std::string cleanFunctionName;
        std::string validateFunctionName;
        int minimum_matches = 0;
    };

    std::string name = "NoName";
    IpProtocol proto;

    UniInfo client;
    UniInfo server;
};

struct ValidateParameters
{
    const uint8_t* data = nullptr;
    uint16_t size = 0;
    int dir = 0;
    AppIdSession* asd = nullptr;
    Packet* pkt = nullptr;
    uint8_t macAddress[6] = {0};
};

struct ServerDetectorState
{
    unsigned int serviceId = APP_ID_UNKNOWN;
    RNAServiceValidationModule serviceModule;
    RNAServiceElement* pServiceElement = nullptr;
};

struct ClientDetectorState
{
    unsigned int appFpId;
    RNAClientAppModule appModule;
};

class Detector
{
public:
    Detector(AppIdConfig* config);
    ~Detector();

    bool isCustom = false;
    bool isActive = false;
    bool wasActive = false;
    ValidateParameters validateParams;
    ServerDetectorState server;
    ClientDetectorState client;
    AppIdSession* pFlow = nullptr;
    lua_State* myLuaState= nullptr;
    int detectorUserDataRef = 0;    // key into LUA_REGISTRYINDEX
    std::string name;
    DetectorPackageInfo packageInfo;
    unsigned detector_version = 0;
    AppIdConfig* appid_config = nullptr;
};

int register_detector(lua_State*);
void remove_detector(void* detector);
CLIENT_APP_RETCODE validate_client_application(const uint8_t* data, uint16_t size, const int dir,
    AppIdSession*, Packet*, Detector*);
int validate_service_application(ServiceValidationArgs*);
int check_service_element(Detector*);
int init_chp_glossary();
void free_chp_glossary();

#endif
