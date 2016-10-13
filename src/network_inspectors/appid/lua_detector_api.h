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

#include <cstdint>
#include <string>

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

struct Detector
{
    ~Detector();

    bool isCustom;          // true for customer created detectors
    bool isActive;
    bool wasActive;

    struct
    {
        const uint8_t* data;
        uint16_t size;
        int dir;
        AppIdSession* asd;
        Packet* pkt;
        uint8_t macAddress[6];
    } validateParams;

    struct
    {
        unsigned int serviceId;
        RNAServiceValidationModule serviceModule;
        RNAServiceElement* pServiceElement;
    } server;

    struct
    {
        unsigned int appFpId;
        RNAClientAppModule appModule;
    } client;

    AppIdSession* pFlow;
    lua_State* myLuaState;
    int detectorUserDataRef;    // key into LUA_REGISTRYINDEX
    std::string name;
    DetectorPackageInfo packageInfo;
    unsigned detector_version;
    char* validatorBuffer;
    unsigned char digest[16];
    AppIdConfig* appid_config;
};

int Detector_register(lua_State*);
void Detector_fini(void* detector);
void detectorRemoveAllPorts(Detector*);
Detector* createDetector(lua_State*, const char* filename);
CLIENT_APP_RETCODE validateAnyClientApp(const uint8_t* data, uint16_t size, const int dir,
    AppIdSession*, Packet*, Detector*);
int Detector_addSSLCertPattern(lua_State*);
int Detector_addDNSHostPattern(lua_State*);
int Detector_addHttpPattern(lua_State*);
int validateAnyService(ServiceValidationArgs*);
int checkServiceElement(Detector*);
int init_CHP_glossary();
void free_CHP_glossary();

#endif
