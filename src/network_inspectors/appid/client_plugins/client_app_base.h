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

// client_app_base.h author Sourcefire Inc.

#ifndef CLIENT_APP_BASE_H
#define CLIENT_APP_BASE_H

#include "appid_api.h"
#include "client_app_api.h"

#define GENERIC_APP_OFFSET 2000000000

class AppIdSession;
class AppIdConfig;
class Detector;
struct RNAClientAppModule;
struct Packet;
struct ClientAppApi;
struct RNAClientAppModuleConfig;

void init_client_plugins();
void finalize_client_plugins();
void UnconfigureClientApp(AppIdConfig*);
void clean_client_plugins();
int ClientAppLoadCallback(void* symbol);
int LoadClientAppModules();
void ClientAppRegisterPattern(RNAClientAppFCN, IpProtocol proto, const uint8_t* const pattern,
        unsigned size, int position, unsigned nocase, Detector*);
const ClientAppApi* getClientApi();
RNAClientAppModuleConfig* getClientAppModuleConfig(const char* moduleName);
int AppIdDiscoverClientApp(Packet* p, int direction, AppIdSession*);
void AppIdAddClientApp(AppIdSession*, AppId service_id, AppId id, const char* version);

const RNAClientAppModule* ClientAppGetClientAppModule(RNAClientAppFCN, Detector*);

#endif
