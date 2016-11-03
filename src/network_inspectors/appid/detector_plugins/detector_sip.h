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

// detector_sip.h author Sourcefire Inc.

#ifndef DETECTOR_SIP_H
#define DETECTOR_SIP_H

//  AppId structures for SIP detection

#include "appid_utils/sf_multi_mpse.h"
#include "detector_api.h"
#include "framework/data_bus.h"

struct RNAServiceValidationModule;

struct SipUaUserData
{
    AppId ClientAppId;
    char* clientVersion;
};

struct DetectorAppSipPattern
{
    tMlpPattern pattern;
    SipUaUserData userData;
    DetectorAppSipPattern* next;
};

extern struct RNAClientAppModule sip_udp_client_mod;
extern struct RNAClientAppModule sip_tcp_client_mod;
extern struct RNAServiceValidationModule sip_service_mod;

// FIXIT-M ServiceEventType enum needs to become real when SIP is supported
enum ServiceEventType {};

void SipSessionSnortCallback(void* ssnptr, ServiceEventType, void* eventData);
int sipUaPatternAdd( AppId, const char* clientVersion, const char* uaPattern);
int sipServerPatternAdd(AppId, const char* clientVersion, const char* uaPattern);
int finalize_sip_ua();

class SipEventHandler : public DataHandler
{
public:
    void handle(DataEvent&, Flow*);
};
#endif

