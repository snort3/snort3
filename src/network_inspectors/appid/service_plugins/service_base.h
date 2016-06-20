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

// service_base.h author Sourcefire Inc.

#ifndef SERVICE_BASE_H
#define SERVICE_BASE_H

#include <cstdint>

#include "appid_api.h"
#include "appid_flow_data.h"
#include "service_api.h"
#include "sfip/sf_ip.h"

class AppIdConfig;
class AppIdData;
struct RNAServiceElement;
struct DhcpFPData;
struct FpSMBData;
struct Packet;
struct ServiceMatch;
struct Detector;
struct RNAServiceValidationPort;
struct RNAServiceValidationModule;

void CleanupServices(AppIdConfig*);
void ReconfigureServices(AppIdConfig*);
void UnconfigureServices(AppIdConfig*);
void ServiceInit(AppIdConfig*);
void ServiceFinalize(AppIdConfig*);
void FailInProcessService(AppIdData*, const AppIdConfig*);
int LoadServiceModules(const char** dir_list, uint32_t instance_id, AppIdConfig*);

// This function is called during reload/reconfiguration. It registers service ports in the given
// AppId configuration. This function also takes care of services associated with detector modules.
int ReloadServiceModules(AppIdConfig*);

int serviceLoadCallback(void* symbol);
int serviceLoadForConfigCallback(void* symbol, AppIdConfig*);
int ServiceAddPort(
    RNAServiceValidationPort*, RNAServiceValidationModule*, Detector*, AppIdConfig*);
void ServiceRemovePorts(RNAServiceValidationFCN, Detector*, AppIdConfig*);
void ServiceRegisterPatternDetector(
    RNAServiceValidationFCN, IpProtocol proto, const uint8_t* pattern,
    unsigned size, int position, Detector*, const char* name);
int AppIdDiscoverService(
    Packet*, int direction, AppIdData*, const AppIdConfig*);
AppId getPortServiceId(IpProtocol proto, uint16_t port, const AppIdConfig*);

void AppIdFreeServiceIDState(AppIdServiceIDState*);

int AppIdServiceAddService(
    AppIdData*, const Packet*, int dir, const RNAServiceElement*,
    AppId appId, const char* vendor, const char* version, const RNAServiceSubtype*);

int AppIdServiceAddServiceSubtype(
    AppIdData*, const Packet*, int dir, const RNAServiceElement*, AppId,
    const char* vendor, const char* version, RNAServiceSubtype*);

int AppIdServiceInProcess(
    AppIdData*, const Packet*, int dir, const RNAServiceElement*);

int AppIdServiceIncompatibleData(
    AppIdData*, const Packet*, int dir, const RNAServiceElement*,
    unsigned flow_data_index, const AppIdConfig*);

int AppIdServiceFailService(
    AppIdData*, const Packet*, int dir, const RNAServiceElement*,
    unsigned flow_data_index, const AppIdConfig*);

int AddFTPServiceState(AppIdData*);
void AppIdFreeDhcpInfo(DHCPInfo*);
void AppIdFreeSMBData(FpSMBData*);
void AppIdFreeDhcpData(DhcpFPData*);

void dumpPorts(FILE*, const AppIdConfig*);

const RNAServiceElement* ServiceGetServiceElement(
    RNAServiceValidationFCN, Detector*, AppIdConfig*);

extern RNAServiceValidationModule* active_service_list;

extern uint32_t app_id_instance_id;

void cleanupFreeServiceMatch();
void AppIdFreeServiceMatchList(ServiceMatch* sm);

inline bool compareServiceElements(
    const RNAServiceElement* first, const RNAServiceElement* second)
{
    if (first == second)
        return 0;
    if (first == nullptr || second == nullptr)
        return 1;
    return (first->validate != second->validate || first->userdata != second->userdata);
}

inline uint32_t AppIdServiceDetectionLevel(AppIdData* session)
{
    if (getAppIdFlag(session, APPID_SESSION_DECRYPTED))
        return 1;
    return 0;
}

inline void PopulateExpectedFlow(AppIdData* parent, AppIdData* expected, uint64_t flags)
{
    setAppIdFlag(expected, flags |
        getAppIdFlag(parent,
        APPID_SESSION_RESPONDER_MONITORED |
        APPID_SESSION_INITIATOR_MONITORED |
        APPID_SESSION_SPECIAL_MONITORED |
        APPID_SESSION_RESPONDER_CHECKED |
        APPID_SESSION_INITIATOR_CHECKED |
        APPID_SESSION_DISCOVER_APP |
        APPID_SESSION_DISCOVER_USER));
    expected->rnaServiceState = RNA_STATE_FINISHED;
    expected->rnaClientState = RNA_STATE_FINISHED;
}

#endif
