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

#include "appid_api.h"
#include "appid_session.h"
#include "service_api.h"

class AppIdConfig;
class AppIdSession;
struct RNAServiceElement;
struct DHCPData;
struct FpSMBData;
struct Packet;
struct ServiceMatch;
class Detector;
struct RNAServiceValidationPort;
struct RNAServiceValidationModule;

void init_service_plugins();
void finalize_service_patterns();

void clean_service_plugins();
void UnconfigureServices();
void ServiceFinalize();
void FailInProcessService(AppIdSession*, const AppIdConfig*);

int serviceLoadCallback(void* symbol);
int ServiceAddPort(const RNAServiceValidationPort*, RNAServiceValidationModule*, Detector*);
void ServiceRemovePorts(RNAServiceValidationFCN, Detector*);
void ServiceRegisterPatternDetector(RNAServiceValidationFCN, IpProtocol proto,
        const uint8_t* pattern, unsigned size, int position, Detector*, const char* name);
int AppIdDiscoverService(Packet*, int direction, AppIdSession*);
AppId getPortServiceId(IpProtocol proto, uint16_t port, const AppIdConfig*);
void AppIdFreeServiceIDState(AppIdServiceIDState*);
int AppIdServiceAddService(AppIdSession*, const Packet*, int dir, const RNAServiceElement*,
    AppId appId, const char* vendor, const char* version, const RNAServiceSubtype*);
int AppIdServiceAddServiceSubtype(AppIdSession*, const Packet*, int dir, const RNAServiceElement*,
        AppId, const char* vendor, const char* version, RNAServiceSubtype*);
int AppIdServiceInProcess(AppIdSession*, const Packet*, int dir, const RNAServiceElement*);
int AppIdServiceIncompatibleData(AppIdSession*, const Packet*, int dir, const RNAServiceElement*,
    unsigned flow_data_index, const AppIdConfig*);
int AppIdServiceFailService(AppIdSession*, const Packet*, int dir, const RNAServiceElement*,
    unsigned flow_data_index);
int AddFTPServiceState(AppIdSession*);
void AppIdFreeDhcpInfo(DHCPInfo*);
void AppIdFreeSMBData(FpSMBData*);
void AppIdFreeDhcpData(DHCPData*);
void dumpPorts(FILE*);
const RNAServiceElement* get_service_element(RNAServiceValidationFCN, Detector*);
void add_service_to_active_list(RNAServiceValidationModule* service);
extern uint32_t app_id_instance_id;

void free_service_match_list(ServiceMatch* sm);

inline bool compareServiceElements(const RNAServiceElement* first,
        const RNAServiceElement* second)
{
    if (first == second)
        return 0;
    if (first == nullptr || second == nullptr)
        return 1;
    return (first->validate != second->validate || first->userdata != second->userdata);
}

inline uint32_t get_service_detect_level(AppIdSession* asd)
{
    if (asd->get_session_flags(APPID_SESSION_DECRYPTED))
        return 1;
    return 0;
}

inline void PopulateExpectedFlow(AppIdSession* parent, AppIdSession* expected, uint64_t flags)
{
    expected->set_session_flags(flags |
        parent->get_session_flags(APPID_SESSION_RESPONDER_MONITORED |
                APPID_SESSION_INITIATOR_MONITORED |
                APPID_SESSION_SPECIAL_MONITORED |
                APPID_SESSION_RESPONDER_CHECKED |
                APPID_SESSION_INITIATOR_CHECKED |
                APPID_SESSION_DISCOVER_APP |
                APPID_SESSION_DISCOVER_USER));
    expected->rnaServiceState = RNA_STATE_FINISHED;
    expected->rna_client_state = RNA_STATE_FINISHED;
}

#endif
