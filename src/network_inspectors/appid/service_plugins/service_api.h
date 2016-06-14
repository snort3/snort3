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

// service_api.h author Sourcefire Inc.

#ifndef SERVICE_API_H
#define SERVICE_API_H

#include "appid_flow_data.h"

class AppIdConfig;
class AppIdData;
struct Detector;
struct RNAServiceSubtype;
struct Packet;
struct DynamicPreprocessorData;

enum SERVICE_RETCODE
{
    SERVICE_SUCCESS = 0,
    SERVICE_INPROCESS = 10,
    SERVICE_NEED_REASSEMBLY = 11,
    SERVICE_NOT_COMPATIBLE = 12,
    SERVICE_INVALID_CLIENT = 13,
    SERVICE_REVERSED = 14,
    SERVICE_NOMATCH = 100,
    SERVICE_ENULL = -10,
    SERVICE_EINVALID = -11,
    SERVICE_ENOMEM = -12
};

struct ServiceValidationArgs
{
    const uint8_t* data;
    uint16_t size;
    int dir;
    AppIdData* flowp;
    Packet* pkt;
    struct Detector* userdata;
    const AppIdConfig* pConfig;
    bool app_id_debug_session_flag;
    char* app_id_debug_session;
};

using RNAServiceValidationFCN = int(*)(ServiceValidationArgs*);

#define MakeRNAServiceValidationPrototype(name) static int name(ServiceValidationArgs* args)

struct CleanServiceAPI
{
    AppIdConfig* pAppidConfig;  ///< AppId context for which this API should be used
};

struct IniServiceAPI;
using RNAServiceValidationInitFCN = int(*)(const IniServiceAPI* const);
using RNAServiceValidationCleanFCN = void(*)(const CleanServiceAPI* const);

struct RNAServiceValidationPort;
struct RNAServiceValidationModule;
struct IniServiceAPI
{
    void (* RegisterPattern)(
        RNAServiceValidationFCN, IpProtocol proto, const uint8_t* pattern,
        unsigned size, int position, const char* name, AppIdConfig*);

    int (* AddPort)(
        RNAServiceValidationPort*, RNAServiceValidationModule*, AppIdConfig*);

    void (* RemovePorts)(RNAServiceValidationFCN, AppIdConfig*);
    void (* RegisterPatternUser)(
        RNAServiceValidationFCN, IpProtocol proto, const uint8_t* pattern,
        unsigned size, int position, const char* name, AppIdConfig*);

    void (* RegisterAppId)(
        RNAServiceValidationFCN, AppId, uint32_t additionalInfo, AppIdConfig*);

    int debug;
    uint32_t instance_id;
    AppIdConfig* pAppidConfig;  ///< AppId context for which this API should be used
};

struct RNAServicePerf
{
    /*time to validate */
    uint64_t totalValidateTime;
};

struct RNAServiceElement
{
    RNAServiceElement* next;
    RNAServiceValidationFCN validate;
    // Value of userdata pointer and validate pointer forms key for comparison.
    Detector* userdata;

    /**type of detector - pattern based, Sourcefire (validator) or User (Validator). */
    unsigned detectorType;

    /**Number of resources registered */
    unsigned ref_count;
    unsigned current_ref_count;
    int provides_user;
    const char* name;
};

typedef void*(* ServiceFlowdataGet)(AppIdData*, unsigned);
typedef int (* ServiceFlowdataAdd)(AppIdData*, void*, unsigned, AppIdFreeFCN);
typedef int (* ServiceFlowdataAddId)(AppIdData*, uint16_t, const RNAServiceElement* const);
typedef int (* ServiceFlowdataAddDHCP)(AppIdData*, unsigned, const uint8_t*, unsigned, const
    uint8_t*, const uint8_t*);
#define APPID_EARLY_SESSION_FLAG_FW_RULE    1
typedef AppIdData*(* ServiceCreateNewFlow)(AppIdData* flowp, const Packet*, const sfip_t*, uint16_t,
    const sfip_t*, uint16_t, IpProtocol, int16_t, int flags);
typedef void (* ServiceDhcpNewLease)(AppIdData* flow, const uint8_t* mac, uint32_t ip, int32_t
    zone,  uint32_t subnetmask, uint32_t leaseSecs, uint32_t router);
typedef void (* ServiceAnalyzeFP)(AppIdData*, unsigned, unsigned, uint32_t);

typedef int (* AddService)(AppIdData* flow, const Packet* pkt, int dir,
		const RNAServiceElement* svc_element, AppId service, const char* vendor,
		const char* version, const RNAServiceSubtype* subtype);
typedef int (* AddServiceConsumeSubtype)(AppIdData* flow, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element, AppId service, const char* vendor, const char* version,
    RNAServiceSubtype* subtype);
typedef int (* ServiceInProcess)(AppIdData* flow, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element);
typedef int (* FailService)(AppIdData* flow, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element, unsigned flow_data_index, const AppIdConfig* pConfig);
typedef int (* IncompatibleData)(AppIdData* flow, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element, unsigned flow_data_index, const AppIdConfig*);
typedef void (* AddHostInfo)(AppIdData* flow, SERVICE_HOST_INFO_CODE code, const void* info);
typedef void (* AddPayload)(AppIdData*, AppId);
typedef void (* AddUser)(AppIdData*, const char*, AppId, int);
typedef void (* AddMisc)(AppIdData*, AppId);
typedef void (* AddDnsQueryInfo)(AppIdData* flow,  uint16_t id, const uint8_t* host,
		uint8_t host_len, uint16_t host_offset, uint16_t record_type);
typedef void (* AddDnsResponseInfo)(AppIdData* flow, uint16_t id, const uint8_t* host,
		uint8_t host_len, uint16_t host_offset, uint8_t response_type, uint32_t ttl);
typedef void (* ResetDnsInfo)(AppIdData* flow);

struct ServiceApi
{
    ServiceFlowdataGet data_get;
    ServiceFlowdataAdd data_add;
    ServiceCreateNewFlow flow_new;
    ServiceFlowdataAddId data_add_id;
    ServiceFlowdataAddDHCP data_add_dhcp;
    ServiceDhcpNewLease dhcpNewLease;
    ServiceAnalyzeFP analyzefp;
    AddService add_service;
    FailService fail_service;
    ServiceInProcess service_inprocess;
    IncompatibleData incompatible_data;
    AddHostInfo add_host_info;
    AddPayload add_payload;
    AddUser add_user;
    AddServiceConsumeSubtype add_service_consume_subtype;
    AddMisc add_misc;
    AddDnsQueryInfo add_dns_query_info;
    AddDnsResponseInfo add_dns_response_info;
    ResetDnsInfo reset_dns_info;
};

struct RNAFlowState
{
    RNAFlowState* next;
    const RNAServiceElement* svc;
    uint16_t port;
};

struct RNAServiceValidationPort
{
    RNAServiceValidationFCN validate;
    uint16_t port;
    IpProtocol proto;
    uint8_t reversed_validation;
};

struct RNAServiceValidationModule
{
    const char* name;
    RNAServiceValidationInitFCN init;
    RNAServiceValidationPort* pp;
    const ServiceApi* api;
    RNAServiceValidationModule* next;
    int provides_user;
    RNAServiceValidationCleanFCN clean;
    unsigned flow_data_index;
};

#if defined(WORDS_BIGENDIAN)
#define LETOHS(p)   BYTE_SWAP_16(*((uint16_t*)(p)))
#define LETOHL(p)   BYTE_SWAP_32(*((uint32_t*)(p)))
#else
#define LETOHS(p)   (*((uint16_t*)(p)))
#define LETOHL(p)   (*((uint32_t*)(p)))
#endif

#endif
