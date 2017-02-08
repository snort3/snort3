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

#include "appid_session.h"

class AppIdConfig;
class AppIdSession;
class Detector;
struct RNAServiceSubtype;
struct Packet;
struct DynamicPreprocessorData;

#define APPID_EARLY_SESSION_FLAG_FW_RULE    1

enum SERVICE_HOST_INFO_CODE
{
    SERVICE_HOST_INFO_NETBIOS_NAME = 1
};

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
    AppIdSession* asd;
    Packet* pkt;
    Detector* userdata;
    const AppIdConfig* pConfig;
    bool session_logging_enabled;
    char* session_logging_id;
};

using RNAServiceValidationFCN = int(*)(ServiceValidationArgs*);

struct InitServiceAPI;
using RNAServiceValidationInitFCN = int(*)(const InitServiceAPI* const);
using RNAServiceValidationCleanFCN = void(*)();

struct RNAServiceValidationPort;
struct RNAServiceValidationModule;
struct InitServiceAPI
{
    void (*RegisterPattern)( RNAServiceValidationFCN, IpProtocol proto, const uint8_t* pattern,
        unsigned size, int position, const char* name);
    int (*AddPort)( const RNAServiceValidationPort*, RNAServiceValidationModule*);
    void (*RemovePorts)(RNAServiceValidationFCN);
    void (*RegisterPatternUser)(RNAServiceValidationFCN, IpProtocol proto,
            const uint8_t* pattern, unsigned size, int position, const char* name);
    void (*RegisterAppId)( RNAServiceValidationFCN, AppId, uint32_t additionalInfo);
};

struct RNAServiceElement
{
    RNAServiceElement* next;
    RNAServiceValidationFCN validate;
    Detector* userdata;
    unsigned detectorType;
    unsigned ref_count;
    unsigned current_ref_count;
    int provides_user;
    const char* name;

    void init()
    {
        next = nullptr;
        name = nullptr;
        validate = nullptr;
        userdata = nullptr;
        provides_user = 0;
        detectorType = DETECTOR_TYPE_NOT_SET;
        ref_count = 0;
        current_ref_count = 0;
    }

    void init(const char* service_name, RNAServiceValidationFCN fcn, Detector* ud,
        int has_user, unsigned type)
    {
        next = nullptr;
        name = service_name;
        validate = fcn;
        userdata = ud;
        provides_user = has_user;
        detectorType = type;
        ref_count = 0;
        current_ref_count = 0;
    }
};

typedef void* (*ServiceFlowdataGet)(AppIdSession*, unsigned);
typedef int (*ServiceFlowdataAdd)(AppIdSession*, void*, unsigned, AppIdFreeFCN);
typedef int (*ServiceFlowdataAddDHCP)(AppIdSession*, unsigned, const uint8_t*, unsigned, const
    uint8_t*, const uint8_t*);
typedef void (*ServiceDhcpNewLease)(AppIdSession* flow, const uint8_t* mac, uint32_t ip, int32_t
    zone,  uint32_t subnetmask, uint32_t leaseSecs, uint32_t router);
typedef void (*ServiceAnalyzeFP)(AppIdSession*, unsigned, unsigned, uint32_t);

typedef int (*AddService)(AppIdSession* flow, const Packet* pkt, int dir,
		const RNAServiceElement* svc_element, AppId service, const char* vendor,
		const char* version, const RNAServiceSubtype* subtype);
typedef int (*AddServiceConsumeSubtype)(AppIdSession* flow, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element, AppId service, const char* vendor, const char* version,
    RNAServiceSubtype* subtype);
typedef int (*ServiceInProcess)(AppIdSession* flow, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element);
typedef int (*FailService)(AppIdSession* flow, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element, unsigned flow_data_index);
typedef int (*IncompatibleData)(AppIdSession* flow, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element, unsigned flow_data_index, const AppIdConfig*);
typedef void (*AddHostInfo)(AppIdSession* flow, SERVICE_HOST_INFO_CODE code, const void* info);
typedef void (*AddPayload)(AppIdSession*, AppId);
typedef void (*AddUser)(AppIdSession*, const char*, AppId, int);
typedef void (*AddMisc)(AppIdSession*, AppId);
typedef void (*AddDnsQueryInfo)(AppIdSession* flow,  uint16_t id, const uint8_t* host,
		uint8_t host_len, uint16_t host_offset, uint16_t record_type);
typedef void (*AddDnsResponseInfo)(AppIdSession* flow, uint16_t id, const uint8_t* host,
		uint8_t host_len, uint16_t host_offset, uint8_t response_type, uint32_t ttl);
typedef void (*ResetDnsInfo)(AppIdSession* flow);

struct ServiceApi
{
    ServiceFlowdataGet data_get;
    ServiceFlowdataAdd data_add;
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
    const RNAServiceValidationPort* pp;
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
