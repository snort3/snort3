//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// appid_session_api.h author Sourcefire Inc.

#ifndef APPID_SESSION_API_H
#define APPID_SESSION_API_H

#include "flow/flow.h"
#include "main/snort_types.h"
#include "sfip/sf_ip.h"
#include "application_ids.h"

class AppIdDnsSession;
class AppIdHttpSession;
class AppIdSession;

namespace snort
{
#define APPID_SESSION_RESPONDER_MONITORED   (1ULL << 0)
#define APPID_SESSION_INITIATOR_MONITORED   (1ULL << 1)
#define APPID_SESSION_SPECIAL_MONITORED     (1ULL << 2)
#define APPID_SESSION_IGNORE_FLOW_LOGGED    (1ULL << 3)
#define APPID_SESSION_EXPECTED_EVALUATE     (1ULL << 4)
#define APPID_SESSION_DISCOVER_USER         (1ULL << 5)
#define APPID_SESSION_HAS_DHCP_FP           (1ULL << 6)
#define APPID_SESSION_HAS_DHCP_INFO         (1ULL << 7)
#define APPID_SESSION_HAS_SMB_INFO          (1ULL << 8)
#define APPID_SESSION_MID                   (1ULL << 9)
#define APPID_SESSION_OOO                   (1ULL << 10)
#define APPID_SESSION_SYN_RST               (1ULL << 11)
/**Service missed the first UDP packet in a flow. This causes detectors to see traffic in reverse direction.
 * Detectors should set this flag by verifying that packet from initiator is indeed a packet from responder.
 * Setting this flag without this check will cause RNA to not try other detectors in some cases (see bug 77551).*/
#define APPID_SESSION_UDP_REVERSED          (1ULL << 12)
#define APPID_SESSION_HTTP_SESSION          (1ULL << 13)
/**Service protocol was detected */
#define APPID_SESSION_SERVICE_DETECTED      (1ULL << 14)
/**Finished with client app detection */
#define APPID_SESSION_CLIENT_DETECTED       (1ULL << 15)
/**Flow is a data connection not a service */
#define APPID_SESSION_NOT_A_SERVICE         (1ULL << 16)
#define APPID_SESSION_DECRYPTED             (1ULL << 17)
#define APPID_SESSION_SERVICE_DELETED       (1ULL << 18)
//The following attributes are references only with appId
/**Continue calling the routine after the service has been identified. */
#define APPID_SESSION_CONTINUE              (1ULL << 19)
/**Call service detection even if the host does not exist */
#define APPID_SESSION_IGNORE_HOST           (1ULL << 20)
/**Service protocol had incompatible client data */
#define APPID_SESSION_INCOMPATIBLE          (1ULL << 21)
/**we are ready to see out of network Server packets */
#define APPID_SESSION_CLIENT_GETS_SERVER_PACKETS    (1ULL << 22)
#define APPID_SESSION_DISCOVER_APP          (1ULL << 23)
#define APPID_SESSION_PORT_SERVICE_DONE     (1ULL << 24)
#define APPID_SESSION_ADDITIONAL_PACKET     (1ULL << 25)
#define APPID_SESSION_RESPONDER_CHECKED     (1ULL << 26)
#define APPID_SESSION_INITIATOR_CHECKED     (1ULL << 27)
#define APPID_SESSION_SSL_SESSION           (1ULL << 28)
#define APPID_SESSION_LOGIN_SUCCEEDED       (1ULL << 29)
#define APPID_SESSION_SPDY_SESSION          (1ULL << 30)
#define APPID_SESSION_ENCRYPTED             (1ULL << 31)
#define APPID_SESSION_APP_REINSPECT         (1ULL << 32)
#define APPID_SESSION_RESPONSE_CODE_CHECKED (1ULL << 33)
#define APPID_SESSION_REXEC_STDERR          (1ULL << 34)
#define APPID_SESSION_CHP_INSPECTING        (1ULL << 35)
#define APPID_SESSION_STICKY_SERVICE        (1ULL << 36)
#define APPID_SESSION_APP_REINSPECT_SSL     (1ULL << 37)
#define APPID_SESSION_NO_TPI                (1ULL << 38)
#define APPID_SESSION_IGNORE_FLOW           (1ULL << 39)
#define APPID_SESSION_IGNORE_FLOW_IDED      (1ULL << 40)
#define APPID_SESSION_IGNORE_ID_FLAGS \
    (APPID_SESSION_IGNORE_FLOW | \
    APPID_SESSION_NOT_A_SERVICE | \
    APPID_SESSION_NO_TPI | \
    APPID_SESSION_SERVICE_DETECTED | \
    APPID_SESSION_PORT_SERVICE_DONE)
const uint64_t APPID_SESSION_ALL_FLAGS = 0xFFFFFFFFFFFFFFFFULL;

enum APPID_FLOW_TYPE
{
    APPID_FLOW_TYPE_IGNORE,
    APPID_FLOW_TYPE_NORMAL,
    APPID_FLOW_TYPE_TMP
};

struct AppIdServiceSubtype
{
    AppIdServiceSubtype* next;
    const char* service;
    const char* vendor;
    const char* version;
};

#define DHCP_OP55_MAX_SIZE  64
#define DHCP_OP60_MAX_SIZE  64

struct DHCPData
{
    DHCPData* next;
    unsigned op55_len;
    unsigned op60_len;
    uint8_t op55[DHCP_OP55_MAX_SIZE];
    uint8_t op60[DHCP_OP60_MAX_SIZE];
    uint8_t eth_addr[6];
};

struct DHCPInfo
{
    DHCPInfo* next;
    uint32_t ipAddr;
    uint8_t eth_addr[6];
    uint32_t subnetmask;
    uint32_t leaseSecs;
    uint32_t router;
};

struct FpSMBData
{
    FpSMBData* next;
    unsigned major;
    unsigned minor;
    uint32_t flags;
};

enum SEARCH_SUPPORT_TYPE
{
    NOT_A_SEARCH_ENGINE,
    SUPPORTED_SEARCH_ENGINE,
    UNSUPPORTED_SEARCH_ENGINE,
    UNKNOWN_SEARCH_ENGINE,
};


class SO_PUBLIC AppIdSessionApi
{
public:
    AppIdSessionApi(AppIdSession* asd) : asd(asd) {}
    bool refresh(Flow& flow);
    AppId get_service_app_id();
    AppId get_port_service_app_id();
    AppId get_only_service_app_id();
    AppId get_misc_app_id();
    AppId get_client_app_id();
    AppId get_payload_app_id();
    AppId get_referred_app_id();
    void get_app_id(AppId& service, AppId& client, AppId& payload, AppId& misc, AppId& referred);
    void get_app_id(AppId* service, AppId* client, AppId* payload, AppId* misc, AppId* referred);
    bool is_ssl_session_decrypted();
    bool is_appid_inspecting_session();
    bool is_appid_available();
    const char* get_user_name(AppId* service, bool* isLoginSuccessful);
    const char* get_client_version();
    uint64_t get_appid_session_attribute(uint64_t flag);
    APPID_FLOW_TYPE get_flow_type();
    void get_service_info(const char** vendor, const char** version,
        AppIdServiceSubtype**);
    short get_service_port();
    SfIp* get_service_ip();
    SfIp* get_initiator_ip();
    AppIdDnsSession* get_dns_session();
    AppIdHttpSession* get_http_session();
    SEARCH_SUPPORT_TYPE get_http_search();
    char* get_tls_host();
    DHCPData* get_dhcp_fp_data();
    void free_dhcp_fp_data(DHCPData*);
    DHCPInfo* get_dhcp_info();
    void free_dhcp_info(DHCPInfo*);
    FpSMBData* get_smb_fp_data();
    void free_smb_fp_data(FpSMBData*);
    const char* get_netbios_name();
    bool is_http_inspection_done();

private:
    AppIdSession* asd;
};

}
#endif
