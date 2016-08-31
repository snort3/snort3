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

// appid_api.h author Sourcefire Inc.

#ifndef APPID_API_H
#define APPID_API_H

#include <cstdint>

#include "flow/flow.h"

enum class IpProtocol : uint8_t;

#define APP_MAPPING_FILE "appMapping.data"
#define APP_CONFIG_FILE "appid.conf"
#define USR_CONFIG_FILE "userappid.conf"

#define APPID_SESSION_RESPONDER_MONITORED   (1ULL << 0)
#define APPID_SESSION_INITIATOR_MONITORED   (1ULL << 1)
#define APPID_SESSION_SPECIAL_MONITORED     (1ULL << 2)
#define APPID_SESSION_INITIATOR_SEEN        (1ULL << 3)
#define APPID_SESSION_RESPONDER_SEEN        (1ULL << 4)
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
    /**Finsihed with client app detection */
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
#define APPID_SESSION_IGNORE_FLOW_LOGGED    (1ULL << 40)
#define APPID_SESSION_OOO_LOGGED            (1ULL << 41)
#define APPID_SESSION_TPI_OOO_LOGGED        (1ULL << 42)
#define APPID_SESSION_EXPECTED_EVALUATE     (1ULL << 43)
#define APPID_SESSION_IGNORE_ID_FLAGS       (APPID_SESSION_IGNORE_FLOW | \
                                             APPID_SESSION_NOT_A_SERVICE | \
                                             APPID_SESSION_NO_TPI | \
                                             APPID_SESSION_SERVICE_DETECTED | \
                                             APPID_SESSION_PORT_SERVICE_DONE)
class AppIdSession;

enum APPID_FLOW_TYPE
{
    APPID_FLOW_TYPE_IGNORE,
    APPID_FLOW_TYPE_NORMAL,
    APPID_FLOW_TYPE_TMP
};

struct RNAServiceSubtype
{
    RNAServiceSubtype *next;
    const char *service;
    const char *vendor;
    const char *version;
};

#define DHCP_OP55_MAX_SIZE  64
#define DHCP_OP60_MAX_SIZE  64

struct DhcpFPData
{
    DhcpFPData *next;
    unsigned op55_len;
    unsigned op60_len;
    uint8_t op55[DHCP_OP55_MAX_SIZE];
    uint8_t op60[DHCP_OP60_MAX_SIZE];
    // FIXIT-L J should be using eth address type here
    uint8_t mac[6];
} ;

// FIXIT-L J inconsistently named structs (DHCPInfo vs DhcpFPData, note the "DHCP")
struct DHCPInfo
{
    DHCPInfo *next;
    uint32_t ipAddr;
    // FIXIT-L J should be using eth address type here
    // FIXIT-L J inconsistently named fields (macAddr here, mac in DhcpFPData)
    uint8_t  macAddr[6];
    uint32_t subnetmask;
    uint32_t leaseSecs;
    uint32_t router;
};

struct FpSMBData
{
    FpSMBData *next;
    unsigned major;
    unsigned minor;
    uint32_t flags;
};

//maximum number of appIds replicated for a flow/session
#define APPID_HA_SESSION_APP_NUM_MAX 8

struct AppIdSessionHA
{
    uint16_t flags;
    AppId appId[APPID_HA_SESSION_APP_NUM_MAX];
};

enum SEARCH_SUPPORT_TYPE
{
    // FIXIT-L J enums are inconsistently named
    NOT_A_SEARCH_ENGINE,
    SUPPORTED_SEARCH_ENGINE,
    UNSUPPORTED_SEARCH_ENGINE,
    SEARCH_SUPPORT_TYPE_UNKNOWN,
};

// FIXIT-M J probable duplication from new http_inspect
enum HTTP_FIELD_ID
{
    REQ_AGENT_FID       = 0,
    REQ_HOST_FID        = 1,
    REQ_REFERER_FID     = 2,
    REQ_URI_FID         = 3,
    REQ_COOKIE_FID      = 4,
    REQ_BODY_FID        = 5,
    RSP_CONTENT_TYPE_FID = 6,
    RSP_LOCATION_FID    = 7,
    RSP_BODY_FID        = 8,
    HTTP_FIELD_MAX      = RSP_BODY_FID
};

// -----------------------------------------------------------------------------
// AppId API
// -----------------------------------------------------------------------------

struct sfip_t;

class SO_PUBLIC AppIdApi
{
public:
    SO_PRIVATE AppIdApi() {}
    SO_PRIVATE ~AppIdApi() {}

    const char* get_application_name(int32_t app_id);
    AppId get_application_id(const char* appName);
    AppId get_service_app_id(AppIdSession*);
    AppId get_port_service_app_id(AppIdSession*);
    AppId get_only_service_app_id(AppIdSession*);
    AppId get_misc_app_id(AppIdSession*);
    AppId get_client_app_id(AppIdSession*);
    AppId get_payload_app_id(AppIdSession*);
    AppId get_referred_app_id(AppIdSession*);
    AppId get_fw_service_app_id(AppIdSession*);
    AppId get_fw_misc_app_id(AppIdSession*);
    AppId get_fw_client_app_id(AppIdSession*);
    AppId get_fw_payload_app_id(AppIdSession*);
    AppId get_fw_referred_app_id(AppIdSession*);
    bool is_ssl_session_decrypted(AppIdSession*);
    bool is_appid_inspecting_session(AppIdSession*);
    bool is_appid_available(AppIdSession*);
    char* get_user_name(AppIdSession*, AppId* service, bool* isLoginSuccessful);
    char* get_client_version(AppIdSession*);
    uint64_t get_appid_session_attribute(AppIdSession*, uint64_t flag);
    APPID_FLOW_TYPE get_flow_type(AppIdSession*);
    void get_service_info(AppIdSession*, char **serviceVendor, char** serviceVersion, RNAServiceSubtype** subtype);
    short get_service_port(AppIdSession*);
    sfip_t* get_service_ip(AppIdSession*);
    sfip_t* get_initiator_ip(AppIdSession*);
    char* get_http_user_agent(AppIdSession*);
    char* get_http_host(AppIdSession*);
    char* get_http_url(AppIdSession*);
    char* get_http_referer(AppIdSession*);
    char* get_http_new_url(AppIdSession*);
    char* get_http_uri(AppIdSession*);
    char* get_http_response_code(AppIdSession*);
    char* get_http_cookie(AppIdSession*);
    char* get_http_new_cookie(AppIdSession*);
    char* get_http_content_type(AppIdSession*);
    char* get_http_location(AppIdSession*);
    char* get_http_body(AppIdSession*);
    char* get_http_request_body(AppIdSession*);
    uint16_t get_http_uri_offset(AppIdSession*);
    uint16_t get_http_uri_end_offset(AppIdSession*);
    uint16_t get_http_cookie_offset(AppIdSession*);
    uint16_t get_http_cookie_end_offset(AppIdSession*);
    SEARCH_SUPPORT_TYPE get_http_search(AppIdSession*);
    sfip_t* get_http_xff_addr(AppIdSession*);
    char* get_tls_host(AppIdSession*);
    DhcpFPData* get_dhcp_fp_data(AppIdSession*);
    void free_dhcp_fp_data(AppIdSession*, DhcpFPData*);
    DHCPInfo* get_dhcp_info(AppIdSession*);
    void free_dhcp_info(AppIdSession*, DHCPInfo*);
    FpSMBData* get_smb_fp_data(AppIdSession*);
    void free_smb_fp_data(AppIdSession*, FpSMBData*);
    char* get_netbios_name(AppIdSession*);
    uint32_t produce_ha_state(void* lwssn, uint8_t* buf);
    uint32_t consume_ha_state(void* lwssn, const uint8_t* buf, uint8_t length, IpProtocol proto, sfip_t* ip);
    AppIdSession* get_appid_data(Flow* flow);
    char* get_dns_query(AppIdSession*, uint8_t* query_len);
    uint16_t get_dns_query_offset(AppIdSession*);
    uint16_t get_dns_record_type(AppIdSession*);
    uint8_t get_dns_response_type(AppIdSession*);
    uint32_t get_dns_ttl(AppIdSession*);
    char* get_http_new_field(AppIdSession*, HTTP_FIELD_ID);
    void free_http_new_field(AppIdSession*, HTTP_FIELD_ID);
};

SO_PUBLIC extern AppIdApi appid_api;

#endif
