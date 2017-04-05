//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// appid_session.h author Sourcefire Inc.

#ifndef APPID_SESSION_H
#define APPID_SESSION_H

#include <map>
#include <string>

#include "appid_api.h"
#include "application_ids.h"
#include "length_app_cache.h"
#include "service_state.h"
#include "detector_plugins/http_url_patterns.h"

struct RNAServiceSubtype;
class ClientDetector;
class ServiceDetector;
class AppInfoManager;

using AppIdFreeFCN = void (*)(void*);

#define MAX_ATTR_LEN           1024
#define HTTP_PREFIX "http://"

#define SF_DEBUG_FILE   stdout

#define APPID_SESSION_DATA_NONE                  0
#define APPID_SESSION_DATA_DHCP_FP_DATA          2
#define APPID_SESSION_DATA_SMB_DATA              4
#define APPID_SESSION_DATA_DHCP_INFO             5
#define APPID_SESSION_DATA_SERVICE_MODSTATE_BIT  0x20000000
#define APPID_SESSION_DATA_CLIENT_MODSTATE_BIT   0x40000000
#define APPID_SESSION_DATA_DETECTOR_MODSTATE_BIT 0x80000000
#define APPID_SESSION_BIDIRECTIONAL_CHECKED \
    (APPID_SESSION_INITIATOR_CHECKED | \
    APPID_SESSION_RESPONDER_CHECKED)
#define APPID_SESSION_DO_RNA \
    (APPID_SESSION_RESPONDER_MONITORED | \
    APPID_SESSION_INITIATOR_MONITORED | APPID_SESSION_DISCOVER_USER | \
    APPID_SESSION_SPECIAL_MONITORED)

// flow status codes
enum AppIdFlowStatusCodes
{
    APPID_SESSION_SUCCESS = 0,
    APPID_SESSION_ENULL,
    APPID_SESSION_EINVALID,
    APPID_SESSION_ENOMEM,
    APPID_SESSION_NOTFOUND,
    APPID_SESSION_BADJUJU,
    APPID_SESSION_DISABLED,
    APPID_SESSION_EUNSUPPORTED,
    APPID_SESSION_STOP_PROCESSING,
    APPID_SESSION_EEXISTS
};

#define MAX_SESSION_LOGGING_ID_LEN    (39+1+5+4+39+1+5+1+3+1+1+1+2+1+10+1+1+1+10+1)

#define MIN_SFTP_PACKET_COUNT   30
#define MAX_SFTP_PACKET_COUNT   55

enum APPID_DISCOVERY_STATE
{
    APPID_DISCO_STATE_NONE = 0,
    APPID_DISCO_STATE_DIRECT,
    APPID_DISCO_STATE_STATEFUL,
    APPID_DISCO_STATE_FINISHED
};

enum APPID_SESSION_DIRECTION
{
    APP_ID_FROM_INITIATOR,
    APP_ID_FROM_RESPONDER,
    APP_ID_APPID_SESSION_DIRECTION_MAX // Maximum value of a direction (must be last in the list)
};

struct AppIdFlowData
{
    AppIdFlowData* next = nullptr;
    unsigned fd_id = 0;
    void* fd_data = nullptr;
    AppIdFreeFCN fd_free = nullptr;
};

struct CommonAppIdData
{
    CommonAppIdData()
    {
        initiator_ip.clear();
    }

    APPID_FLOW_TYPE flow_type = APPID_FLOW_TYPE_IGNORE;
    unsigned policyId = 0;
    //flags shared with other preprocessor via session attributes.
    uint64_t flags = 0;
    SfIp initiator_ip;
    uint16_t initiator_port = 0;
};

#define SCAN_HTTP_VIA_FLAG          (1<<0)
#define SCAN_HTTP_USER_AGENT_FLAG   (1<<1)
#define SCAN_HTTP_HOST_URL_FLAG     (1<<2)
#define SCAN_SSL_HOST_FLAG          (1<<4)
#define SCAN_HOST_PORT_FLAG         (1<<5)
#define SCAN_HTTP_VENDOR_FLAG       (1<<6)
#define SCAN_HTTP_XWORKINGWITH_FLAG (1<<7)
#define SCAN_HTTP_CONTENT_TYPE_FLAG (1<<8)

#define RESPONSE_CODE_PACKET_THRESHHOLD 0

// These values are used in Lua code as raw numbers. Do NOT reassign new values.
#define APP_TYPE_SERVICE    0x1
#define APP_TYPE_CLIENT     0x2
#define APP_TYPE_PAYLOAD    0x4

struct HttpSession
{
    char* host = nullptr;
    uint16_t host_buflen = 0;
    char* url = nullptr;
    char* uri = nullptr;
    uint16_t uri_buflen = 0;
    char* via = nullptr;
    char* useragent = nullptr;
    uint16_t useragent_buflen = 0;
    char* response_code = nullptr;
    uint16_t response_code_buflen = 0;
    char* referer = nullptr;
    uint16_t referer_buflen = 0;
    char* cookie = nullptr;
    uint16_t cookie_buflen = 0;
    char* content_type = nullptr;
    uint16_t content_type_buflen = 0;
    char* location = nullptr;
    uint16_t location_buflen = 0;
    char* body = nullptr;
    uint16_t body_buflen = 0;
    char* req_body = nullptr;
    uint16_t req_body_buflen = 0;
    char* server = nullptr;
    char* x_working_with = nullptr;
    char* new_field[HTTP_FIELD_MAX + 1] = { nullptr };
    uint16_t new_field_len[HTTP_FIELD_MAX + 1] = { 0 };
    uint16_t fieldOffset[HTTP_FIELD_MAX + 1] = { 0 };
    uint16_t fieldEndOffset[HTTP_FIELD_MAX + 1] = { 0 };
    bool new_field_contents = false;
    bool is_webdav = false;
    int chp_finished = 0;
    AppId chp_candidate = APP_ID_NONE;
    AppId chp_alt_candidate = APP_ID_NONE;
    int chp_hold_flow = 0;
    int ptype_req_counts[NUMBER_OF_PTYPES] = { 0 };
    int total_found = 0;
    unsigned app_type_flags = 0;
    int num_matches = 0;
    int num_scans = 0;
    int get_offsets_from_rebuilt = 0;
    bool skip_simple_detect = false;
    SfIp* xffAddr = nullptr;
    const char** xffPrecedence = nullptr;
    int numXffFields = 0;
    int ptype_scan_counts[NUMBER_OF_PTYPES] = { 0 };

#if RESPONSE_CODE_PACKET_THRESHHOLD
    unsigned response_code_packets = 0;
#endif
};

// For dnsSession.state:
#define DNS_GOT_QUERY    0x01
#define DNS_GOT_RESPONSE 0x02

struct DnsSession
{
    uint8_t state = 0;              // state
    uint8_t host_len = 0;           // for host
    uint8_t response_type = 0;      // response: RCODE
    uint16_t id = 0;                // DNS msg ID
    uint16_t host_offset = 0;       // for host
    uint16_t record_type = 0;       // query: QTYPE
    uint32_t ttl = 0;               // response: TTL
    char* host = nullptr;           // host (usually query, but could be response for reverse
                                    // lookup)
};

struct _RNAServiceSubtype;

struct TlsSession
{
    char* tls_host = nullptr;
    int tls_host_strlen = 0;
    char* tls_cname = nullptr;
    int tls_cname_strlen = 0;
    char* tls_orgUnit = nullptr;
    int tls_orgUnit_strlen = 0;
};

class AppIdSession : public FlowData
{
public:
    AppIdSession(IpProtocol, const SfIp*, uint16_t port);
    ~AppIdSession();

    static AppIdSession* allocate_session(const Packet*, IpProtocol, int);
    static AppIdSession* create_future_session(const Packet*, const SfIp*, uint16_t, const SfIp*,
        uint16_t, IpProtocol, int16_t, int);

    AppIdConfig* config = nullptr;
    CommonAppIdData common;
    Flow* flow = nullptr;
    AppIdFlowData* flowData = nullptr;
    AppInfoManager* app_info_mgr = nullptr;
    HttpPatternMatchers* http_matchers;

    SfIp service_ip;
    uint16_t service_port = 0;
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
    uint8_t previous_tcp_flags = 0;

    // AppId matching service side
    APPID_DISCOVERY_STATE service_disco_state = APPID_DISCO_STATE_NONE;
    SESSION_SERVICE_ID_STATE service_search_state = START;
    AppId serviceAppId = APP_ID_NONE;
    AppId portServiceAppId = APP_ID_NONE;
    ServiceDetector* service_detector = nullptr;
    char* serviceVendor = nullptr;
    char* serviceVersion = nullptr;
    RNAServiceSubtype* subtype = nullptr;
    char* netbios_name = nullptr;
    std::vector<ServiceDetector*> service_candidates;
    bool got_incompatible_services = false;

    // AppId matching client side
    APPID_DISCOVERY_STATE client_disco_state = APPID_DISCO_STATE_NONE;
    AppId client_app_id = APP_ID_NONE;
    AppId client_service_app_id = APP_ID_NONE;
    char* client_version = nullptr;
    ClientDetector* client_detector = nullptr;
    std::map<std::string, ClientDetector*> client_candidates;
    bool tried_reverse_service = false;

    // AppId matching payload
    AppId payload_app_id = APP_ID_NONE;
    AppId referred_payload_app_id = APP_ID_NONE;
    AppId misc_app_id = APP_ID_NONE;

    // appId determined by 3rd party library
    AppId tp_app_id = APP_ID_NONE;
    AppId tp_payload_app_id = APP_ID_NONE;

    char* username = nullptr;
    AppId username_service = APP_ID_NONE;
    char* netbios_domain = nullptr;
    uint32_t session_id = 0;
    HttpSession* hsession = nullptr;
    TlsSession* tsession = nullptr;
    unsigned scan_flags = 0;
    AppId referredAppId = APP_ID_NONE;
    AppId temp_app_id = APP_ID_NONE;
    void* tpsession = nullptr;
    uint16_t init_tpPackets = 0;
    uint16_t resp_tpPackets = 0;
    bool tp_reinspect_by_initiator = false;
    char* payload_version = nullptr;
    uint16_t session_packet_count = 0;
    int16_t snort_id = 0;

    /* Length-based detectors. */
    LengthKey length_sequence;

    struct
    {
        uint32_t firstPktsecond;
        uint32_t lastPktsecond;
        uint64_t initiatorBytes;
        uint64_t responderBytes;
    } stats = { 0, 0, 0, 0 };

    // Policy and rule ID for related flows (e.g. ftp-data)
    AppIdSession* expectedFlow = nullptr;

    //appIds picked from encrypted session.
    struct
    {
        AppId serviceAppId;
        AppId ClientAppId;
        AppId payloadAppId;
        AppId miscAppId;
        AppId referredAppId;
    } encrypted = { APP_ID_NONE, APP_ID_NONE, APP_ID_NONE, APP_ID_NONE, APP_ID_NONE };

    // New fields introduced for DNS Blacklisting
    DnsSession* dsession = nullptr;

    void* firewallEarlyData = nullptr;
    AppId pastIndicator = APP_ID_NONE;
    AppId pastForecast = APP_ID_NONE;

    bool is_http2 = false;
    SEARCH_SUPPORT_TYPE search_support_type = UNKNOWN_SEARCH_ENGINE;
    bool in_expected_cache = false;
    static unsigned flow_id;
    static void init() { flow_id = FlowData::get_flow_id(); }

    void set_session_flags(uint64_t flags)
    {
        common.flags |= flags;
    }

    void clear_session_flags(uint64_t flags)
    {
        common.flags &= ~flags;
    }

    uint64_t get_session_flags(uint64_t flags)
    {
        return (common.flags & flags);
    }

    bool is_decrypted()
    {
       return get_session_flags(APPID_SESSION_DECRYPTED) == APPID_SESSION_DECRYPTED;
    }
    char session_logging_id[MAX_SESSION_LOGGING_ID_LEN];
    bool session_logging_enabled = false;

    static void release_free_list_flow_data();
    void* get_flow_data(unsigned id);
    int add_flow_data(void* data, unsigned id, AppIdFreeFCN);
    int add_flow_data_id(uint16_t port, ServiceDetector*);
    void* remove_flow_data(unsigned id);
    void free_flow_data_by_id(unsigned id);
    void free_flow_data_by_mask(unsigned mask);

    void clear_http_field();
    void free_http_session_data();
    void free_dns_session_data();
    void free_tls_session_data();
    void free_flow_data();
    void delete_shared_data();

    AppId is_appid_detection_done();
    AppId pick_service_app_id();
    AppId pick_only_service_app_id();
    AppId pick_misc_app_id();
    AppId pick_client_app_id();
    AppId pick_payload_app_id();
    AppId pick_referred_payload_app_id();
    AppId pick_fw_service_app_id();
    AppId pick_fw_misc_app_id();
    AppId pick_fw_client_app_id();
    AppId pick_fw_payload_app_id();
    AppId pick_fw_referred_payload_app_id();
    bool is_ssl_session_decrypted();
    int process_http_packet(int);

    void examine_ssl_metadata(Packet*);
    void set_client_app_id_data(AppId clientAppId, char** version);
    void set_service_appid_data(AppId, char*, char**);
    void set_referred_payload_app_id_data(AppId);
    void set_payload_app_id_data(ApplicationId, char**);
    void check_app_detection_restart();
    void update_encrypted_app_id(AppId);
    void examine_rtmp_metadata();
    void sync_with_snort_id(AppId, Packet*);
    void stop_rna_service_inspection(Packet*,  int);

private:
    bool is_payload_appid_set();
    void reinit_shared_data();
    bool is_ssl_decryption_enabled();

    void set_session_logging_state(const Packet*, int direction);
    void clear_app_id_data();
    int initial_chp_sweep(char**, uint16_t*, MatchedCHPAction**);
    void clear_http_flags();
    void process_chp_buffers(char**, Packet*);
    void create_session_logging_id(int direction, Packet*);

    static THREAD_LOCAL uint32_t appid_flow_data_id;
    static THREAD_LOCAL AppIdFlowData* fd_free_list;
};

#endif

