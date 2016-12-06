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

// appid_session.h author Sourcefire Inc.

#ifndef APPID_SESSION_H
#define APPID_SESSION_H

//  AppId configuration data structures and access methods

#include <cstdint>
#include <ctime>

#include "protocols/packet.h"
#include "utils/sflsq.h"

#include "appid_api.h"
#include "application_ids.h"
#include "length_app_cache.h"
#include "service_state.h"
#include "http_common.h"
#include "thirdparty_appid_api.h"
#include "thirdparty_appid_types.h"
#include "thirdparty_appid_utils.h"

struct RNAServiceElement;
struct RNAServiceSubtype;
struct RNAClientAppModule;
class AppInfoManager;

using AppIdFreeFCN = void(*)(void*);

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

enum RNA_INSPECTION_STATE
{
    RNA_STATE_NONE = 0,
    RNA_STATE_DIRECT,
    RNA_STATE_STATEFUL,
    RNA_STATE_FINISHED
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

struct httpSession
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
    char* new_field[HTTP_FIELD_MAX+1] = { nullptr };
    uint16_t new_field_len[HTTP_FIELD_MAX+1] = { 0 };
    uint16_t fieldOffset[HTTP_FIELD_MAX+1] = { 0 };
    uint16_t fieldEndOffset[HTTP_FIELD_MAX+1] = { 0 };
    bool new_field_contents = false;
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

struct dnsSession
{
    uint8_t state = 0;              // state
    uint8_t host_len = 0;           // for host
    uint8_t response_type = 0;      // response: RCODE
    uint16_t id = 0;                // DNS msg ID
    uint16_t host_offset = 0;       // for host
    uint16_t record_type = 0;       // query: QTYPE
    uint32_t ttl = 0;               // response: TTL
    char* host = nullptr;           // host (usually query, but could be response for reverse lookup)
};

struct _RNAServiceSubtype;

struct tlsSession
{
    char* tls_host = nullptr;
    int tls_host_strlen = 0;
    char* tls_cname = nullptr;
    int tls_cname_strlen = 0;
    char* tls_orgUnit = nullptr;
    int tls_orgUnit_strlen = 0;
};

void map_app_names_to_snort_ids();

class AppIdSession : public FlowData
{
public:
    AppIdSession(IpProtocol, const SfIp*, uint16_t port);
    ~AppIdSession();

    static AppIdSession* allocate_session(const Packet*, IpProtocol, int);
    static AppIdSession* create_future_session(const Packet*, const SfIp*, uint16_t, const SfIp*,
            uint16_t, IpProtocol, int16_t, int);
    static void do_application_discovery(Packet*);
    static void add_user(AppIdSession*, const char* username, AppId, int success);
    static void add_payload(AppIdSession*, AppId);

    AppIdConfig* config = nullptr;
    CommonAppIdData common;
    Flow* flow = nullptr;
    AppIdFlowData* flowData = nullptr;
    AppInfoManager* app_info_mgr = nullptr;

    SfIp service_ip;
    uint16_t service_port = 0;
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
    uint8_t previous_tcp_flags = 0;

    // AppId matching service side
    RNA_INSPECTION_STATE rnaServiceState = RNA_STATE_NONE;
    AppId serviceAppId = APP_ID_NONE;
    AppId portServiceAppId = APP_ID_NONE;
    const RNAServiceElement* serviceData = nullptr;
    char* serviceVendor = nullptr;
    char* serviceVersion = nullptr;
    RNAServiceSubtype* subtype = nullptr;
    char* netbios_name = nullptr;
    SF_LIST* candidate_service_list = nullptr;
    unsigned int num_candidate_services_tried = 0;
    bool got_incompatible_services = false;

    // AppId matching client side
    RNA_INSPECTION_STATE rna_client_state = RNA_STATE_NONE;
    AppId client_app_id = APP_ID_NONE;
    AppId client_service_app_id = APP_ID_NONE;
    char* client_version = nullptr;
    const RNAClientAppModule* rna_client_data = nullptr;
    SF_LIST* candidate_client_list = nullptr;
    unsigned int num_candidate_clients_tried = 0;
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
    httpSession* hsession = nullptr;
    tlsSession* tsession = nullptr;
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
    } stats = {0, 0, 0, 0};

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
    dnsSession* dsession = nullptr;

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

    inline uint64_t get_session_flags(uint64_t flags)
    {
        return (common.flags & flags);
    }

    char session_logging_id[MAX_SESSION_LOGGING_ID_LEN];
    bool session_logging_enabled = false;

    static void release_free_list_flow_data();
    void* get_flow_data(unsigned id);
    int add_flow_data(void* data, unsigned id, AppIdFreeFCN);
    int add_flow_data_id(uint16_t port, const RNAServiceElement*);
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
    AppId fw_pick_service_app_id();
    AppId fw_pick_misc_app_id();
    AppId fw_pick_client_app_id();
    AppId fw_pick_payload_app_id();
    AppId fw_pick_referred_payload_app_id();
    bool is_ssl_session_decrypted();
    int process_http_packet(Packet*, int, HttpParsedHeaders* const);
    int process_http_packet(int);

private:
    bool do_client_discovery(int, Packet*);
    bool do_service_discovery(IpProtocol, int, AppId, AppId,  Packet*);
    int exec_client_detectors(Packet*, int);

    static uint64_t is_session_monitored(const Packet*, int, AppIdSession*);
    static bool is_packet_ignored(Packet* p);
    bool is_payload_appid_set();
    void reinit_shared_data();
    bool is_ssl_decryption_enabled();
    void check_app_detection_restart();
    void update_encrypted_app_id(AppId serviceAppId);
    void sync_with_snort_id(AppId, Packet*);
    void examine_ssl_metadata(Packet*);
    void examine_rtmp_metadata();
    void set_client_app_id_data(AppId clientAppId, char** version);
    void set_service_appid_data( AppId, char*, char**);
    void set_referred_payload_app_id_data( AppId);
    void set_payload_app_id_data( ApplicationId, char**);
    void stop_rna_service_inspection(Packet*,  int);
    void set_session_logging_state(const Packet* pkt, int direction);
    void clear_app_id_data();
    int initial_CHP_sweep(char**, uint16_t*, MatchedCHPAction**);
    void clearMiscHttpFlags();
    void processCHP(char**, Packet*);

#ifdef REMOVED_WHILE_NOT_IN_USE
    // FIXIT-M these are not needed until appid for snort3 supports 3rd party detectors (e.g. NAVL)
    void ProcessThirdPartyResults(Packet*, int, AppId*, ThirdPartyAppIDAttributeData*);
    void checkTerminateTpModule(uint16_t tpPktCount);
    bool do_third_party_discovery(IpProtocol, const SfIp*,  Packet*, int&);
    void pickHttpXffAddress(Packet*, ThirdPartyAppIDAttributeData*);
#endif

    void create_session_logging_id(int direction, Packet* pkt);

    static THREAD_LOCAL uint32_t appid_flow_data_id;
    static THREAD_LOCAL AppIdFlowData* fd_free_list;
};

inline bool is_third_party_appid_done(void* tp_session)
{
    if (thirdparty_appid_module)
    {
        unsigned state;

        if (tp_session)
            state = thirdparty_appid_module->session_state_get(tp_session);
        else
            state = TP_STATE_INIT;

        return (state  == TP_STATE_CLASSIFIED || state == TP_STATE_TERMINATED
                        || state == TP_STATE_HA);
    }

    return true;
}

inline bool is_third_party_appid_available(void* tp_session)
{
    if (thirdparty_appid_module)
    {
        unsigned state;

        if (tp_session)
            state = thirdparty_appid_module->session_state_get(tp_session);
        else
            state = TP_STATE_INIT;

        return (state == TP_STATE_CLASSIFIED || state == TP_STATE_TERMINATED
                        || state == TP_STATE_MONITORING);
    }

    return true;
}

#endif
