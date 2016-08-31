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

#include "appid.h"
#include "appid_api.h"
#include "application_ids.h"
#include "flow_error.h"
#include "length_app_cache.h"
#include "service_state.h"
#include "thirdparty_appid_api.h"
#include "thirdparty_appid_types.h"
#include "http_common.h"

#define MAX_ATTR_LEN           1024
#define HTTP_PREFIX "http://"

#define SF_DEBUG_FILE   stdout
#define NUMBER_OF_PTYPES    9

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

struct RNAServiceElement;
struct RNAServiceSubtype;
struct RNAClientAppModule;

enum RNA_INSPECTION_STATE
{
    RNA_STATE_NONE = 0,
    RNA_STATE_DIRECT,
    RNA_STATE_STATEFUL,
    RNA_STATE_FINISHED
};

struct AppIdFlowData
{
    AppIdFlowData* next;
    unsigned fd_id;
    void* fd_data;
    AppIdFreeFCN fd_free;
};

#define APPID_SESSION_TYPE_IGNORE   APPID_FLOW_TYPE_IGNORE
#define APPID_SESSION_TYPE_NORMAL   APPID_FLOW_TYPE_NORMAL
#define APPID_SESSION_TYPE_TMP      APPID_FLOW_TYPE_TMP

struct APPID_SESSION_STRUCT_FLAG
{
    APPID_FLOW_TYPE flow_type;
};

struct CommonAppIdData
{
    APPID_SESSION_STRUCT_FLAG fsf_type;  /* This must be first. */
    unsigned policyId;
    //flags shared with other preprocessor via session attributes.
    uint64_t flags;
    sfip_t initiator_ip;
    uint16_t initiator_port;
};

#define SCAN_HTTP_VIA_FLAG          (1<<0)
#define SCAN_HTTP_USER_AGENT_FLAG   (1<<1)
#define SCAN_HTTP_HOST_URL_FLAG     (1<<2)
#define SCAN_SSL_HOST_FLAG          (1<<4)
#define SCAN_HOST_PORT_FLAG         (1<<5)
#define SCAN_HTTP_VENDOR_FLAG       (1<<6)
#define SCAN_HTTP_XWORKINGWITH_FLAG (1<<7)
#define SCAN_HTTP_CONTENT_TYPE_FLAG (1<<8)

struct fflow_info
{
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    IpProtocol protocol;
    AppId appId;
    int flow_prepared;
};

struct HttpRewriteableFields
{
    char* str;
};

struct httpSession
{
    char* host;
    char* url;
    char* uri;
    char* via;
    char* useragent;
    char* response_code;
    char* referer;
    char* cookie;
    char* content_type;
    char* location;
    char* body;
    char* req_body;
    char* server;
    char* x_working_with;
    char* new_field[HTTP_FIELD_MAX+1];

    uint16_t uriOffset;
    uint16_t uriEndOffset;
    uint16_t cookieOffset;
    uint16_t cookieEndOffset;

    fflow_info* fflow;

    int chp_finished;
    AppId chp_candidate;
    AppId chp_alt_candidate;
    int chp_hold_flow;
    int ptype_req_counts[NUMBER_OF_PTYPES];
    int total_found;
    unsigned app_type_flags;
    int num_matches;
    int num_scans;
    int get_offsets_from_rebuilt;
    bool skip_simple_detect;    // Flag to indicate if simple detection of client ID, payload ID,
                                // etc
                                // should be skipped
    sfip_t* xffAddr;
    const char** xffPrecedence;
    int numXffFields;

#if RESPONSE_CODE_PACKET_THRESHHOLD
    unsigned response_code_packets;
#endif
};

// For dnsSession.state:
#define DNS_GOT_QUERY    0x01
#define DNS_GOT_RESPONSE 0x02

struct dnsSession
{
    uint8_t state;              // state
    uint8_t host_len;           // for host
    uint8_t response_type;      // response: RCODE
    uint16_t id;                // DNS msg ID
    uint16_t host_offset;       // for host
    uint16_t record_type;       // query: QTYPE
    uint32_t ttl;               // response: TTL
    char* host;                 // host (usually query, but could be response for reverse lookup)
};

struct _RNAServiceSubtype;

struct tlsSession
{
    char* tls_host;
    int tls_host_strlen;
    char* tls_cname;
    int tls_cname_strlen;
    char* tls_orgUnit;
    int tls_orgUnit_strlen;
};

extern char app_id_debug_session[];
extern bool app_id_debug_session_flag;

/* The UNSYNCED_SNORT_ID value is to cheaply insure we get
   the value from snort rather than assume */
#define UNSYNCED_SNORT_ID   0x5555

void map_app_names_to_snort_ids();

class AppIdSession : public FlowData
{
public:
    AppIdSession(IpProtocol proto, const sfip_t* ip);
    ~AppIdSession();

    static AppIdSession* allocate_session(const Packet*, IpProtocol, int);
    static AppIdSession* create_future_session(const Packet*, const sfip_t*, uint16_t, const sfip_t*,
            uint16_t, IpProtocol, int16_t, int);
    static void do_application_discovery(Packet*);

private:
    bool do_client_discovery(int, Packet*);
    bool do_service_discovery(IpProtocol, int, AppId, AppId,  Packet*);
    int exec_client_detectors(Packet*, int, AppIdConfig*);

    static uint64_t is_session_monitored(const Packet*, int, AppIdSession*);
    static bool is_packet_ignored(Packet* p);
    bool is_payload_appid_set();
    void clear_app_id_data();
    void reinit_shared_data();
    bool is_ssl_decryption_enabled();
    void check_app_detection_restart();
    void update_encrypted_app_id(AppId serviceAppId);
    void sync_with_snort_id(AppId, Packet*, AppIdConfig*);
    void examine_ssl_metadata(Packet*, AppIdConfig*);
    void examine_rtmp_metadata();
    void set_client_app_id_data(AppId clientAppId, char** version);
    void set_service_appid_data( AppId, char*, char**);
    void set_referred_payload_app_id_data( AppId);
    void set_payload_app_id_data( ApplicationId, char**);
    void stop_rna_service_inspection(Packet*,  int);

#ifdef REMOVED_WHILE_NOT_IN_USE
    // FIXIT-M: these are not needed until appid for snort3 supports 3rd party detectors (e.g. NAVL)
    void ProcessThirdPartyResults(Packet*, int, AppId*, ThirdPartyAppIDAttributeData*);
    void checkTerminateTpModule(uint16_t tpPktCount);
    bool do_third_party_discovery(IpProtocol, const sfip_t*,  Packet*, int&);

    // FIXIT-H: when http detection is made functional we need to look at these methods and determine if they are
    // needed and what changes are required for snort3
    void pickHttpXffAddress(Packet*, ThirdPartyAppIDAttributeData*);
    int initial_CHP_sweep(char**, MatchedCHPAction**, const DetectorHttpConfig*);
    void clearMiscHttpFlags();
    int processHTTPPacket(Packet*, int, HttpParsedHeaders* const, const AppIdConfig*);
    void processCHP(char**, Packet*, const AppIdConfig*);
#endif

public:
    CommonAppIdData common;
    AppIdSession* next = nullptr;
    Flow* flow = nullptr;

    sfip_t service_ip;
    uint16_t service_port = 0;
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
    uint8_t previous_tcp_flags = 0;

    AppIdFlowData* flowData = nullptr;

    // AppId matching service side
    AppId serviceAppId = APP_ID_NONE;
    AppId portServiceAppId = APP_ID_NONE;
    // RNAServiceElement for identifying detector
    const RNAServiceElement* serviceData = nullptr;
    RNA_INSPECTION_STATE rnaServiceState = RNA_STATE_NONE;
    char* serviceVendor = nullptr;
    char* serviceVersion = nullptr;
    RNAServiceSubtype* subtype = nullptr;
    AppIdServiceIDState* id_state = nullptr;
    char* netbios_name = nullptr;
    SF_LIST* candidate_service_list = nullptr;
    unsigned int num_candidate_services_tried = 0;
    int got_incompatible_services = 0;

    /**AppId matching client side */
    AppId client_app_id = APP_ID_NONE;
    AppId client_service_app_id = APP_ID_NONE;
    char* client_version = nullptr;
    /**RNAClientAppModule for identifying client detector*/
    const RNAClientAppModule* rna_client_data = nullptr;
    RNA_INSPECTION_STATE rna_client_state = RNA_STATE_NONE;
    SF_LIST* candidate_client_list = nullptr;
    unsigned int num_candidate_clients_tried = 0;
    bool tried_reverse_service = false;

    /**AppId matching payload*/
    AppId payload_app_id = APP_ID_NONE;
    AppId referred_payload_app_id = APP_ID_NONE;
    AppId misc_app_id = APP_ID_NONE;

    //appId determined by 3rd party library
    AppId tp_app_id = APP_ID_NONE;
    AppId tp_payload_app_id = APP_ID_NONE;

    char* username = nullptr;
    AppId username_service = APP_ID_NONE;
    char* netbios_domain = nullptr;
    uint32_t id = 0;
    httpSession* hsession = nullptr;
    tlsSession* tsession = nullptr;
    unsigned scan_flags = 0;
    AppId referredAppId = APP_ID_NONE;
    AppId temp_app_id = APP_ID_NONE;
    void* tpsession = nullptr;
    uint16_t init_tpPackets = 0;
    uint16_t resp_tpPackets = 0;
    uint8_t tp_reinspect_by_initiator = 0;
    char* payload_version = nullptr;
    uint16_t session_packet_count = 0;
    int16_t snort_id = UNSYNCED_SNORT_ID;

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
    SEARCH_SUPPORT_TYPE search_support_type = SEARCH_SUPPORT_TYPE_UNKNOWN;

    static unsigned flow_id;
    static void init() { flow_id = FlowData::get_flow_id(); }

    void setAppIdFlag(uint64_t flags)
    {
        common.flags |= flags;
    }

    void clearAppIdFlag(uint64_t flags)
    {
        common.flags &= ~flags;
    }

    inline uint64_t getAppIdFlag(uint64_t flags)
    {
        return (common.flags & flags);
    }

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
};

#endif
