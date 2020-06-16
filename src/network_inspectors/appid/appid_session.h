//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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
#include <mutex>
#include <string>
#include <unordered_map>

#include "pub_sub/appid_events.h"

#include "app_info_table.h"
#include "appid_api.h"
#include "appid_app_descriptor.h"
#include "appid_config.h"
#include "appid_http_session.h"
#include "appid_types.h"
#include "application_ids.h"
#include "detector_plugins/http_url_patterns.h"
#include "length_app_cache.h"
#include "service_state.h"

class ClientDetector;
class ServiceDetector;
class AppIdDnsSession;
class AppIdHttpSession;
class ThirdPartyAppIdSession;

using AppIdFreeFCN = void (*)(void*);

const uint8_t* service_strstr(const uint8_t* haystack, unsigned haystack_len,
    const uint8_t* needle, unsigned needle_len);

#define MAX_ATTR_LEN           1024

#define SF_DEBUG_FILE   stdout
#define MIN_SFTP_PACKET_COUNT   30
#define MAX_SFTP_PACKET_COUNT   55

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

enum APPID_DISCOVERY_STATE
{
    APPID_DISCO_STATE_NONE = 0,
    APPID_DISCO_STATE_DIRECT,
    APPID_DISCO_STATE_STATEFUL,
    APPID_DISCO_STATE_FINISHED
};

class AppIdFlowData
{
public:
    AppIdFlowData(void* data, unsigned id, AppIdFreeFCN fcn) :
        fd_data(data), fd_id(id), fd_free(fcn)
    { }

    ~AppIdFlowData()
    {
        if (fd_data && fd_free)
            fd_free(fd_data);
    }

    void* fd_data;
    unsigned fd_id;
    AppIdFreeFCN fd_free;
};
typedef std::unordered_map<unsigned, AppIdFlowData*>::const_iterator AppIdFlowDataIter;

struct CommonAppIdData
{
    CommonAppIdData()
    {
        initiator_ip.clear();
    }

    //flags shared with other preprocessor via session attributes.
    uint64_t flags = 0;
    snort::SfIp initiator_ip;
    uint16_t initiator_port = 0;
};

enum MatchedTlsType
{
    MATCHED_TLS_NONE = 0,
    MATCHED_TLS_HOST,
    MATCHED_TLS_FIRST_SAN,
    MATCHED_TLS_CNAME,
    MATCHED_TLS_ORG_UNIT,
};

class TlsSession
{
public:
    ~TlsSession()
    {
        if (tls_host)
            snort_free(tls_host);
        if (tls_first_alt_name)
            snort_free(tls_first_alt_name);
        if (tls_cname)
            snort_free(tls_cname);
        if (tls_org_unit)
            snort_free(tls_org_unit);
    }

    const char* get_tls_host() const
    {
        switch (matched_tls_type)
        {
            case MATCHED_TLS_HOST:
                return tls_host;
            case MATCHED_TLS_FIRST_SAN:
                return tls_first_alt_name;
            case MATCHED_TLS_CNAME:
                return tls_cname;
            default:
                if (tls_host)
                    return tls_host;
                else if (tls_first_alt_name)
                    return tls_first_alt_name;
                else if (tls_cname)
                    return tls_cname;
        }
        return nullptr;
    }

    const char* get_tls_first_alt_name() const { return tls_first_alt_name; }

    const char* get_tls_cname() const { return tls_cname; }

    const char* get_tls_org_unit() const { return tls_org_unit; }

    bool get_tls_handshake_done() { return tls_handshake_done; }

    // Duplicate only if len > 0, otherwise simply set (i.e., own the argument)
    void set_tls_host(const char* new_tls_host, uint32_t len, AppidChangeBits& change_bits)
    {
        if (tls_host)
            snort_free(tls_host);
        if (!new_tls_host or *new_tls_host == '\0')
        {
            tls_host = nullptr;
            return;
        }
        tls_host = len? snort::snort_strndup(new_tls_host,len) : const_cast<char*>(new_tls_host);
        change_bits.set(APPID_TLSHOST_BIT);
    }

    void set_tls_first_alt_name(const char* new_tls_first_alt_name, uint32_t len, AppidChangeBits& change_bits)
    {
        if (tls_first_alt_name)
            snort_free(tls_first_alt_name);
        if (!new_tls_first_alt_name or *new_tls_first_alt_name == '\0')
        {
            tls_first_alt_name = nullptr;
            return;
        }
        tls_first_alt_name = len? snort::snort_strndup(new_tls_first_alt_name, len) :
            const_cast<char*>(new_tls_first_alt_name);
        if (!tls_host)
            change_bits.set(APPID_TLSHOST_BIT);
    }

    void set_tls_cname(const char* new_tls_cname, uint32_t len, AppidChangeBits& change_bits)
    {
        if (tls_cname)
            snort_free(tls_cname);
        if (!new_tls_cname or *new_tls_cname == '\0')
        {
            tls_cname = nullptr;
            return;
        }
        tls_cname = len? snort::snort_strndup(new_tls_cname,len) :
            const_cast<char*>(new_tls_cname);
        if (tls_host == nullptr)
            change_bits.set(APPID_TLSHOST_BIT);
    }

    void set_tls_org_unit(const char* new_tls_org_unit, uint32_t len)
    {
        if (tls_org_unit)
            snort_free(tls_org_unit);
        if (!new_tls_org_unit or *new_tls_org_unit == '\0')
        {
            tls_org_unit = nullptr;
            return;
        }
        tls_org_unit = len? snort::snort_strndup(new_tls_org_unit,len) :
            const_cast<char*>(new_tls_org_unit);
    }

    void set_tls_handshake_done() { tls_handshake_done = true; }

    void set_matched_tls_type(MatchedTlsType type)
    {
        matched_tls_type = type;
    }

private:
    char* tls_host = nullptr;
    char* tls_first_alt_name = nullptr;
    char* tls_cname = nullptr;
    char* tls_org_unit = nullptr;
    bool tls_handshake_done = false;
    MatchedTlsType matched_tls_type = MATCHED_TLS_NONE;
};

class AppIdSession : public snort::FlowData
{
public:
    AppIdSession(IpProtocol, const snort::SfIp*, uint16_t port, AppIdInspector&);
    ~AppIdSession() override;

    static AppIdSession* allocate_session(const snort::Packet*, IpProtocol,
        AppidSessionDirection, AppIdInspector*);
    static AppIdSession* create_future_session(const snort::Packet*, const snort::SfIp*, uint16_t,
        const snort::SfIp*, uint16_t, IpProtocol, SnortProtocolId);
    void initialize_future_session(AppIdSession&, uint64_t, AppidSessionDirection);

    size_t size_of() override
    { return sizeof(*this); }

    uint32_t session_id = 0;
    snort::Flow* flow = nullptr;
    AppIdContext& ctxt;
    std::unordered_map<unsigned, AppIdFlowData*> flow_data;
    CommonAppIdData common;
    uint16_t session_packet_count = 0;
    uint16_t init_pkts_without_reply = 0;
    uint64_t init_bytes_without_reply = 0;

    snort::SfIp service_ip;
    uint16_t service_port = 0;
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
    uint8_t previous_tcp_flags = 0;

    // AppId matching service side
    APPID_DISCOVERY_STATE service_disco_state = APPID_DISCO_STATE_NONE;
    SESSION_SERVICE_SEARCH_STATE service_search_state = SESSION_SERVICE_SEARCH_STATE::START;
    ServiceDetector* service_detector = nullptr;
    AppIdServiceSubtype* subtype = nullptr;
    std::vector<ServiceDetector*> service_candidates;
    ServiceAppDescriptor service;

    // Following three fields are used only for non-http sessions. For HTTP traffic,
    // these fields are maintained inside AppIdHttpSession.
    // Note: RTMP traffic is treated like HTTP in AppId
    ClientAppDescriptor client;
    PayloadAppDescriptor payload;
    AppId misc_app_id = APP_ID_NONE;

    // AppId matching client side
    APPID_DISCOVERY_STATE client_disco_state = APPID_DISCO_STATE_NONE;
    AppId client_inferred_service_id = APP_ID_NONE;
    ClientDetector* client_detector = nullptr;
    std::map<std::string, ClientDetector*> client_candidates;
    bool tried_reverse_service = false;

    // FIXIT-RC netbios_name is never set to a valid value; set when netbios_domain is set?
    char* netbios_name = nullptr;
    char* netbios_domain = nullptr;

    TlsSession* tsession = nullptr;
    unsigned scan_flags = 0;
    ThirdPartyAppIdSession* tpsession = nullptr;
    uint16_t init_tpPackets = 0;
    uint16_t resp_tpPackets = 0;
    bool tp_reinspect_by_initiator = false;
    SnortProtocolId snort_protocol_id = UNKNOWN_PROTOCOL_ID;

    /* Length-based detectors. */
    LengthKey length_sequence;

    struct
    {
        uint32_t first_packet_second;
        uint32_t last_packet_second;
        uint64_t initiator_bytes;
        uint64_t responder_bytes;
    } stats = { 0, 0, 0, 0 };

    //appIds picked from encrypted session.
    struct
    {
        AppId service_id;
        AppId client_id;
        AppId payload_id;
        AppId misc_id;
        AppId referred_id;
    } encrypted = { APP_ID_NONE, APP_ID_NONE, APP_ID_NONE, APP_ID_NONE, APP_ID_NONE };

    AppId past_indicator = APP_ID_NONE;
    AppId past_forecast = APP_ID_NONE;

    bool in_expected_cache = false;
    static unsigned inspector_id;
    static std::mutex inferred_svcs_lock;

    static void init() { inspector_id = FlowData::create_flow_data_id(); }

    void set_session_flags(uint64_t flags) { common.flags |= flags; }
    void clear_session_flags(uint64_t flags) { common.flags &= ~flags; }
    uint64_t get_session_flags(uint64_t flags) const { return (common.flags & flags); }
    void set_service_detected() { common.flags |= APPID_SESSION_SERVICE_DETECTED; }
    bool is_service_detected() { return ((common.flags & APPID_SESSION_SERVICE_DETECTED) == 0) ?
        false : true; }
    void set_client_detected() { common.flags |= APPID_SESSION_CLIENT_DETECTED; }
    bool is_client_detected() { return ((common.flags & APPID_SESSION_CLIENT_DETECTED) == 0) ?
        false : true; }
    bool is_decrypted() { return ((common.flags & APPID_SESSION_DECRYPTED) == 0) ? false : true; }
    bool is_svc_taking_too_much_time();

    void* get_flow_data(unsigned id);
    int add_flow_data(void* data, unsigned id, AppIdFreeFCN);
    int add_flow_data_id(uint16_t port, ServiceDetector*);
    void* remove_flow_data(unsigned id);
    void free_flow_data_by_id(unsigned id);
    void free_flow_data_by_mask(unsigned mask);
    void free_flow_data();

    AppId pick_service_app_id();
    // pick_ss_* and set_ss_* methods below are for application protocols that support only a single
    // stream in a flow. They should not be used for HTTP2 sessions which can have multiple
    // streams within a single flow
    AppId pick_ss_misc_app_id();
    AppId pick_ss_client_app_id();
    AppId pick_ss_payload_app_id();
    AppId pick_ss_referred_payload_app_id();

    void set_ss_application_ids(AppId service, AppId client, AppId payload, AppId misc,
        AppidChangeBits& change_bits);
    void set_application_ids_service(AppId service_id, AppidChangeBits& change_bits);

    // For protocols such as HTTP2 which can have multiple streams within a single flow, get_first_stream_*
    // methods return the appids in the first stream seen in a packet.
    void get_first_stream_app_ids(AppId& service, AppId& client, AppId& payload, AppId& misc);
    void get_first_stream_app_ids(AppId& service, AppId& client, AppId& payload);
    AppId get_application_ids_service();
    AppId get_application_ids_client(uint32_t stream_index = 0);
    AppId get_application_ids_payload(uint32_t stream_index = 0);
    AppId get_application_ids_misc(uint32_t stream_index = 0);

    uint32_t get_hsessions_size()
    {
        return hsessions.size();
    }

    bool is_ssl_session_decrypted();
    void examine_ssl_metadata(AppidChangeBits& change_bits);
    void set_client_appid_data(AppId, AppidChangeBits& change_bits, char* version = nullptr);
    void set_service_appid_data(AppId, AppidChangeBits& change_bits, char* version = nullptr);
    void set_payload_appid_data(AppId, AppidChangeBits& change_bits, char* version = nullptr);
    void check_app_detection_restart(AppidChangeBits& change_bits);
    void check_ssl_detection_restart(AppidChangeBits& change_bits);
    void check_tunnel_detection_restart();
    void update_encrypted_app_id(AppId);
    void examine_rtmp_metadata(AppidChangeBits& change_bits);
    void sync_with_snort_protocol_id(AppId, snort::Packet*);
    void stop_service_inspection(snort::Packet*,  AppidSessionDirection);

    bool is_payload_appid_set();
    void clear_http_flags();
    void clear_http_data();
    void reset_session_data();

    AppIdHttpSession* create_http_session(uint32_t stream_id = 0);
    AppIdHttpSession* get_http_session(uint32_t stream_index = 0);
    AppIdHttpSession* get_matching_http_session(uint32_t stream_id);
    void delete_all_http_sessions()
    {
        for (auto hsession : hsessions)
            delete hsession;
        hsessions.clear();
    }

    AppIdDnsSession* create_dns_session();
    AppIdDnsSession* get_dns_session();

    bool is_tp_appid_done() const;
    bool is_tp_processing_done() const;
    bool is_tp_appid_available() const;

    void set_tp_app_id(snort::Packet& p, AppidSessionDirection dir, AppId app_id,
        AppidChangeBits& change_bits);
    void set_tp_payload_app_id(snort::Packet& p, AppidSessionDirection dir, AppId app_id,
        AppidChangeBits& change_bits);
    void publish_appid_event(AppidChangeBits&, snort::Flow*, bool is_http2 = false,
        uint32_t http2_stream_index = 0);

    inline void set_tp_app_id(AppId app_id) {
        if (tp_app_id != app_id)
        {
            tp_app_id = app_id;
            tp_app_id_deferred = ctxt.get_odp_ctxt().get_app_info_mgr().get_app_info_flags
                (tp_app_id, APPINFO_FLAG_DEFER);
        }
    }

    inline void set_tp_payload_app_id(AppId app_id) {
        if (tp_payload_app_id != app_id)
        {
            tp_payload_app_id = app_id;
            tp_payload_app_id_deferred = ctxt.get_odp_ctxt().get_app_info_mgr().get_app_info_flags
                (tp_payload_app_id, APPINFO_FLAG_DEFER_PAYLOAD);
        }
    }

    inline AppId get_tp_app_id() {
        return tp_app_id;
    }

    inline AppId get_tp_payload_app_id() {
        return tp_payload_app_id;
    }

    inline uint16_t is_inferred_svcs_ver_updated()
    {
        if (my_inferred_svcs_ver == inferred_svcs_ver)
            return false;
        my_inferred_svcs_ver = inferred_svcs_ver;
        return true;
    }

    static inline void incr_inferred_svcs_ver()
    {
        inferred_svcs_ver++;
        if (inferred_svcs_ver == 0)
            inferred_svcs_ver++;
    }

    uint16_t get_prev_http2_raw_packet() const
    {
        return prev_http2_raw_packet;
    }

    void set_prev_http2_raw_packet(uint16_t packet_num)
    {
        prev_http2_raw_packet = packet_num;
    }

private:
    std::vector<AppIdHttpSession*> hsessions;
    AppIdDnsSession* dsession = nullptr;
    uint16_t prev_http2_raw_packet = 0;

    void reinit_session_data(AppidChangeBits& change_bits);
    void delete_session_data();

    static THREAD_LOCAL uint32_t appid_flow_data_id;
    AppId application_ids[APP_PROTOID_MAX];
    bool tp_app_id_deferred = false;
    bool tp_payload_app_id_deferred = false;

    // appId determined by 3rd party library
    AppId tp_app_id = APP_ID_NONE;
    AppId tp_payload_app_id = APP_ID_NONE;

    uint16_t my_inferred_svcs_ver = 0;
    static uint16_t inferred_svcs_ver;
};

static inline bool is_svc_http_type(AppId serviceId)
{
    switch(serviceId)
    {
        case APP_ID_HTTP:
        case APP_ID_HTTPS:
        case APP_ID_FTPS:
        case APP_ID_IMAPS:
        case APP_ID_IRCS:
        case APP_ID_LDAPS:
        case APP_ID_NNTPS:
        case APP_ID_POP3S:
        case APP_ID_SMTPS:
        case APP_ID_SSHELL:
        case APP_ID_SSL:
        case APP_ID_QUIC:
            return true;
    }
    return false;
}
#endif

