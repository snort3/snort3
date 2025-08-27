//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
#include <tuple>
#include <unordered_map>

#include <daq_common.h>
#include "flow/flow_data.h"
#include "pub_sub/appid_events.h"

#include "app_info_table.h"
#include "appid_api.h"
#include "appid_app_descriptor.h"
#include "appid_config.h"
#include "appid_flow_data.h"
#include "appid_http_session.h"
#include "appid_types.h"
#include "application_ids.h"
#include "detector_plugins/http_url_patterns.h"
#include "length_app_cache.h"
#include "pub_sub/shadowtraffic_aggregator.h"
#include "service_state.h"

#define STASH_APPID_DATA "appid_data"

namespace snort
{
    class AppIdSessionApi;
}

class ClientDetector;
class ServiceDetector;
class AppIdDnsSession;
class AppIdHttpSession;
class ThirdPartyAppIdSession;

const uint8_t* service_strstr(const uint8_t* haystack, unsigned haystack_len,
    const uint8_t* needle, unsigned needle_len);

#define SF_DEBUG_FILE   stdout
#define MIN_SFTP_PACKET_COUNT   30
#define MAX_SFTP_PACKET_COUNT   55

#define APPID_SESSION_DATA_NONE                  0
#define APPID_SESSION_DATA_SERVICE_MODSTATE_BIT  0x20000000
#define APPID_SESSION_DATA_CLIENT_MODSTATE_BIT   0x40000000
#define APPID_SESSION_DATA_DETECTOR_MODSTATE_BIT 0x80000000

enum APPID_DISCOVERY_STATE
{
    APPID_DISCO_STATE_NONE = 0,
    APPID_DISCO_STATE_STATEFUL,
    APPID_DISCO_STATE_FINISHED
};

enum MatchedTlsType
{
    MATCHED_TLS_NONE = 0,
    MATCHED_TLS_SNI,
    MATCHED_TLS_FIRST_SAN,
    MATCHED_TLS_CNAME,
    MATCHED_TLS_ORG_UNIT,
};

class TlsSession
{
public:
    TlsSession()
    { }

    ~TlsSession()
    {
        if (tls_sni)
            snort_free(tls_sni);
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
            case MATCHED_TLS_SNI:
                return tls_sni;
            case MATCHED_TLS_FIRST_SAN:
                return tls_first_alt_name;
            case MATCHED_TLS_CNAME:
                return tls_cname;
            case MATCHED_TLS_ORG_UNIT:
            default:
                if (tls_sni and !tls_host_mismatch)
                    return tls_sni;
                else if (tls_cname)
                    return tls_cname;
                else if (tls_first_alt_name)
                    return tls_first_alt_name;
                
                return nullptr;
        }
    }

    const char* get_tls_sni() const
    {
        return tls_sni;
    }

    void process_sni_mismatch()
    {
        tls_host_mismatch = true;
    }

    bool is_tls_host_mismatched() const { return tls_host_mismatch; }

    const char* get_tls_first_alt_name() const { return tls_first_alt_name; }

    const char* get_tls_cname() const { return tls_cname; }

    const char* get_tls_org_unit() const { return tls_org_unit; }

    bool get_tls_handshake_done() const { return tls_handshake_done; }

    uint16_t get_tls_version() const { return tls_version; }

    void set_tls_sni(const char* new_tls_sni, uint32_t len)
    {
        if (tls_sni)
        {
            snort_free(tls_sni);
        }
        if (new_tls_sni)
        {
            tls_sni = len ? snort::snort_strndup(new_tls_sni, len) :
                const_cast<char*>(new_tls_sni);
        }
        else
        {
            tls_sni = nullptr;
        }
    }

    void set_tls_first_alt_name(const char* new_tls_first_alt_name, uint32_t len)
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
    }

    void set_tls_cname(const char* new_tls_cname, uint32_t len)
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

    MatchedTlsType get_matched_tls_type() const
    {
        return matched_tls_type;
    }

    void set_matched_tls_type(MatchedTlsType type, bool is_tls_data_finished = true)
    {
        matched_tls_type = type;
        tls_data_finished = is_tls_data_finished;
    }

    void set_tls_host_published(bool val) { tls_host_published = val; }

    bool is_tls_host_published() const { return tls_host_published; }

    void set_tls_version(const char* value, uint32_t length, AppidChangeBits& change_bits)
    {
        if (value and length == sizeof(uint16_t))
        {
            tls_version = *reinterpret_cast<const uint16_t*>(value);
            change_bits.set(AppidChangeBit::APPID_TLS_VERSION_BIT);
        }
    }

    bool is_tls_data_finished() const { return tls_data_finished; }

private:
    char* tls_sni = nullptr;
    char* tls_first_alt_name = nullptr;
    char* tls_cname = nullptr;
    char* tls_org_unit = nullptr;
    bool tls_handshake_done = false;
    bool tls_host_published = false;
    bool tls_host_mismatch = false;
    bool tls_data_finished = false;
    uint16_t tls_version = 0;
    MatchedTlsType matched_tls_type = MATCHED_TLS_NONE;
};

class AppIdSession : public snort::FlowData
{
public:
    AppIdSession(IpProtocol, const snort::SfIp*, uint16_t port, AppIdInspector&,
        OdpContext&, uint32_t asid
#ifndef DISABLE_TENANT_ID
        ,uint32_t tenant_id
#endif
        );
    ~AppIdSession() override;

    static AppIdSession* allocate_session(const snort::Packet*, IpProtocol,
        AppidSessionDirection, AppIdInspector&, OdpContext&);
    static AppIdSession* create_future_session(const snort::Packet*, const snort::SfIp*, uint16_t,
        const snort::SfIp*, uint16_t, IpProtocol, SnortProtocolId, OdpContext&,
        bool swap_app_direction=false, bool bidirectional=false, bool expect_persist=false);
    void initialize_future_session(AppIdSession&, uint64_t);

    snort::Flow* flow = nullptr;
    AppIdConfig& config;
    std::unordered_map<unsigned, AppIdFlowData*> flow_data;
    uint64_t flags = 0;
    uint16_t initiator_port = 0;
#ifndef DISABLE_TENANT_ID
    uint32_t tenant_id = 0;
#endif
    uint32_t asid = 0;

    uint16_t session_packet_count = 0;
    uint16_t init_pkts_without_reply = 0;
    uint64_t init_bytes_without_reply = 0;
    AppId first_pkt_service_id = 0;
    AppId first_pkt_payload_id = 0;
    AppId first_pkt_client_id = 0;
    FirstPktAppIdDiscovered first_pkt_appid_prefix = NO_APPID_FOUND;


    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
    uint8_t previous_tcp_flags = 0;

    // AppId matching service side
    APPID_DISCOVERY_STATE service_disco_state = APPID_DISCO_STATE_NONE;
    SESSION_SERVICE_SEARCH_STATE service_search_state = SESSION_SERVICE_SEARCH_STATE::START;
    ServiceDetector* service_detector = nullptr;
    std::vector<ServiceDetector*> service_candidates;

    // Following field is used only for non-http sessions. For HTTP traffic,
    // this field is maintained inside AppIdHttpSession.
    AppId misc_app_id = APP_ID_NONE;

    // Following field stores AppID detection of which is delegated to external module.
    AppId expected_external_app_id = APP_ID_NONE;

    // AppId matching client side
    APPID_DISCOVERY_STATE client_disco_state = APPID_DISCO_STATE_NONE;
    AppId client_inferred_service_id = APP_ID_NONE;
    ClientDetector* client_detector = nullptr;
    std::map<std::string, ClientDetector*> client_candidates;
    bool tried_reverse_service = false;

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
        uint32_t cpu_profiler_pkt_count;
        uint32_t prev_payload_processing_packets;
        uint64_t processing_time;
        uint64_t prev_payload_processing_time;
    } stats = { 0, 0, 0, 0, 0, 0, 0, 0};

    //appIds picked from encrypted session.
    struct
    {
        AppId service_id;
        AppId client_id;
        AppId payload_id;
        AppId misc_id;
        AppId referred_id;
    } encrypted = { APP_ID_NONE, APP_ID_NONE, APP_ID_NONE, APP_ID_NONE, APP_ID_NONE };

    bool in_expected_cache = false;
    static unsigned inspector_id;
    static std::mutex inferred_svcs_lock;

    static void init() { inspector_id = snort::FlowData::create_flow_data_id(); }

    void set_session_flags(uint64_t set_flags) { flags |= set_flags; }
    void clear_session_flags(uint64_t clear_flags) { flags &= ~clear_flags; }
    uint64_t get_session_flags(uint64_t get_flags) const { return (flags & get_flags); }
    void set_service_detected() { flags |= APPID_SESSION_SERVICE_DETECTED; }
    bool is_service_detected() const { return ((flags & APPID_SESSION_SERVICE_DETECTED) == 0) ?
        false : true; }
    void set_client_detected() { flags |= APPID_SESSION_CLIENT_DETECTED; }
    bool is_client_detected() const { return ((flags & APPID_SESSION_CLIENT_DETECTED) == 0) ?
        false : true; }
    bool is_decrypted() const { return ((flags & APPID_SESSION_DECRYPTED) == 0) ? false : true; }
    bool is_svc_taking_too_much_time() const;

    AppIdFlowData* get_flow_data(unsigned id) const;
    int add_flow_data(AppIdFlowData* data, unsigned id);
    int add_flow_data_id(uint16_t port, ServiceDetector*);
    void free_flow_data_by_id(unsigned id);
    void free_flow_data_by_mask(unsigned mask);
    void free_flow_data();

    AppId pick_service_app_id() const;
    // pick_ss_* and set_ss_* methods below are for application protocols that support only a single
    // stream in a flow. They should not be used for HTTP2/HTTP3 sessions which can have multiple
    // streams within a single flow
    AppId pick_ss_misc_app_id() const;
    AppId pick_ss_client_app_id() const;
    AppId pick_ss_payload_app_id() const;
    AppId check_first_pkt_tp_payload_app_id() const;
    AppId pick_ss_payload_app_id(AppId service_id) const;
    AppId pick_ss_referred_payload_app_id() const;

    void set_ss_application_ids(AppId service, AppId client, AppId payload, AppId misc,
        AppId referred, AppidChangeBits& change_bits);
    void set_ss_application_ids(AppId client, AppId payload, AppidChangeBits& change_bits);
    void set_ss_application_ids_payload(AppId payload, AppidChangeBits& change_bits);
    void set_application_ids_service(AppId service_id, AppidChangeBits& change_bits);

    void examine_ssl_metadata(AppidChangeBits& change_bits, bool partial_inspect = false);
    void set_client_appid_data(AppId, AppidChangeBits& change_bits, char* version = nullptr);
    void set_client_appid_data(AppId, char* version = nullptr, bool published=false);
    void set_service_appid_data(AppId, AppidChangeBits& change_bits, char* version = nullptr);
    void set_payload_appid_data(AppId, char* version = nullptr);
    void check_app_detection_restart(AppidChangeBits& change_bits,
        ThirdPartyAppIdContext* tp_appid_ctxt);
    void check_ssl_detection_restart(AppidChangeBits& change_bits,
        ThirdPartyAppIdContext* tp_appid_ctxt);
    void check_tunnel_detection_restart();
    void update_encrypted_app_id(AppId);
    void examine_rtmp_metadata(AppidChangeBits& change_bits);
    void sync_with_snort_protocol_id(AppId, snort::Packet*, AppidChangeBits&);
    void stop_service_inspection(snort::Packet*,  AppidSessionDirection);

    void clear_http_flags();
    void clear_http_data();
    void reset_session_data(AppidChangeBits& change_bits);

    AppIdHttpSession* get_http_session(uint32_t stream_index = 0) const;
    AppIdHttpSession* create_http_session(int64_t stream_id = -1);
    AppIdHttpSession* get_matching_http_session(int64_t stream_id) const;
    void delete_all_http_sessions();

    AppIdDnsSession* create_dns_session();
    AppIdDnsSession* get_dns_session() const;

    bool is_tp_appid_done() const;
    bool is_tp_processing_done() const;
    bool is_tp_appid_available() const;

    void set_tp_app_id(const snort::Packet& p, AppidSessionDirection dir, AppId app_id,
        AppidChangeBits& change_bits);
    void set_tp_payload_app_id(const snort::Packet& p, AppidSessionDirection dir, AppId app_id,
        AppidChangeBits& change_bits);
    void publish_appid_event(AppidChangeBits&, const snort::Packet&, bool is_httpx = false,
        uint32_t httpx_stream_index = 0);
    void publish_shadow_traffic_event(const uint32_t& shadow_traffic_bits,snort::Flow*);
    void process_shadow_traffic_appids();
    void check_shadow_traffic_bits(AppId id, uint32_t& shadow_bits, AppId &publishing_appid, bool& is_publishing_set);
    void check_domain_fronting_status(const std::string& host);


    bool need_to_delete_tp_conn(ThirdPartyAppIdContext*) const;

    inline void set_tp_app_id(AppId app_id)
    {
        if (tp_app_id != app_id)
        {
            tp_app_id = app_id;
            tp_app_id_deferred = odp_ctxt.get_app_info_mgr().get_app_info_flags
                (tp_app_id, APPINFO_FLAG_DEFER);
        }
    }

    inline void set_tp_payload_app_id(AppId app_id)
    {
        if (tp_payload_app_id != app_id)
        {
            tp_payload_app_id = app_id;
            tp_payload_app_id_deferred = odp_ctxt.get_app_info_mgr().get_app_info_flags
                (tp_payload_app_id, APPINFO_FLAG_DEFER_PAYLOAD);
        }
    }

    inline AppId get_tp_app_id() const
    {
        return tp_app_id;
    }

    inline AppId get_tp_payload_app_id() const
    {
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

    uint16_t get_prev_httpx_raw_packet() const
    {
        return prev_httpx_raw_packet;
    }

    void set_prev_httpx_raw_packet(uint16_t packet_num)
    {
        prev_httpx_raw_packet = packet_num;
    }

    const snort::AppIdSessionApi& get_api() const
    {
        return api;
    }

    AppId get_service_id() const
    {
        return api.service.get_id();
    }

    void set_service_id(AppId id, OdpContext &ctxt)
    {
        api.service.set_id(id, ctxt);
    }

    AppId get_port_service_id() const
    {
        return api.service.get_port_service_id();
    }

    void set_port_service_id(AppId id)
    {
        api.service.set_port_service_id(id);
    }

    void set_service_version(const char* version, AppidChangeBits& change_bits)
    {
        if (!version)
            return;
        api.service.set_version(version);
        change_bits.set(APPID_SERVICE_INFO_BIT);
    }

    void set_service_vendor(const char* vendor, AppidChangeBits& change_bits)
    {
        api.service.set_vendor(vendor, change_bits);
    }

    void add_service_subtype(AppIdServiceSubtype& subtype, AppidChangeBits& change_bits)
    {
        api.service.add_subtype(subtype, change_bits);
    }

    AppId get_client_id() const
    {
        return api.client.get_id();
    }

    void set_client_id(AppId id)
    {
        api.client.set_id(id);
    }

    void set_client_id(const snort::Packet& p, AppidSessionDirection dir, AppId id, AppidChangeBits& change_bits)
    {
        api.client.set_id(p, *this, dir, id, change_bits);
    }

    void set_client_version(const char* version, AppidChangeBits& change_bits)
    {
        if (!version)
            return;
        api.client.set_version(version);
        change_bits.set(APPID_CLIENT_INFO_BIT);
    }

    const char* get_client_user() const
    {
        return api.client.get_username();
    }

    AppId get_client_user_id() const
    {
        return api.client.get_user_id();
    }

    void set_client_user(AppId id, const char* username, AppidChangeBits& change_bits)
    {
        api.client.update_user(id, username, change_bits);
    }

    void set_eve_client_app_id(AppId id)
    {
        api.client.set_eve_client_app_id(id);
    }

    AppId get_eve_client_app_id() const
    {
        return api.client.get_eve_client_app_id();
    }

    bool use_eve_client_app_id() const
    {
        if (api.client.get_eve_client_app_id() <= APP_ID_NONE)
            return false;

        if (get_session_flags(APPID_SESSION_HTTP_SESSION))
        {
            if (odp_ctxt.eve_http_client)
                api.client.reset_version();
            return odp_ctxt.eve_http_client;
        }
        else
            return (api.client.get_id() == APP_ID_SSL_CLIENT or api.client.get_id() <= APP_ID_NONE);
    }

    void set_alpn_service_app_id(AppId id)
    {
        api.service.set_alpn_service_app_id(id);
    }

    AppId get_alpn_service_app_id() const
    {
        return api.service.get_alpn_service_app_id();
    }

    AppId get_payload_id() const
    {
        return api.payload.get_id();
    }

    void set_payload_id(AppId id)
    {
        api.payload.set_id(id);
    }

    const snort::SfIp& get_initiator_ip() const
    {
        return api.initiator_ip;
    }

    void set_initiator_ip(const snort::SfIp& ip)
    {
        api.initiator_ip = ip;
    }

    void set_service_ip(const snort::SfIp& ip)
    {
        api.service.set_service_ip(ip);
    }

    void set_service_port(uint16_t port)
    {
        api.service.set_service_port(port);
    }

    void set_netbios_name(AppidChangeBits& change_bits, const char *name)
    {
        api.set_netbios_name(change_bits, name);
    }

    void set_netbios_domain(AppidChangeBits& change_bits, const char *domain)
    {
        api.set_netbios_domain(change_bits, domain);
    }

    void consume_ha_tls_host(const char* tls_host)
    {
        api.set_tls_host(tls_host);
    }

    OdpContext& get_odp_ctxt() const
    {
        return odp_ctxt;
    }

    uint32_t get_odp_ctxt_version() const
    {
        return odp_ctxt_version;
    }

    ThirdPartyAppIdContext* get_tp_appid_ctxt() const
    {
        return tp_appid_ctxt;
    }

    void set_server_info(const snort::SfIp& ip, uint16_t port, int16_t group = DAQ_PKTHDR_UNKNOWN)
    {
        api.service.set_service_ip(ip);
        api.service.set_service_port(port);
        api.service.set_service_group(group);
    }

    std::tuple<const snort::SfIp*, uint16_t, int16_t>  get_server_info() const
    {
        return std::make_tuple(&api.service.get_service_ip(), api.service.get_service_port(),
            api.service.get_service_group());
    }

    uint16_t get_service_port() const
    {
        return api.service.get_service_port();
    }

    bool is_service_ip_set() const
    {
        return api.service.is_service_ip_set();
    }

    void set_user_logged_in()
    {
        api.set_user_logged_in();
    }

    void clear_user_logged_in()
    {
        api.clear_user_logged_in();
    }

    void set_consumed_ha_data(bool val)
    {
        consumed_ha_data = val;
    }

    bool has_no_service_candidate() const
    {
        return no_service_candidate;
    }

    void set_no_service_candidate()
    {
        no_service_candidate = true;
    }

    bool has_no_service_inspector() const
    {
        return no_service_inspector;
    }

    void set_no_service_inspector()
    {
        no_service_inspector = true;
    }

    void set_client_info_unpublished(bool val)
    {
        client_info_unpublished = val;
    }

    bool is_client_info_unpublished()
    {
        return client_info_unpublished;
    }

    inline bool is_encrypted_oportunistic_tls_session()
    {
        return get_session_flags(APPID_SESSION_OPPORTUNISTIC_TLS) and !flow->flags.data_decrypted;
    }

    void set_shadow_traffic_bits(uint32_t lv_bits)
    {
        appid_shadow_traffic_bits = lv_bits;
    }

    void reset_shadow_traffic_bits()
    {
        appid_shadow_traffic_bits = 0;
    }

    uint32_t get_shadow_traffic_bits()
    {
        return appid_shadow_traffic_bits;
    }

    void set_shadow_traffic_publishing_appid(AppId id)
    {
       shadow_traffic_appid = id;
    }

    AppId get_shadow_traffic_publishing_appid() const
    {
        return shadow_traffic_appid;
    }

    inline void change_shadow_traffic_bits_to_string (const uint32_t& st_bits,std::string& str) const
    {
        std::string tempStr;

        if (st_bits & ShadowTraffic_Type_Encrypted_DNS) {
            tempStr.append("Encrypted_DNS ");
        }
        if (st_bits & ShadowTraffic_Type_Evasive_VPN) {
            tempStr.append("Evasive_VPN ");
        }
        if (st_bits & ShadowTraffic_Type_Multihop_Proxy) {
            tempStr.append("Multihop_Proxy ");
        }
        if (st_bits & ShadowTraffic_Type_Domain_Fronting) {
            tempStr.append("Domain_Fronting ");
        }
        if (!tempStr.empty()) {
            tempStr.pop_back();
        }

        str.append(tempStr);
    }

    void set_cert_key (const std::string& key)
    {
        ssl_cert_key = key;
    }

    const std::string& get_cert_key() const
    {
        return ssl_cert_key;
    }

    void set_previous_shadow_traffic_bits(uint32_t lv_bits)
    {
       appid_previous_shadow_traffic_bits = lv_bits;
    }

    uint32_t get_previous_shadow_traffic_bits()
    {
        return appid_previous_shadow_traffic_bits;
    }

private:
    uint16_t prev_httpx_raw_packet = 0;

    void reinit_session_data(AppidChangeBits& change_bits, ThirdPartyAppIdContext* tp_appid_ctxt);
    void delete_session_data();

    bool tp_app_id_deferred = false;
    bool tp_payload_app_id_deferred = false;

    // appId determined by 3rd party library
    AppId tp_app_id = APP_ID_NONE;
    AppId tp_payload_app_id = APP_ID_NONE;

    uint16_t my_inferred_svcs_ver = 0;
    snort::AppIdSessionApi& api;
    static uint16_t inferred_svcs_ver;
    OdpContext& odp_ctxt;
    uint32_t odp_ctxt_version;
    ThirdPartyAppIdContext* tp_appid_ctxt = nullptr;
    bool consumed_ha_data = false;
    bool no_service_candidate = false;
    bool no_service_inspector = false;
    bool client_info_unpublished = false;
    string ssl_cert_key;
    uint32_t appid_shadow_traffic_bits = 0;
    uint32_t appid_previous_shadow_traffic_bits = 0;
    AppId shadow_traffic_appid = APP_ID_NONE;
};

#endif
