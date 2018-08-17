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

// appid_session.h author Sourcefire Inc.

#ifndef APPID_SESSION_H
#define APPID_SESSION_H

#include <map>
#include <string>
#include <unordered_map>

#include "detector_plugins/http_url_patterns.h"
#include "app_info_table.h"
#include "appid_api.h"
#include "appid_app_descriptor.h"
#include "appid_types.h"
#include "application_ids.h"
#include "length_app_cache.h"
#include "service_state.h"

class ClientDetector;
class ServiceDetector;
class AppIdDnsSession;
class AppIdHttpSession;
class ThirdPartyAppIDSession;

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
        if ( fd_data && fd_free )
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

    snort::APPID_FLOW_TYPE flow_type = snort::APPID_FLOW_TYPE_IGNORE;
    unsigned policyId = 0;
    //flags shared with other preprocessor via session attributes.
    uint64_t flags = 0;
    snort::SfIp initiator_ip;
    uint16_t initiator_port = 0;
};

// FIXIT-L: make these const strings
struct TlsSession
{
    char* tls_host = nullptr;
    int tls_host_strlen = 0;     // FIXIT-M: not rvalue, remove
    char* tls_cname = nullptr;
    int tls_cname_strlen = 0;    // FIXIT-M: not rvalue, remove
    char* tls_orgUnit = nullptr;
    int tls_orgUnit_strlen = 0;  // FIXiT-M: not rvalue, remove

    void set_tls_host(const char* new_tls_host, uint32_t len)
    {
        if (tls_host) snort_free(tls_host);
        tls_host = snort::snort_strndup(new_tls_host,len);
        tls_host_strlen = len;
    }

    void set_tls_cname(const char* new_tls_cname, uint32_t len)
    {
        if (tls_cname) snort_free(tls_cname);
        tls_cname = snort::snort_strndup(new_tls_cname,len);
        tls_cname_strlen = len;
    }

    void set_tls_org_unit(const char* new_tls_org_unit, uint32_t len)
    {
        if (tls_orgUnit) snort_free(tls_orgUnit);
        tls_orgUnit = snort::snort_strndup(new_tls_org_unit,len);
        tls_orgUnit_strlen = len;
    }
};

class AppIdSession : public snort::FlowData
{
public:
    AppIdSession(IpProtocol, const snort::SfIp*, uint16_t port, AppIdInspector&);
    ~AppIdSession() override;

    static AppIdSession* allocate_session(const snort::Packet*, IpProtocol,
        AppidSessionDirection, AppIdInspector&);
    static AppIdSession* create_future_session(const snort::Packet*, const snort::SfIp*, uint16_t,
        const snort::SfIp*,
        uint16_t, IpProtocol, SnortProtocolId, int, AppIdInspector&);

    AppIdInspector& get_inspector() const
    {
        return inspector;
    }

    uint32_t session_id = 0;
    snort::Flow* flow = nullptr;
    AppIdConfig* config;
    std::unordered_map<unsigned, AppIdFlowData*> flow_data;
    AppInfoManager* app_info_mgr = nullptr;
    CommonAppIdData common;
    uint16_t session_packet_count = 0;

    snort::SfIp service_ip;
    uint16_t service_port = 0;
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
    uint8_t previous_tcp_flags = 0;

    // AppId matching service side
    APPID_DISCOVERY_STATE service_disco_state = APPID_DISCO_STATE_NONE;
    SESSION_SERVICE_SEARCH_STATE service_search_state = SESSION_SERVICE_SEARCH_STATE::START;
    ServiceDetector* service_detector = nullptr;
    snort::AppIdServiceSubtype* subtype = nullptr;
    std::vector<ServiceDetector*> service_candidates;
    ServiceAppDescriptor service;
    ClientAppDescriptor client;
    PayloadAppDescriptor payload;

    // AppId matching client side
    APPID_DISCOVERY_STATE client_disco_state = APPID_DISCO_STATE_NONE;
    AppId client_inferred_service_id = APP_ID_NONE;
    ClientDetector* client_detector = nullptr;
    std::map<std::string, ClientDetector*> client_candidates;
    bool tried_reverse_service = false;

    AppId referred_payload_app_id = APP_ID_NONE;
    AppId misc_app_id = APP_ID_NONE;


    // FIXIT-M netbios_name is never set to a valid value
    char* netbios_name = nullptr;
    char* netbios_domain = nullptr;

    TlsSession* tsession = nullptr;
    unsigned scan_flags = 0;
    ThirdPartyAppIDSession* tpsession = nullptr;
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

    void* firewall_early_data = nullptr;
    AppId past_indicator = APP_ID_NONE;
    AppId past_forecast = APP_ID_NONE;

    bool is_http2 = false;
    snort::SEARCH_SUPPORT_TYPE search_support_type = snort::UNKNOWN_SEARCH_ENGINE;
    bool in_expected_cache = false;
    static unsigned inspector_id;
    static void init() { inspector_id = FlowData::create_flow_data_id(); }

    void set_session_flags(uint64_t flags) { common.flags |= flags; }
    void clear_session_flags(uint64_t flags) { common.flags &= ~flags; }
    uint64_t get_session_flags(uint64_t flags) const { return (common.flags & flags); }
    void set_service_detected() { common.flags |= APPID_SESSION_SERVICE_DETECTED; }
    bool is_service_detected() { return common.flags & APPID_SESSION_SERVICE_DETECTED; }
    void set_client_detected() { common.flags |= APPID_SESSION_CLIENT_DETECTED; }
    bool is_client_detected() { return common.flags & APPID_SESSION_CLIENT_DETECTED; }
    bool is_decrypted() { return common.flags & APPID_SESSION_DECRYPTED; }

    void* get_flow_data(unsigned id);
    int add_flow_data(void* data, unsigned id, AppIdFreeFCN);
    int add_flow_data_id(uint16_t port, ServiceDetector*);
    void* remove_flow_data(unsigned id);
    void free_flow_data_by_id(unsigned id);
    void free_flow_data_by_mask(unsigned mask);
    void free_tls_session_data();
    void free_flow_data();

    AppId pick_service_app_id();
    AppId pick_only_service_app_id();
    AppId pick_misc_app_id();
    AppId pick_client_app_id();
    AppId pick_payload_app_id();
    AppId pick_referred_payload_app_id();
    void set_application_ids(AppId service, AppId client, AppId payload, AppId misc);
    void get_application_ids(AppId& service, AppId& client, AppId& payload, AppId& misc);
    void get_application_ids(AppId& service, AppId& client, AppId& payload);
    AppId get_application_ids_service();
    AppId get_application_ids_client();
    AppId get_application_ids_payload();
    AppId get_application_ids_misc();

    bool is_ssl_session_decrypted();
    void examine_ssl_metadata(snort::Packet*);
    void set_client_appid_data(AppId, char*);
    void set_service_appid_data(AppId, char*, char*);
    void set_referred_payload_app_id_data(AppId);
    void set_payload_appid_data(AppId, char*);
    void check_app_detection_restart();
    void update_encrypted_app_id(AppId);
    void examine_rtmp_metadata();
    void sync_with_snort_protocol_id(AppId, snort::Packet*);
    void stop_rna_service_inspection(snort::Packet*,  AppidSessionDirection);

    bool is_payload_appid_set();
    void clear_http_flags();
    void clear_http_data();
    void reset_session_data();

    AppIdHttpSession* get_http_session();
    AppIdDnsSession* get_dns_session();

    bool is_tp_appid_done() const;
    bool is_tp_processing_done() const;
    bool is_tp_appid_available() const;

    inline void set_tp_app_id(AppId app_id) {
        if(tp_app_id != app_id) {
            tp_app_id = app_id;
            tp_app_id_deferred = app_info_mgr->get_app_info_flags(tp_app_id, APPINFO_FLAG_DEFER);
        }
    }

    inline void set_tp_payload_app_id(AppId app_id) {
        if(tp_payload_app_id != app_id) {
            tp_payload_app_id = app_id;
            tp_payload_app_id_deferred = app_info_mgr->get_app_info_flags(tp_payload_app_id, APPINFO_FLAG_DEFER_PAYLOAD);
        }
    }

    inline AppId get_tp_app_id() {
        return tp_app_id;
    }

    inline AppId get_tp_payload_app_id() {
        return tp_payload_app_id;
    }

private:
    AppIdHttpSession* hsession = nullptr;
    AppIdDnsSession* dsession = nullptr;

    void reinit_session_data();
    void delete_session_data();

    static THREAD_LOCAL uint32_t appid_flow_data_id;
    AppId application_ids[APP_PROTOID_MAX];
    AppIdInspector& inspector;
    bool tp_app_id_deferred = false;
    bool tp_payload_app_id_deferred = false;

    // appId determined by 3rd party library
    AppId tp_app_id = APP_ID_NONE;
    AppId tp_payload_app_id = APP_ID_NONE;
};

#endif

