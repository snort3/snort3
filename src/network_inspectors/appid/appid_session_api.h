//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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
#include "flow/stash_item.h"
#include "main/snort_types.h"
#include "pub_sub/appid_events.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"
#include "appid_dns_session.h"
#include "appid_http_session.h"
#include "application_ids.h"

class AppIdDnsSession;
class AppIdSession;

namespace snort
{
#define APPID_SESSION_RESPONDER_MONITORED   (1ULL << 0)
#define APPID_SESSION_INITIATOR_MONITORED   (1ULL << 1)
#define APPID_SESSION_SPECIAL_MONITORED     (1ULL << 2)
#define APPID_SESSION_FUTURE_FLOW           (1ULL << 3)
#define APPID_SESSION_EXPECTED_EVALUATE     (1ULL << 4)
#define APPID_SESSION_DISCOVER_USER         (1ULL << 5)
#define APPID_SESSION_HAS_DHCP_FP           (1ULL << 6)
#define APPID_SESSION_HAS_DHCP_INFO         (1ULL << 7)
#define APPID_SESSION_HAS_SMB_INFO          (1ULL << 8)
#define APPID_SESSION_MID                   (1ULL << 9)
#define APPID_SESSION_OOO                   (1ULL << 10)
#define APPID_SESSION_SYN_RST               (1ULL << 11)
// Service missed the first UDP packet in a flow. This causes detectors to see traffic in reverse direction.
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
#define APPID_SESSION_SPDY_SESSION          (1ULL << 29)
#define APPID_SESSION_ENCRYPTED             (1ULL << 30)
#define APPID_SESSION_APP_REINSPECT         (1ULL << 31)
#define APPID_SESSION_RESPONSE_CODE_CHECKED (1ULL << 32)
#define APPID_SESSION_REXEC_STDERR          (1ULL << 33)
#define APPID_SESSION_CHP_INSPECTING        (1ULL << 34)
#define APPID_SESSION_STICKY_SERVICE        (1ULL << 35)
#define APPID_SESSION_APP_REINSPECT_SSL     (1ULL << 36)
#define APPID_SESSION_NO_TPI                (1ULL << 37)
#define APPID_SESSION_FUTURE_FLOW_IDED      (1ULL << 38)
#define APPID_SESSION_OOO_CHECK_TP          (1ULL << 39)
#define APPID_SESSION_PAYLOAD_SEEN          (1ULL << 40)
#define APPID_SESSION_HOST_CACHE_MATCHED    (1ULL << 41)
#define APPID_SESSION_DECRYPT_MONITOR       (1ULL << 42)
#define APPID_SESSION_HTTP_TUNNEL           (1ULL << 43)
#define APPID_SESSION_OPPORTUNISTIC_TLS     (1ULL << 44)
#define APPID_SESSION_IGNORE_ID_FLAGS \
    (APPID_SESSION_FUTURE_FLOW | \
    APPID_SESSION_NOT_A_SERVICE | \
    APPID_SESSION_NO_TPI | \
    APPID_SESSION_SERVICE_DETECTED | \
    APPID_SESSION_PORT_SERVICE_DONE)
const uint64_t APPID_SESSION_ALL_FLAGS = 0xFFFFFFFFFFFFFFFFULL;

class SO_PUBLIC AppIdSessionApi : public StashGenericObject
{
public:
    AppId get_service_app_id() const;
    void get_service_info(const char*& vendor, const char*& version,
        const AppIdServiceSubtype*& subtype) const;
    const char* get_user_info(AppId& service, bool& login) const;
    AppId get_misc_app_id(uint32_t stream_index = 0) const;
    AppId get_client_app_id(uint32_t stream_index = 0) const;
    AppId get_payload_app_id(uint32_t stream_index = 0) const;
    AppId get_referred_app_id(uint32_t stream_index = 0) const;
    void get_app_id(AppId& service, AppId& client, AppId& payload, AppId& misc, AppId& referred,
        uint32_t stream_index = 0) const;
    void get_app_id(AppId* service, AppId* client, AppId* payload, AppId* misc, AppId* referred,
        uint32_t stream_index = 0) const;
    bool is_appid_inspecting_session() const;
    bool is_appid_available(uint32_t stream_index = 0) const;
    const char* get_client_info(uint32_t stream_index = 0) const;
    uint64_t get_appid_session_attribute(uint64_t flag) const;
    const SfIp* get_initiator_ip() const;
    const SfIp& get_service_ip() const;
    uint16_t get_service_port() const;
    const AppIdDnsSession* get_dns_session() const;
    const AppIdHttpSession* get_http_session(uint32_t stream_index = 0) const;
    const char* get_tls_host() const;
    bool is_http_inspection_done() const;
    const char* get_netbios_name() const;
    const char* get_netbios_domain() const;
    ClientAppDetectType get_client_app_detect_type() const;

    // For protocols such as HTTP2 which can have multiple streams within a single flow,
    // get_first_stream_* methods return the appids in the first stream seen in a packet.
    void get_first_stream_app_ids(AppId& service, AppId& client, AppId& payload, AppId& misc) const;
    void get_first_stream_app_ids(AppId& service, AppId& client, AppId& payload) const;

    ~AppIdSessionApi() override
    {
        delete_session_data();
    }

    uint32_t get_hsessions_size() const
    {
        return hsessions.size();
    }

    const std::string& get_session_id() const
    {
        return session_id;
    }

    void set_user_logged_in() { user_logged_in = true; }

    void clear_user_logged_in() { user_logged_in = false; }

protected:
    AppIdSessionApi(const AppIdSession* asd, const SfIp& ip);

private:
    const AppIdSession* asd = nullptr;
    AppId application_ids[APP_PROTOID_MAX] =
        { APP_ID_NONE, APP_ID_NONE, APP_ID_NONE, APP_ID_NONE, APP_ID_NONE };
    bool published = false;
    bool stored_in_stash = false;
    std::vector<AppIdHttpSession*> hsessions;
    AppIdDnsSession* dsession = nullptr;
    snort::SfIp initiator_ip;
    ServiceAppDescriptor service;
    char* tls_host = nullptr;
    char* netbios_name = nullptr;
    char* netbios_domain = nullptr;
    std::string session_id;
    bool user_logged_in = false;

    // Following two fields are used only for non-http sessions. For HTTP traffic,
    // these fields are maintained inside AppIdHttpSession.
    // Note: RTMP traffic is treated like HTTP in AppId
    ClientAppDescriptor client;
    PayloadAppDescriptor payload;

    static THREAD_LOCAL uint32_t appid_flow_data_id;

    void set_ss_application_ids(AppId service, AppId client, AppId payload, AppId misc,
        AppId referred, AppidChangeBits& change_bits, Flow& flow);
    void set_ss_application_ids(AppId client, AppId payload, AppidChangeBits& change_bits, Flow& flow);
    void set_application_ids_service(AppId service_id, AppidChangeBits& change_bits, Flow& flow);
    void set_netbios_name(AppidChangeBits& change_bits, const char* name);
    void set_netbios_domain(AppidChangeBits& change_bits, const char* domain);

    AppIdHttpSession* get_hsession(uint32_t stream_index = 0) const;

    void delete_session_data()
    {
        delete_all_http_sessions();
        snort_free(tls_host);
        snort_free(netbios_name);
        snort_free(netbios_domain);
        delete dsession;
    }

    void delete_all_http_sessions()
    {
        for (auto hsession : hsessions)
            delete hsession;
        hsessions.clear();
    }

    void set_tls_host(const char* host)
    {
        if (host)
        {
            if (tls_host)
                snort_free(tls_host);
            tls_host = snort_strdup(host);
        }
    }

    friend AppIdSession;
};

}
#endif
