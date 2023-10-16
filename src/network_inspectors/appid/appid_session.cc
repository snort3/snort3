//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// appid_session.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_session.h"

#include <cstring>

#include "flow/flow_stash.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "pub_sub/appid_events.h"
#include "stream/stream.h"
#include "target_based/snort_protocols.h"
#include "time/packet_time.h"

#include "app_info_table.h"
#include "appid_config.h"
#include "appid_debug.h"
#include "appid_dns_session.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "appid_session_api.h"
#include "appid_stats.h"
#include "lua_detector_api.h"
#include "service_plugins/service_ssl.h"
#include "tp_lib_handler.h"

using namespace snort;

unsigned AppIdSession::inspector_id = 0;
std::mutex AppIdSession::inferred_svcs_lock;
uint16_t AppIdSession::inferred_svcs_ver = 0;

const uint8_t* service_strstr(const uint8_t* haystack, unsigned haystack_len,
    const uint8_t* needle, unsigned needle_len)
{
    const uint8_t* h_end = haystack + haystack_len;

    for (const uint8_t* p = haystack; h_end-p >= (int)needle_len; p++)
    {
        if (memcmp(p, needle, needle_len) == 0)
        {
            return p;
        }
    }

    return nullptr;
}

static inline bool is_special_session_monitored(const Packet* p)
{
    if (p->is_ip4())
    {
        if (p->is_udp() and ((p->ptrs.sp == 68 and p->ptrs.dp == 67)
            or (p->ptrs.sp == 67 and  p->ptrs.dp == 68)))
        {
            return true;
        }
    }
    return false;
}

static void is_session_monitored(uint64_t& flow_flags, const Packet* p,
    AppIdInspector& inspector)
{

    DiscoveryFilter* filter = inspector.get_ctxt().get_discovery_filter();
    if (filter and filter->is_app_monitored(p))
    {
        flow_flags |= APPID_SESSION_DISCOVER_APP;
        flow_flags |= APPID_SESSION_DISCOVER_USER;
        if (is_special_session_monitored(p))
            flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
    }
    else if (!filter)
        flow_flags |= (APPID_SESSION_SPECIAL_MONITORED | APPID_SESSION_DISCOVER_USER |
            APPID_SESSION_DISCOVER_APP);

}

AppIdSession* AppIdSession::allocate_session(const Packet* p, IpProtocol proto,
    AppidSessionDirection direction, AppIdInspector& inspector, OdpContext& odp_context)
{
    uint16_t port = 0;

    const SfIp* ip = (direction == APP_ID_FROM_INITIATOR)
        ? p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst();
    if ((proto == IpProtocol::TCP or proto == IpProtocol::UDP) and
        (p->ptrs.sp != p->ptrs.dp))
        port = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.sp : p->ptrs.dp;

    AppIdSession* asd = new AppIdSession(proto, ip, port, inspector, odp_context,
        p->pkth->address_space_id);
    is_session_monitored(asd->flags, p, inspector);
    asd->flow = p->flow;
    asd->stats.first_packet_second = p->pkth->ts.tv_sec;
    asd->snort_protocol_id = asd->config.snort_proto_ids[PROTO_INDEX_UNSYNCHRONIZED];
    p->flow->set_flow_data(asd);
    return asd;
}

AppIdSession::AppIdSession(IpProtocol proto, const SfIp* ip, uint16_t port,
    AppIdInspector& inspector, OdpContext& odp_ctxt, uint32_t asid)
    : FlowData(inspector_id, &inspector), config(inspector.get_ctxt().config),
        initiator_port(port), asid(asid), protocol(proto),
        api(*(new AppIdSessionApi(this, *ip))), odp_ctxt(odp_ctxt),
        odp_ctxt_version(odp_ctxt.get_version()),
        tp_appid_ctxt(pkt_thread_tp_appid_ctxt)
{
    appid_stats.total_sessions++;
}

AppIdSession::~AppIdSession()
{
    if (!in_expected_cache)
    {
        if (config.log_stats)
            AppIdStatistics::get_stats_manager()->update(*this);

        // fail any service detection that is in process for this flow
        if (!get_session_flags(APPID_SESSION_SERVICE_DETECTED |
            APPID_SESSION_UDP_REVERSED | APPID_SESSION_MID |
            APPID_SESSION_OOO) and flow)
        {
            const SfIp& svc_ip = api.service.get_service_ip();
            ServiceDiscoveryState* sds =
                AppIdServiceState::get(&svc_ip, protocol, api.service.get_service_port(),
                    api.service.get_service_group(), asid, is_decrypted());
            if (sds)
            {
                if (flow->server_ip.fast_eq6(svc_ip))
                    sds->set_service_id_failed(*this, &flow->client_ip,
                        STATE_ID_INCONCLUSIVE_SERVICE_WEIGHT);
                else
                    sds->set_service_id_failed(*this, &flow->server_ip,
                        STATE_ID_INCONCLUSIVE_SERVICE_WEIGHT);
            }
        }
    }

    if (tpsession)
    {
        if (need_to_delete_tp_conn(pkt_thread_tp_appid_ctxt))
            tpsession->delete_with_ctxt();
        else
            delete tpsession;
    }

    delete tsession;
    free_flow_data();
    service_candidates.clear();
    client_candidates.clear();

    // If api was not stored in the stash, delete it. An example would be when an appid future
    // session is created, but it doesn't get attached to a snort flow (because the packets for the
    // future session were never received by snort), api object is not stored in the stash.
    if (!api.flags.stored_in_stash)
        delete &api;
    else
        api.asd = nullptr;
}

// FIXIT-RC X Move this to somewhere more generally available/appropriate (decode_data.h).
static inline PktType get_pkt_type_from_ip_proto(IpProtocol proto)
{
    switch (proto)
    {
    case IpProtocol::TCP:
        return PktType::TCP;
    case IpProtocol::UDP:
        return PktType::UDP;
    case IpProtocol::ICMPV4:
        return PktType::ICMP;
    case IpProtocol::IP:
        return PktType::IP;
    default:
        break;
    }
    return PktType::NONE;
}

AppIdSession* AppIdSession::create_future_session(const Packet* ctrlPkt, const SfIp* cliIp,
    uint16_t cliPort, const SfIp* srvIp, uint16_t srvPort, IpProtocol proto,
    SnortProtocolId snort_protocol_id, OdpContext& odp_ctxt, bool swap_app_direction,
    bool bidirectional, bool expect_persist)
{
    enum PktType type = get_pkt_type_from_ip_proto(proto);

    if (type == PktType::NONE)
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Failed to create a related flow - invalid protocol %u\n",
                appidDebug->get_debug_session(), (unsigned)proto);
        return nullptr;
    }

    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    AppIdInspector* inspector = (AppIdInspector*)ctrlPkt->flow->flow_data->get_handler();
    if ((inspector == nullptr) or strcmp(inspector->get_name(), MOD_NAME))
        inspector = (AppIdInspector*)InspectorManager::get_inspector(MOD_NAME, true);

    // FIXIT-RC - port parameter passed in as 0 since we may not know client port, verify

    AppIdSession* asd = new AppIdSession(proto, cliIp, 0, *inspector, odp_ctxt,
        ctrlPkt->pkth->address_space_id);
    is_session_monitored(asd->flags, ctrlPkt, *inspector);

    if (Stream::set_snort_protocol_id_expected(ctrlPkt, type, proto, cliIp,
        cliPort, srvIp, srvPort, snort_protocol_id, asd, swap_app_direction, false,
        bidirectional, expect_persist))
    {
        if (appidDebug->is_active())
        {
            sfip_ntop(cliIp, src_ip, sizeof(src_ip));
            sfip_ntop(srvIp, dst_ip, sizeof(dst_ip));
            LogMessage("AppIdDbg %s Failed to create a related flow for %s-%u -> %s-%u %u\n",
                appidDebug->get_debug_session(), src_ip, (unsigned)cliPort, dst_ip,
                (unsigned)srvPort, (unsigned)proto);
        }
        delete asd;
        asd = nullptr;
    }
    else
    {
        if (appidDebug->is_active())
        {
            sfip_ntop(cliIp, src_ip, sizeof(src_ip));
            sfip_ntop(srvIp, dst_ip, sizeof(dst_ip));
            LogMessage("AppIdDbg %s Related flow created for %s-%u -> %s-%u %u\n",
                appidDebug->get_debug_session(),
                src_ip, (unsigned)cliPort, dst_ip, (unsigned)srvPort, (unsigned)proto);
        }
        asd->in_expected_cache = true;
    }

    return asd;
}

void AppIdSession::initialize_future_session(AppIdSession& expected, uint64_t flags)
{

    expected.set_session_flags(flags |
        get_session_flags(
        APPID_SESSION_SPECIAL_MONITORED |
        APPID_SESSION_DISCOVER_APP |
        APPID_SESSION_DISCOVER_USER));

    expected.service_disco_state = APPID_DISCO_STATE_FINISHED;
    expected.client_disco_state = APPID_DISCO_STATE_FINISHED;
}

void AppIdSession::reinit_session_data(AppidChangeBits& change_bits,
    ThirdPartyAppIdContext* curr_tp_appid_ctxt)
{
    misc_app_id = APP_ID_NONE;

    //data
    if (is_service_over_ssl(tp_app_id))
    {
        api.payload.reset();
        tp_payload_app_id = APP_ID_NONE;
        clear_session_flags(APPID_SESSION_CONTINUE);
        if (!api.hsessions.empty())
            api.hsessions[0]->set_field(MISC_URL_FID, nullptr, change_bits);
    }

    //service
    if (!get_session_flags(APPID_SESSION_STICKY_SERVICE))
    {
        api.service.reset();
        tp_app_id = APP_ID_NONE;
        service_disco_state = APPID_DISCO_STATE_NONE;
        service_detector = nullptr;
        service_search_state = SESSION_SERVICE_SEARCH_STATE::START;
        free_flow_data_by_mask(APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);
    }

    //client
    api.client.reset();
    client_inferred_service_id = APP_ID_NONE;
    client_disco_state = APPID_DISCO_STATE_NONE;
    free_flow_data_by_mask(APPID_SESSION_DATA_CLIENT_MODSTATE_BIT);

    //3rd party cleaning
    if (tpsession and need_to_delete_tp_conn(curr_tp_appid_ctxt))
        tpsession->reset();
    else if (tpsession)
        tpsession->set_state(TP_STATE_TERMINATED);

    init_tpPackets = 0;
    resp_tpPackets = 0;

    scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
    clear_session_flags(APPID_SESSION_SERVICE_DETECTED |
        APPID_SESSION_CLIENT_DETECTED | APPID_SESSION_SSL_SESSION |
        APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT);
}

void AppIdSession::sync_with_snort_protocol_id(AppId newAppId, Packet* p)
{
    if (newAppId  <= APP_ID_NONE or newAppId >= SF_APPID_MAX)
        return;

    // Certain AppIds are not useful to identifying snort inspector choices
    switch (newAppId)
    {
    case APP_ID_FTPS:
    case APP_ID_FTPSDATA:

    // These all are variants of HTTPS
    case APP_ID_DDM_SSL:
    case APP_ID_MSFT_GC_SSL:
    case APP_ID_NSIIOPS:
    case APP_ID_SF_APPLIANCE_MGMT:
    case APP_ID_HTTPS:

    case APP_ID_IMAPS:
    case APP_ID_IRCS:
    case APP_ID_LDAPS:
    case APP_ID_NNTPS:
    case APP_ID_POP3S:
    case APP_ID_SMTPS:
    case APP_ID_SSHELL:
    case APP_ID_TELNETS:
        return;

    default:
            break;
    }

    AppInfoTableEntry* entry = odp_ctxt.get_app_info_mgr().get_app_info_entry(newAppId);
    if (!entry)
        return;

    SnortProtocolId tmp_snort_protocol_id = entry->snort_protocol_id;
    // A particular APP_ID_xxx may not be assigned a service_snort_key value
    // in the appMapping.data file entry; so ignore the snort_protocol_id ==
    // UNKNOWN_PROTOCOL_ID case.
    if (tmp_snort_protocol_id != snort_protocol_id)
    {
        snort_protocol_id = tmp_snort_protocol_id;
        Stream::set_snort_protocol_id(p->flow, tmp_snort_protocol_id, true);
    }
}

void AppIdSession::check_ssl_detection_restart(AppidChangeBits& change_bits,
    ThirdPartyAppIdContext* curr_tp_appid_ctxt)
{
    if (get_session_flags(APPID_SESSION_DECRYPTED) or !flow->is_proxied())
        return;

    AppId service_id = pick_service_app_id();
    bool isSsl = is_service_over_ssl(service_id);

    // A session could either:
    // 1. Start off as SSL - captured with isSsl flag, OR
    // 2. It could start off as a non-SSL session and later change to SSL. For example, FTP->FTPS.
    //    In this case APPID_SESSION_ENCRYPTED flag is set by the protocol state machine.
    if (get_session_flags(APPID_SESSION_ENCRYPTED) or isSsl)
    {
        set_session_flags(APPID_SESSION_DECRYPTED);
        encrypted.service_id = service_id;
        encrypted.payload_id = pick_ss_payload_app_id();
        encrypted.client_id = pick_ss_client_app_id();
        encrypted.misc_id = pick_ss_misc_app_id();
        encrypted.referred_id = pick_ss_referred_payload_app_id();

        reinit_session_data(change_bits, curr_tp_appid_ctxt);
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s SSL decryption is available, restarting app detection\n",
                appidDebug->get_debug_session());

        // APPID_SESSION_ENCRYPTED is set upon receiving a command which upgrades the session to
        // SSL. Next packet after the command will have encrypted traffic.  In the case of a
        // session which starts as SSL, current packet itself is encrypted. Set the special flag
        // APPID_SESSION_APP_REINSPECT_SSL which allows reinspection of this packet.
        if (isSsl)
            set_session_flags(APPID_SESSION_APP_REINSPECT_SSL);
    }
}

void AppIdSession::check_tunnel_detection_restart()
{
    if (tp_payload_app_id != APP_ID_HTTP_TUNNEL or get_session_flags(APPID_SESSION_HTTP_TUNNEL))
        return;

    AppIdHttpSession* hsession = get_http_session();
    if (!hsession or !hsession->get_tunnel())
        return;

    if (appidDebug->is_active())
        LogMessage("AppIdDbg %s Found HTTP Tunnel, restarting app Detection\n",
            appidDebug->get_debug_session());

    // service
    if (api.service.get_id() == api.service.get_port_service_id())
        api.service.set_id(APP_ID_NONE, odp_ctxt);
    api.service.set_port_service_id(APP_ID_NONE);
    api.service.reset();
    service_disco_state = APPID_DISCO_STATE_NONE;
    service_detector = nullptr;
    free_flow_data_by_mask(APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);

    // client
    api.client.reset();
    client_inferred_service_id = APP_ID_NONE;
    client_disco_state = APPID_DISCO_STATE_NONE;
    free_flow_data_by_mask(APPID_SESSION_DATA_CLIENT_MODSTATE_BIT);
    client_candidates.clear();

    init_tpPackets = 0;
    resp_tpPackets = 0;
    scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
    clear_session_flags(APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_CLIENT_DETECTED |
        APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT);

    set_session_flags(APPID_SESSION_HTTP_TUNNEL);

}

void AppIdSession::check_app_detection_restart(AppidChangeBits& change_bits,
    ThirdPartyAppIdContext* curr_tp_appid_ctxt)
{
    check_ssl_detection_restart(change_bits, curr_tp_appid_ctxt);
    check_tunnel_detection_restart();
}

void AppIdSession::update_encrypted_app_id(AppId service_id)
{
    switch (service_id)
    {
    case APP_ID_HTTP:
        if (misc_app_id == APP_ID_NSIIOPS or
            misc_app_id == APP_ID_DDM_SSL or
            misc_app_id == APP_ID_MSFT_GC_SSL or
            misc_app_id == APP_ID_SF_APPLIANCE_MGMT)
        {
            break;
        }
        misc_app_id = APP_ID_HTTPS;
        break;
    case APP_ID_SMTP:
        misc_app_id = APP_ID_SMTPS;
        break;
    case APP_ID_NNTP:
        misc_app_id = APP_ID_NNTPS;
        break;
    case APP_ID_IMAP:
        misc_app_id = APP_ID_IMAPS;
        break;
    case APP_ID_SHELL:
        misc_app_id = APP_ID_SSHELL;
        break;
    case APP_ID_LDAP:
        misc_app_id = APP_ID_LDAPS;
        break;
    case APP_ID_FTP_DATA:
        misc_app_id = APP_ID_FTPSDATA;
        break;
    case APP_ID_FTP:
        misc_app_id = APP_ID_FTPS;
        break;
    case APP_ID_TELNET:
        misc_app_id = APP_ID_TELNET;
        break;
    case APP_ID_IRC:
        misc_app_id = APP_ID_IRCS;
        break;
    case APP_ID_POP3:
        misc_app_id = APP_ID_POP3S;
        break;
    case APP_ID_HTTP3:
    case APP_ID_SMB_OVER_QUIC:
        misc_app_id = APP_ID_QUIC;
    default:
        break;
    }
}

void AppIdSession::examine_ssl_metadata(AppidChangeBits& change_bits)
{
    AppId client_id = 0;
    AppId payload_id = 0;
    const char* tls_str = tsession->get_tls_host();

    if (scan_flags & SCAN_CERTVIZ_ENABLED_FLAG)
        return;

    if ((scan_flags & SCAN_SSL_HOST_FLAG) and tls_str)
    {
        size_t size = strlen(tls_str);
        if (odp_ctxt.get_ssl_matchers().scan_hostname((const uint8_t*)tls_str, size,
            client_id, payload_id))
        {
            if (api.client.get_id() == APP_ID_NONE or api.client.get_id() == APP_ID_SSL_CLIENT)
                set_client_appid_data(client_id, change_bits);
            set_payload_appid_data(payload_id);
        }
        scan_flags &= ~SCAN_SSL_HOST_FLAG;
    }
    if ((scan_flags & SCAN_SSL_CERTIFICATE_FLAG) and (tls_str = tsession->get_tls_cname()))
    {
        size_t size = strlen(tls_str);
        if (odp_ctxt.get_ssl_matchers().scan_cname((const uint8_t*)tls_str, size,
            client_id, payload_id))
        {
            if (api.client.get_id() == APP_ID_NONE or api.client.get_id() == APP_ID_SSL_CLIENT)
                set_client_appid_data(client_id, change_bits);
            set_payload_appid_data(payload_id);
        }
        scan_flags &= ~SCAN_SSL_CERTIFICATE_FLAG;
    }
    if ((tls_str = tsession->get_tls_org_unit()))
    {
        size_t size = strlen(tls_str);
        if (odp_ctxt.get_ssl_matchers().scan_cname((const uint8_t*)tls_str, size,
            client_id, payload_id))
        {
            set_client_appid_data(client_id, change_bits);
            set_payload_appid_data(payload_id);
        }
        tsession->set_tls_org_unit(nullptr, 0);
    }
    if (tsession->get_tls_handshake_done() and
        api.payload.get_id() == APP_ID_NONE)
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s End of SSL/TLS handshake detected with no payloadAppId, "
                "so setting to unknown\n", appidDebug->get_debug_session());
        api.payload.set_id(APP_ID_UNKNOWN);
    }
}

void AppIdSession::examine_rtmp_metadata(AppidChangeBits& change_bits)
{
    AppId service_id = APP_ID_NONE;
    AppId client_id = APP_ID_NONE;
    AppId payload_id = APP_ID_NONE;
    AppId referred_payload_id = APP_ID_NONE;
    char* version = nullptr;

    AppIdHttpSession* hsession = get_http_session();
    if (!hsession)
        return;

    const string* field;
    if ((scan_flags & SCAN_HTTP_USER_AGENT_FLAG) and
        hsession->client.get_id() <= APP_ID_NONE and
        (field = hsession->get_field(REQ_AGENT_FID)))
    {
        char *agent_version = nullptr;
        HttpPatternMatchers& http_matchers = get_odp_ctxt().get_http_matchers();

        http_matchers.identify_user_agent(field->c_str(), field->size(), service_id,
            client_id, &agent_version);

        hsession->set_client(client_id, change_bits, "User Agent", agent_version);

        // do not overwrite a previously-set service
        if ( api.service.get_id() <= APP_ID_NONE )
            set_service_appid_data(service_id, change_bits);

        scan_flags &= ~SCAN_HTTP_USER_AGENT_FLAG;
        snort_free(agent_version);
    }

    if (const char* url = hsession->get_cfield(MISC_URL_FID))
    {
        HttpPatternMatchers& http_matchers = odp_ctxt.get_http_matchers();
        const char* referer = hsession->get_cfield(REQ_REFERER_FID);
        if ((http_matchers.get_appid_from_url(nullptr, url, &version,
            referer, &client_id, &service_id, &payload_id,
            &referred_payload_id, true, odp_ctxt)) or
            (http_matchers.get_appid_from_url(nullptr, url, &version,
            referer, &client_id, &service_id, &payload_id,
            &referred_payload_id, false, odp_ctxt)))
        {
            // do not overwrite a previously-set client or service
            if (hsession->client.get_id() <= APP_ID_NONE)
                hsession->set_client(client_id, change_bits, "URL");
            if (api.service.get_id() <= APP_ID_NONE)
                set_service_appid_data(service_id, change_bits);

            // DO overwrite a previously-set payload
            hsession->set_payload(payload_id, change_bits, "URL");
            hsession->set_referred_payload(referred_payload_id, change_bits);
        }
    }
}

void AppIdSession::set_client_appid_data(AppId id, char* version, bool published)
{
    if (id <= APP_ID_NONE or id == APP_ID_HTTP)
        return;

    AppId cur_id = api.client.get_id();
    if (id != cur_id)
    {
        if (cur_id)
            if (odp_ctxt.get_app_info_mgr().get_priority(cur_id) >
                odp_ctxt.get_app_info_mgr().get_priority(id))
                return;
        api.client.set_id(id);
    }
    if (!version)
        return;
    api.client.set_version(version);

    if (!published)
        client_info_unpublished = true;
}

void AppIdSession::set_client_appid_data(AppId id, AppidChangeBits& change_bits, char* version)
{
    set_client_appid_data(id, version, true);
    if (version)
        change_bits.set(APPID_CLIENT_INFO_BIT);
}

void AppIdSession::set_payload_appid_data(AppId id, char* version)
{
    if (id <= APP_ID_NONE)
        return;

    if (odp_ctxt.get_app_info_mgr().get_priority(api.payload.get_id()) >
        odp_ctxt.get_app_info_mgr().get_priority(id))
        return;
    api.payload.set_id(id);
    api.payload.set_version(version);
}

void AppIdSession::set_service_appid_data(AppId id, AppidChangeBits& change_bits, char* version)
{
    if (id <= APP_ID_NONE)
        return;

    // 3rd party is in INIT state after processing first GET request.
    if (id == APP_ID_HTTP)
    {
        if (client_inferred_service_id == APP_ID_NONE)
            client_inferred_service_id = id;
        return;
    }

    api.service.update(id, version);
    if (version)
        change_bits.set(APPID_SERVICE_INFO_BIT);
}

bool AppIdSession::is_svc_taking_too_much_time() const
{
    return (init_pkts_without_reply > odp_ctxt.max_packet_service_fail_ignore_bytes or
        (init_pkts_without_reply > odp_ctxt.max_packet_before_service_fail and
        init_bytes_without_reply > odp_ctxt.max_bytes_before_service_fail));
}

void AppIdSession::delete_session_data()
{
    api.service.reset();
    api.client.reset();
    api.payload.reset();
    api.delete_session_data();
    delete tsession;
}

int AppIdSession::add_flow_data(void* data, unsigned id, AppIdFreeFCN fcn)
{
    AppIdFlowDataIter it = flow_data.find(id);
    if (it != flow_data.end())
        return -1;

    AppIdFlowData* fd = new AppIdFlowData(data, id, fcn);
    flow_data[id] = fd;
    return 0;
}

void* AppIdSession::get_flow_data(unsigned id) const
{
    AppIdFlowDataIter it = flow_data.find(id);
    if (it != flow_data.end())
        return it->second->fd_data;
    else
        return nullptr;
}

void AppIdSession::free_flow_data()
{
    for (AppIdFlowDataIter it = flow_data.cbegin();
         it != flow_data.cend();
         ++it)
        delete it->second;

    flow_data.clear();
}

void AppIdSession::free_flow_data_by_id(unsigned id)
{
    AppIdFlowDataIter it = flow_data.find(id);
    if (it != flow_data.end())
    {
        delete it->second;
        flow_data.erase(it);
    }
}

void AppIdSession::free_flow_data_by_mask(unsigned mask)
{
    for (AppIdFlowDataIter it = flow_data.cbegin(); it != flow_data.cend();)
        if (!mask or (it->second->fd_id & mask))
        {
            delete it->second;
            it = flow_data.erase(it);
        }
        else
            ++it;
}

int AppIdSession::add_flow_data_id(uint16_t port, ServiceDetector* service)
{
    if (service_detector)
        return -1;
    service_detector = service;
    set_service_port(port);
    return 0;
}

void AppIdSession::stop_service_inspection(Packet* p, AppidSessionDirection direction)
{
    if (direction == APP_ID_FROM_INITIATOR)
    {
        set_service_ip(*p->ptrs.ip_api.get_dst());
        set_service_port(p->ptrs.dp);
    }
    else
    {
        set_service_ip(*p->ptrs.ip_api.get_src());
        set_service_port(p->ptrs.sp);
    }

    service_disco_state = APPID_DISCO_STATE_FINISHED;

    if (api.payload.get_id() == APP_ID_NONE and
        (is_tp_appid_available() or get_session_flags(APPID_SESSION_NO_TPI)))
        api.payload.set_id(APP_ID_UNKNOWN);

    set_session_flags(APPID_SESSION_SERVICE_DETECTED);
    clear_session_flags(APPID_SESSION_CONTINUE);
}

AppId AppIdSession::pick_service_app_id() const
{
    AppId rval = APP_ID_NONE;

    if (api.service.get_alpn_service_app_id() > APP_ID_NONE)
        return api.service.get_alpn_service_app_id();

    if (!tp_appid_ctxt)
    {
        if (is_service_detected())
        {
            if ((rval = api.service.get_id()) > APP_ID_NONE)
                return rval;
            else if (odp_ctxt.first_pkt_service_id > APP_ID_NONE)
                return odp_ctxt.first_pkt_service_id;
            else
                rval = APP_ID_UNKNOWN;
        }
        else if (odp_ctxt.first_pkt_service_id > APP_ID_NONE)
            return odp_ctxt.first_pkt_service_id;
    }
    else
    {
        if (is_service_detected())
        {
            bool deferred = api.service.get_deferred() or tp_app_id_deferred;

            if (api.service.get_id() > APP_ID_NONE and !deferred)
                return api.service.get_id();
            if (odp_ctxt.first_pkt_service_id > APP_ID_NONE)
                return odp_ctxt.first_pkt_service_id;

            if (is_tp_appid_available())
            {
                if (tp_app_id > APP_ID_NONE)
                    return tp_app_id;
                else if (deferred)
                    return api.service.get_id();
                else
                    rval = APP_ID_UNKNOWN;
            }
            else
                rval = tp_app_id;
        }
        else if (tp_app_id > APP_ID_NONE)
            return tp_app_id;
        else if (odp_ctxt.first_pkt_service_id > APP_ID_NONE)
            return odp_ctxt.first_pkt_service_id;
    }

    if (client_inferred_service_id > APP_ID_NONE)
        return client_inferred_service_id;

    if (api.service.get_port_service_id() > APP_ID_NONE)
        return api.service.get_port_service_id();

    if (rval == APP_ID_NONE or
        (rval == APP_ID_UNKNOWN and encrypted.service_id > APP_ID_NONE))
        return encrypted.service_id;

    return rval;
}

AppId AppIdSession::pick_ss_misc_app_id() const
{
    if (api.service.get_id() == APP_ID_HTTP2 or
        (api.service.get_id() == APP_ID_HTTP3 and !api.hsessions.empty()))
        return APP_ID_NONE;

    if (misc_app_id > APP_ID_NONE)
        return misc_app_id;

    AppId tmp_id = APP_ID_NONE;
    if (!api.hsessions.empty())
        tmp_id = api.hsessions[0]->misc_app_id;
    if (tmp_id > APP_ID_NONE)
        return tmp_id;

    return encrypted.misc_id;
}

AppId AppIdSession::pick_ss_client_app_id() const
{
    bool prefer_eve_client = use_eve_client_app_id();
    if (api.service.get_id() == APP_ID_HTTP2 and !prefer_eve_client)
    {
        api.client.set_eve_client_app_detect_type(CLIENT_APP_DETECT_APPID);
        return APP_ID_NONE;
    }

    if (api.service.get_id() == APP_ID_HTTP3 and !api.hsessions.empty())
        return APP_ID_NONE;

    if (prefer_eve_client)
    {
        api.client.set_eve_client_app_detect_type(CLIENT_APP_DETECT_TLS_FP);
        return api.client.get_eve_client_app_id();
    }

    AppId tmp_id = APP_ID_NONE;
    if (!api.hsessions.empty())
        tmp_id = api.hsessions[0]->client.get_id();
    if (tmp_id > APP_ID_NONE)
    {
        api.client.set_eve_client_app_detect_type(CLIENT_APP_DETECT_APPID);
        return tmp_id;
    }

    if (api.client.get_id() > APP_ID_NONE)
    {
        api.client.set_eve_client_app_detect_type(CLIENT_APP_DETECT_APPID);
        return api.client.get_id();
    }

    if (odp_ctxt.first_pkt_client_id > APP_ID_NONE)
    {
        api.client.set_eve_client_app_detect_type(CLIENT_APP_DETECT_APPID);
        return odp_ctxt.first_pkt_client_id;
    }

    api.client.set_eve_client_app_detect_type(CLIENT_APP_DETECT_APPID);
    return encrypted.client_id;
}

AppId AppIdSession::check_first_pkt_tp_payload_app_id() const
{
    if (get_session_flags(APPID_SESSION_FIRST_PKT_CACHE_MATCHED) and
        (api.payload.get_id() <= APP_ID_NONE))
    {
        if ((odp_ctxt.first_pkt_payload_id > APP_ID_NONE) and (tp_payload_app_id > APP_ID_NONE))
        {
            return tp_payload_app_id;
        }
    }
    return APP_ID_NONE;
}

AppId AppIdSession::pick_ss_payload_app_id(AppId service_id) const
{
    if (service_id == APP_ID_HTTP2 or
        (service_id == APP_ID_HTTP3 and !api.hsessions.empty()))
        return APP_ID_NONE;

    if (tp_payload_app_id_deferred)
        return tp_payload_app_id;

    AppId tmp_id = APP_ID_NONE;
    if (!api.hsessions.empty())
        tmp_id = api.hsessions[0]->payload.get_id();
    if (tmp_id > APP_ID_NONE)
    {
        if (tmp_id == APP_ID_HTTP_TUNNEL)
        {
            AppId first_pkt_payload_appid = check_first_pkt_tp_payload_app_id();
            if (first_pkt_payload_appid > APP_ID_NONE)
                return first_pkt_payload_appid;
            else if (api.payload.get_id() > APP_ID_NONE)
                return api.payload.get_id();
            else if (tp_payload_app_id > APP_ID_NONE)
                return tp_payload_app_id;
            else if (odp_ctxt.first_pkt_payload_id > APP_ID_NONE)
                return odp_ctxt.first_pkt_payload_id;
        }
        else
            return tmp_id;
    }

    AppId first_pkt_payload_appid = check_first_pkt_tp_payload_app_id();
    if (first_pkt_payload_appid > APP_ID_NONE)
        return first_pkt_payload_appid;

    if (api.payload.get_id() > APP_ID_NONE)
        return api.payload.get_id();

    if (tp_payload_app_id > APP_ID_NONE)
        return tp_payload_app_id;

    if (encrypted.payload_id > APP_ID_NONE)
        return encrypted.payload_id;

    if (odp_ctxt.first_pkt_payload_id > APP_ID_NONE)
        return odp_ctxt.first_pkt_payload_id;

    // APP_ID_UNKNOWN is valid only for HTTP type services
    if (tmp_id == APP_ID_UNKNOWN)
        return tmp_id;

    if (api.payload.get_id() == APP_ID_UNKNOWN and
        appid_api.is_service_http_type(service_id))
        return APP_ID_UNKNOWN;

    return APP_ID_NONE;
}

AppId AppIdSession::pick_ss_payload_app_id() const
{
    AppId service_id = pick_service_app_id();

    return pick_ss_payload_app_id(service_id);
}

AppId AppIdSession::pick_ss_referred_payload_app_id() const
{
    if (api.service.get_id() == APP_ID_HTTP2 or api.service.get_id() == APP_ID_HTTP3)
        return APP_ID_NONE;

    AppId tmp_id = APP_ID_NONE;
    if (!api.hsessions.empty())
        tmp_id = api.hsessions[0]->referred_payload_app_id;
    if (tmp_id > APP_ID_NONE)
        return tmp_id;

    return encrypted.referred_id;
}

void AppIdSession::set_ss_application_ids(AppId service_id, AppId client_id, AppId payload_id,
    AppId misc_id, AppId referred_id, AppidChangeBits& change_bits)
{
    assert(flow);
    api.set_ss_application_ids(service_id, client_id, payload_id, misc_id, referred_id, change_bits, *flow);
}

void AppIdSession::set_ss_application_ids(AppId client_id, AppId payload_id,
    AppidChangeBits& change_bits)
{
    assert(flow);
    api.set_ss_application_ids(client_id, payload_id, change_bits, *flow);
}

void AppIdSession::set_ss_application_ids_payload(AppId payload_id,
    AppidChangeBits& change_bits)
{
    assert(flow);
    api.set_ss_application_ids_payload(payload_id, change_bits, *flow);
}

void AppIdSession::set_application_ids_service(AppId service_id, AppidChangeBits& change_bits)
{
    assert(flow);
    api.set_application_ids_service(service_id, change_bits, *flow);
}

void AppIdSession::reset_session_data(AppidChangeBits& change_bits)
{
    delete_session_data();
    api.hsessions.clear();

    tp_payload_app_id = APP_ID_UNKNOWN;
    tp_app_id = APP_ID_UNKNOWN;

    if (tpsession and need_to_delete_tp_conn(pkt_thread_tp_appid_ctxt))
        tpsession->reset();
    else if (tpsession)
        tpsession->set_state(TP_STATE_TERMINATED);

    change_bits.reset();
    change_bits.set(APPID_RESET_BIT);
}

void AppIdSession::clear_http_flags()
{
    if (!get_session_flags(APPID_SESSION_SPDY_SESSION))
    {
        clear_session_flags(APPID_SESSION_CHP_INSPECTING);
        if (this->tpsession)
            this->tpsession->clear_attr(TP_ATTR_CONTINUE_MONITORING);
    }
}

void AppIdSession::clear_http_data()
{
    if (api.hsessions.empty())
        return;
    api.hsessions[0]->clear_all_fields();
}

AppIdHttpSession* AppIdSession::get_http_session(uint32_t stream_index) const
{
    if (stream_index < api.hsessions.size())
        return api.hsessions[stream_index];
    else
        return nullptr;
}

AppIdHttpSession* AppIdSession::create_http_session(int64_t stream_id)
{
    AppIdHttpSession* hsession = new AppIdHttpSession(*this, stream_id);
    api.hsessions.push_back(hsession);
    return hsession;
}

AppIdHttpSession* AppIdSession::get_matching_http_session(int64_t stream_id) const
{
    for (uint32_t stream_index=0; stream_index < api.hsessions.size(); stream_index++)
    {
        if(stream_id == api.hsessions[stream_index]->get_httpx_stream_id())
            return api.hsessions[stream_index];
    }
    return nullptr;
}

void AppIdSession::delete_all_http_sessions()
{
    api.delete_all_http_sessions();
}

AppIdDnsSession* AppIdSession::create_dns_session()
{
    if (api.dsession)
        delete api.dsession;
    api.dsession = new AppIdDnsSession();
    return api.dsession;
}

AppIdDnsSession* AppIdSession::get_dns_session() const
{
    return api.dsession;
}

bool AppIdSession::is_tp_appid_done() const
{
    if (get_session_flags(APPID_SESSION_FUTURE_FLOW) or !tp_appid_ctxt)
        return true;

    if (!tpsession)
        return false;

    unsigned state = tpsession->get_state();
    return (state == TP_STATE_CLASSIFIED or state == TP_STATE_TERMINATED or
        state == TP_STATE_HA);
}

bool AppIdSession::is_tp_processing_done() const
{
    if (!get_session_flags(APPID_SESSION_NO_TPI) and
        (!is_tp_appid_done() or
        get_session_flags(APPID_SESSION_APP_REINSPECT | APPID_SESSION_APP_REINSPECT_SSL)))
        return false;

    return true;
}

bool AppIdSession::is_tp_appid_available() const
{
    if (tp_appid_ctxt)
    {
        if (!tpsession)
            return false;

        unsigned state = tpsession->get_state();

        return (state == TP_STATE_CLASSIFIED or state == TP_STATE_TERMINATED or
            state == TP_STATE_MONITORING);
    }

    return true;
}

bool AppIdSession::need_to_delete_tp_conn(ThirdPartyAppIdContext* curr_tp_appid_ctxt) const
{
    // do not delete a third-party connection when reload third-party is in progress, and
    // third-party context swap isn't complete; since all open connections will be deleted
    // as part of the third-party reload pruning process.
    return (curr_tp_appid_ctxt and ((tpsession->get_ctxt_version() == curr_tp_appid_ctxt->get_version()) and
        !ThirdPartyAppIdContext::get_tp_reload_in_progress()));
}

void AppIdSession::set_tp_app_id(const Packet& p, AppidSessionDirection dir, AppId app_id,
    AppidChangeBits& change_bits)
{
    if (tp_app_id != app_id)
    {
        tp_app_id = app_id;
        AppInfoTableEntry* entry =
            odp_ctxt.get_app_info_mgr().get_app_info_entry(tp_app_id);
        if (entry)
        {
            tp_app_id_deferred = (entry->flags & APPINFO_FLAG_DEFER) ? true : false;
            check_detector_callback(p, *this, dir, app_id, change_bits, entry);
        }
    }
}

void AppIdSession::set_tp_payload_app_id(const Packet& p, AppidSessionDirection dir, AppId app_id,
    AppidChangeBits& change_bits)
{
    if (tp_payload_app_id != app_id)
    {
        tp_payload_app_id = app_id;
        AppInfoTableEntry* entry =
            odp_ctxt.get_app_info_mgr().get_app_info_entry(tp_payload_app_id);
        if (entry)
        {
            tp_payload_app_id_deferred = (entry->flags & APPINFO_FLAG_DEFER_PAYLOAD) ? true : false;
            check_detector_callback(p, *this, dir, app_id, change_bits, entry);
        }
    }
}

void AppIdSession::publish_appid_event(AppidChangeBits& change_bits, const Packet& p,
    bool is_httpx, uint32_t httpx_stream_index)
{
    if (!api.flags.stored_in_stash)
    {
        assert(p.flow and p.flow->stash);
        p.flow->stash->store(STASH_APPID_DATA, &api, false);
        api.flags.stored_in_stash = true;
    }

    if (!api.flags.published)
    {
        change_bits.set(APPID_CREATED_BIT);
        api.flags.published = true;
    }

    if (consumed_ha_data)
    {
        AppIdHttpSession* hsession = get_http_session();
        if (hsession)
        {
            if (hsession->get_field(MISC_URL_FID))
                change_bits.set(APPID_URL_BIT);
            if (hsession->get_field(REQ_HOST_FID))
                change_bits.set(APPID_HOST_BIT);
        }

        if (api.get_tls_host())
            change_bits.set(APPID_TLSHOST_BIT);

        consumed_ha_data = false;
    }

    if (!(api.flags.finished || api.is_appid_inspecting_session()))
    {
        change_bits.set(APPID_DISCOVERY_FINISHED_BIT);
        api.flags.finished = true;
    }

    // Publish an event, if this is the first packet after appid processing
    if (get_session_flags(APPID_SESSION_DO_NOT_DECRYPT))
        clear_session_flags(APPID_SESSION_DO_NOT_DECRYPT);
    else if (change_bits.none())
        return;

    AppidEvent app_event(change_bits, is_httpx, httpx_stream_index, api, p);
    DataBus::publish(AppIdInspector::get_pub_id(), AppIdEventIds::ANY_CHANGE, app_event, p.flow);
    if (appidDebug->is_active())
    {
        std::string str;
        change_bits_to_string(change_bits, str);
        if (is_httpx)
            LogMessage("AppIdDbg %s Published event for changes: %s for HTTPX stream index %u\n",
                appidDebug->get_debug_session(), str.c_str(), httpx_stream_index);
        else
            LogMessage("AppIdDbg %s Published event for changes: %s\n",
                appidDebug->get_debug_session(), str.c_str());
    }
}

