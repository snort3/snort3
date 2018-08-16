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

// appid_session.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_session.h"

#include <cstring>

#include "log/messages.h"
#include "main/snort_config.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "stream/stream.h"
#include "target_based/snort_protocols.h"
#include "time/packet_time.h"

#include "app_forecast.h"
#include "app_info_table.h"
#include "appid_debug.h"
#include "appid_dns_session.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "appid_stats.h"
#include "appid_utils/ip_funcs.h"
#include "service_plugins/service_ssl.h"
#ifdef ENABLE_APPID_THIRD_PARTY
#include "tp_lib_handler.h"
#endif

using namespace snort;

unsigned AppIdSession::inspector_id = 0;
THREAD_LOCAL uint32_t AppIdSession::appid_flow_data_id = 0;

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

AppIdSession* AppIdSession::allocate_session(const Packet* p, IpProtocol proto,
    AppidSessionDirection direction,
    AppIdInspector& inspector)
{
    uint16_t port = 0;

    const SfIp* ip = (direction == APP_ID_FROM_INITIATOR)
        ? p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst();
    if ( ( proto == IpProtocol::TCP || proto == IpProtocol::UDP ) && ( p->ptrs.sp != p->ptrs.dp ) )
        port = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.sp : p->ptrs.dp;

    AppIdSession* asd = new AppIdSession(proto, ip, port, inspector);
    asd->flow = p->flow;
    asd->stats.first_packet_second = p->pkth->ts.tv_sec;
    asd->snort_protocol_id = snortId_for_unsynchronized;
    p->flow->set_flow_data(asd);
    return asd;
}

AppIdSession::AppIdSession(IpProtocol proto, const SfIp* ip, uint16_t port,
    AppIdInspector& inspector)
    : FlowData(inspector_id, &inspector), config(inspector.get_appid_config()),
    protocol(proto), inspector(inspector)
{
    service_ip.clear();
    session_id = ++appid_flow_data_id;
    common.flow_type = APPID_FLOW_TYPE_NORMAL;
    common.initiator_ip = *ip;
    common.initiator_port = port;
    app_info_mgr = &AppInfoManager::get_instance();

    length_sequence.proto = IpProtocol::PROTO_NOT_SET;
    length_sequence.sequence_cnt = 0;
    memset(length_sequence.sequence, '\0', sizeof(length_sequence.sequence));

    appid_stats.total_sessions++;
}

AppIdSession::~AppIdSession()
{
    if ( !in_expected_cache )
    {
        if ( config->mod_config->stats_logging_enabled )
            AppIdStatistics::get_stats_manager()->update(*this);

        // fail any service detection that is in process for this flow
        if (!get_session_flags(APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_UDP_REVERSED |
            APPID_SESSION_MID | APPID_SESSION_OOO) and flow)
        {
            ServiceDiscoveryState* sds =
                AppIdServiceState::get(&service_ip, protocol, service_port, is_decrypted());
            if ( sds )
            {
                if (flow->server_ip.fast_eq6(service_ip))
                    sds->set_service_id_failed(*this, &flow->client_ip,
                        STATE_ID_INCONCLUSIVE_SERVICE_WEIGHT);
                else
                    sds->set_service_id_failed(*this, &flow->server_ip,
                        STATE_ID_INCONCLUSIVE_SERVICE_WEIGHT);
            }
        }
    }

#ifdef ENABLE_APPID_THIRD_PARTY
    if (tpsession)
    {
        delete tpsession;
        tpsession = nullptr;
    }
#endif

    delete_session_data();
    free_flow_data();
    service_candidates.clear();
    client_candidates.clear();
    snort_free(firewall_early_data);
}

// FIXIT-L X Move this to somewhere more generally available/appropriate.
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
    SnortProtocolId snort_protocol_id, int /*flags*/, AppIdInspector& inspector)
{
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    enum PktType type = get_pkt_type_from_ip_proto(proto);

    assert(type != PktType::NONE);

    // FIXIT-M - port parameter passed in as 0 since we may not know client port, verify this is
    // correct
    AppIdSession* asd = new AppIdSession(proto, cliIp, 0, inspector);
    asd->common.policyId = asd->config->appIdPolicyId;

    if ( Stream::set_snort_protocol_id_expected(ctrlPkt, type, proto, cliIp, cliPort, srvIp,
        srvPort, snort_protocol_id, asd) )
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

void AppIdSession::reinit_session_data()
{
    misc_app_id = APP_ID_NONE;

    //data
    if ( is_service_over_ssl(tp_app_id) )
    {
        payload.reset();
        referred_payload_app_id = tp_payload_app_id = APP_ID_NONE;
        clear_session_flags(APPID_SESSION_CONTINUE);
        if ( hsession )
            hsession->set_field(MISC_URL_FID, nullptr);
    }

    //service
    if ( !get_session_flags(APPID_SESSION_STICKY_SERVICE) )
    {
        service.reset();
        tp_app_id = APP_ID_NONE;
        service_ip.clear();
        service_port = 0;
        service_disco_state = APPID_DISCO_STATE_NONE;
        service_detector = nullptr;
        free_flow_data_by_mask(APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);
    }

    //client
    client.reset();
    client_inferred_service_id = APP_ID_NONE;
    client_disco_state = APPID_DISCO_STATE_NONE;
    free_flow_data_by_mask(APPID_SESSION_DATA_CLIENT_MODSTATE_BIT);

#ifdef ENABLE_APPID_THIRD_PARTY
    //3rd party cleaning
    if (tpsession)
        tpsession->reset();
#endif

    init_tpPackets = 0;
    resp_tpPackets = 0;

    scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
    clear_session_flags(APPID_SESSION_SERVICE_DETECTED |APPID_SESSION_CLIENT_DETECTED |
        APPID_SESSION_SSL_SESSION|APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT);
}

void AppIdSession::sync_with_snort_protocol_id(AppId newAppId, Packet* p)
{
    if (newAppId  > APP_ID_NONE && newAppId < SF_APPID_MAX)
    {
        // Certain AppIds are not useful to identifying snort preprocessor choices
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

        case APP_ID_HTTP:
            if (is_http2)
                newAppId = APP_ID_HTTP2;
            break;
        default:
            break;
        }

        AppInfoTableEntry* entry = app_info_mgr->get_app_info_entry(newAppId);
        if ( entry )
        {
            SnortProtocolId tmp_snort_protocol_id = entry->snort_protocol_id;
            // A particular APP_ID_xxx may not be assigned a service_snort_key value
            // in the rna_app.yaml file entry; so ignore the snort_protocol_id ==
            // UNKNOWN_PROTOCOL_ID case.
            if ( tmp_snort_protocol_id == UNKNOWN_PROTOCOL_ID && (newAppId == APP_ID_HTTP2))
                tmp_snort_protocol_id = snortId_for_http2;

            if ( tmp_snort_protocol_id != snort_protocol_id )
            {
                snort_protocol_id = tmp_snort_protocol_id;
                if (appidDebug->is_active() && tmp_snort_protocol_id == snortId_for_http2)
                    LogMessage("AppIdDbg %s Telling Snort that it's HTTP/2\n",
                        appidDebug->get_debug_session());

                p->flow->ssn_state.snort_protocol_id = tmp_snort_protocol_id;
            }
        }
    }
}

void AppIdSession::check_app_detection_restart()
{
    if (get_session_flags(APPID_SESSION_DECRYPTED) || !flow->is_proxied())
        return;

    AppId service_id = pick_service_app_id();
    bool isSsl = is_service_over_ssl(service_id);

    // A session could either:
    // 1. Start off as SSL - captured with isSsl flag, OR
    // 2. It could start off as a non-SSL session and later change to SSL. For example, FTP->FTPS.
    //    In this case APPID_SESSION_ENCRYPTED flag is set by the protocol state machine.
    if (get_session_flags(APPID_SESSION_ENCRYPTED) || isSsl)
    {
        set_session_flags(APPID_SESSION_DECRYPTED);
        encrypted.service_id = service_id;
        encrypted.payload_id = pick_payload_app_id();
        encrypted.client_id = pick_client_app_id();
        encrypted.misc_id = pick_misc_app_id();
        encrypted.referred_id = pick_referred_payload_app_id();
        reinit_session_data();
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

void AppIdSession::update_encrypted_app_id(AppId service_id)
{
    switch (service_id)
    {
    case APP_ID_HTTP:
        if (misc_app_id == APP_ID_NSIIOPS || misc_app_id == APP_ID_DDM_SSL
            || misc_app_id == APP_ID_MSFT_GC_SSL
            || misc_app_id == APP_ID_SF_APPLIANCE_MGMT)
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
    default:
        break;
    }
}

void AppIdSession::examine_ssl_metadata(Packet* p)
{
    int ret;
    AppId client_id = 0;
    AppId payload_id = 0;

    if ((scan_flags & SCAN_SSL_HOST_FLAG) && tsession->tls_host)
    {
        size_t size = strlen(tsession->tls_host);
        if ((ret = ssl_scan_hostname((const uint8_t*)tsession->tls_host, size,
                &client_id, &payload_id)))
        {
            set_client_appid_data(client_id, nullptr);
            set_payload_appid_data((AppId)payload_id, nullptr);
            setSSLSquelch(p, ret, (ret == 1 ? payload_id : client_id), inspector);
        }
        scan_flags &= ~SCAN_SSL_HOST_FLAG;
    }
    if (tsession->tls_cname)
    {
        size_t size = strlen(tsession->tls_cname);
        if ((ret = ssl_scan_cname((const uint8_t*)tsession->tls_cname, size,
                &client_id, &payload_id)))
        {
            set_client_appid_data(client_id, nullptr);
            set_payload_appid_data((AppId)payload_id, nullptr);
            setSSLSquelch(p, ret, (ret == 1 ? payload_id : client_id), inspector);
        }
        snort_free(tsession->tls_cname);
        tsession->tls_cname = nullptr;
    }
    if (tsession->tls_orgUnit)
    {
        size_t size = strlen(tsession->tls_orgUnit);
        if ((ret = ssl_scan_cname((const uint8_t*)tsession->tls_orgUnit, size,
                &client_id, &payload_id)))
        {
            set_client_appid_data(client_id, nullptr);
            set_payload_appid_data((AppId)payload_id, nullptr);
            setSSLSquelch(p, ret, (ret == 1 ? payload_id : client_id), inspector);
        }
        snort_free(tsession->tls_orgUnit);
        tsession->tls_orgUnit = nullptr;
    }
}

void AppIdSession::examine_rtmp_metadata()
{
    AppId service_id = APP_ID_NONE;
    AppId client_id = APP_ID_NONE;
    AppId payload_id = APP_ID_NONE;
    AppId referred_payload_id = APP_ID_NONE;
    char* version = nullptr;

    if ( !hsession )
        hsession = new AppIdHttpSession(*this);

    if ( const char* url = hsession->get_cfield(MISC_URL_FID) )
    {
        HttpPatternMatchers* http_matchers = HttpPatternMatchers::get_instance();
        const char* referer = hsession->get_cfield(REQ_REFERER_FID);
        if ( ( ( http_matchers->get_appid_from_url(nullptr, url, &version,
            referer, &client_id, &service_id,
            &payload_id, &referred_payload_id, true) )
            ||
            ( http_matchers->get_appid_from_url(nullptr, url, &version,
            referer, &client_id, &service_id,
            &payload_id, &referred_payload_id, false) ) ) )
        {
            /* do not overwrite a previously-set client or service */
            if (client.get_id() <= APP_ID_NONE)
                set_client_appid_data(payload_id, nullptr);
            if (service.get_id() <= APP_ID_NONE)
                set_service_appid_data(service_id, nullptr, nullptr);

            /* DO overwrite a previously-set data */
            set_payload_appid_data((AppId)payload.get_id(), nullptr);
            set_referred_payload_app_id_data(referred_payload_id);
        }
    }
}

void AppIdSession::set_client_appid_data(AppId id, char* version)
{
    if ( id <= APP_ID_NONE || id == APP_ID_HTTP )
        return;

    AppId cur_id = client.get_id();
    if ( id != cur_id )
    {
        if ( cur_id )
            if ( app_info_mgr->get_priority(cur_id) > app_info_mgr->get_priority(id) )
                return;

        client.set_id(id);
    }

    client.set_version(version);
}

void AppIdSession::set_referred_payload_app_id_data(AppId id)
{
    if (id <= APP_ID_NONE)
        return;

    if (referred_payload_app_id != id)
        referred_payload_app_id = id;
}

void AppIdSession::set_payload_appid_data(AppId id, char* version)
{
    if ( id <= APP_ID_NONE )
        return;

    if ( app_info_mgr->get_priority(payload.get_id()) > app_info_mgr->get_priority(id) )
        return;
    payload.set_id(id);
    payload.set_version(version);
}

void AppIdSession::set_service_appid_data(AppId id, char* vendor, char* version)
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

    service.update(id, vendor, version);
}

void AppIdSession::free_tls_session_data()
{
    if ( tsession )
    {
        if (tsession->tls_host)
            snort_free(tsession->tls_host);
        if (tsession->tls_cname)
            snort_free(tsession->tls_cname);
        if (tsession->tls_orgUnit)
            snort_free(tsession->tls_orgUnit);
        snort_free(tsession);
        tsession = nullptr;
    }
}

void AppIdSession::delete_session_data()
{
    service.reset();
    client.reset();
    payload.reset();
    snort_free(netbios_name);
    snort_free(netbios_domain);

    AppIdServiceSubtype* rna_ss = subtype;
    while ( rna_ss )
    {
        subtype = rna_ss->next;
        snort_free(const_cast<char*>(rna_ss->service));
        snort_free(const_cast<char*>(rna_ss->vendor));
        snort_free(const_cast<char*>(rna_ss->version));
        snort_free(rna_ss);
        rna_ss = subtype;
    }

    delete hsession;
    free_tls_session_data();
    delete dsession;
}

int AppIdSession::add_flow_data(void* data, unsigned id, AppIdFreeFCN fcn)
{
    AppIdFlowDataIter it = flow_data.find(id);
    if ( it != flow_data.end() )
        return -1;

    AppIdFlowData* fd = new AppIdFlowData(data, id, fcn);
    flow_data[id] = fd;
    return 0;
}

void* AppIdSession::get_flow_data(unsigned id)
{
    AppIdFlowDataIter it = flow_data.find(id);
    if ( it != flow_data.end() )
        return it->second->fd_data;
    else
        return nullptr;
}

void* AppIdSession::remove_flow_data(unsigned id)
{
    void* data = nullptr;

    AppIdFlowDataIter it = flow_data.find(id);
    if ( it != flow_data.end() )
    {
        data = it->second->fd_data;
        delete it->second;
        flow_data.erase(it);
    }

    return data;
}

void AppIdSession::free_flow_data()
{
    for ( AppIdFlowDataIter it = flow_data.cbegin(); it != flow_data.cend(); ++it )
        delete it->second;

    flow_data.clear();
}

void AppIdSession::free_flow_data_by_id(unsigned id)
{
    AppIdFlowDataIter it = flow_data.find(id);
    if ( it != flow_data.end() )
    {
        delete it->second;
        flow_data.erase(it);
    }
}

void AppIdSession::free_flow_data_by_mask(unsigned mask)
{
    for ( AppIdFlowDataIter it = flow_data.cbegin(); it != flow_data.cend(); )
        if ( !mask || ( it->second->fd_id & mask ) )
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
    service_port = port;
    return 0;
}

void AppIdSession::stop_rna_service_inspection(Packet* p, AppidSessionDirection direction)
{
    if (direction == APP_ID_FROM_INITIATOR)
    {
        service_ip = *p->ptrs.ip_api.get_dst();
        service_port = p->ptrs.dp;
    }
    else
    {
        service_ip = *p->ptrs.ip_api.get_src();
        service_port = p->ptrs.sp;
    }

    service_disco_state = APPID_DISCO_STATE_FINISHED;

    if ( (is_tp_appid_available() or get_session_flags(APPID_SESSION_NO_TPI) )
        and payload.get_id() == APP_ID_NONE )
        payload.set_id(APP_ID_UNKNOWN);

    set_session_flags(APPID_SESSION_SERVICE_DETECTED);
    clear_session_flags(APPID_SESSION_CONTINUE);
}

AppId AppIdSession::pick_service_app_id()
{
    AppId rval = APP_ID_NONE;

    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;

    if ( is_service_detected() )
    {
        bool deferred = service.get_deferred() || tp_app_id_deferred;

        if (service.get_id() > APP_ID_NONE && !deferred)
            return service.get_id();
        if (is_tp_appid_available())
        {
            if (tp_app_id > APP_ID_NONE)
                return tp_app_id;
            else if (deferred)
                return service.get_id();
            else
                rval = APP_ID_UNKNOWN_UI;
        }
        else
            rval = tp_app_id;
    }
    else if (tp_app_id > APP_ID_NONE)
        return tp_app_id;

    if (client_inferred_service_id > APP_ID_NONE)
        return client_inferred_service_id;

    if (service.get_port_service_id() > APP_ID_NONE)
        return service.get_port_service_id();

    if (rval == APP_ID_NONE or
        (rval == APP_ID_UNKNOWN_UI and encrypted.service_id > APP_ID_NONE))
        return encrypted.service_id;

    return rval;
}

AppId AppIdSession::pick_only_service_app_id()
{
    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;

    bool deferred = service.get_deferred() || tp_app_id_deferred;

    if (service.get_id() > APP_ID_NONE && !deferred)
        return service.get_id();

    if (is_tp_appid_available() && tp_app_id > APP_ID_NONE)
        return tp_app_id;
    else if (deferred)
        return service.get_id();

    if (service.get_id() < APP_ID_NONE)
        return APP_ID_UNKNOWN_UI;

    return APP_ID_NONE;
}

AppId AppIdSession::pick_misc_app_id()
{
    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;
    if (misc_app_id > APP_ID_NONE)
        return misc_app_id;
    return encrypted.misc_id;
}

AppId AppIdSession::pick_client_app_id()
{
    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;
    if (client.get_id() > APP_ID_NONE)
        return client.get_id();
    return encrypted.client_id;
}

AppId AppIdSession::pick_payload_app_id()
{
    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;

    if (tp_payload_app_id_deferred)
        return tp_payload_app_id;
    else if (payload.get_id() > APP_ID_NONE)
        return payload.get_id();
    else if (tp_payload_app_id > APP_ID_NONE)
        return tp_payload_app_id;
    return encrypted.payload_id;
}

AppId AppIdSession::pick_referred_payload_app_id()
{
    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;
    if ( referred_payload_app_id > APP_ID_NONE )
        return referred_payload_app_id;
    return encrypted.referred_id;
}

void AppIdSession::set_application_ids(AppId service_id, AppId client_id,
    AppId payload_id, AppId misc_id)
{
    application_ids[APP_PROTOID_SERVICE] = service_id;
    application_ids[APP_PROTOID_CLIENT] = client_id;
    application_ids[APP_PROTOID_PAYLOAD] = payload_id;
    application_ids[APP_PROTOID_MISC] = misc_id;
}

void AppIdSession::get_application_ids(AppId& service_id, AppId& client_id,
    AppId& payload_id, AppId& misc_id)
{
    service_id = application_ids[APP_PROTOID_SERVICE];
    client_id  = application_ids[APP_PROTOID_CLIENT];
    payload_id = application_ids[APP_PROTOID_PAYLOAD];
    misc_id    = application_ids[APP_PROTOID_MISC];
}

void AppIdSession::get_application_ids(AppId& service_id, AppId& client_id,
    AppId& payload_id)
{
    service_id = application_ids[APP_PROTOID_SERVICE];
    client_id  = application_ids[APP_PROTOID_CLIENT];
    payload_id = application_ids[APP_PROTOID_PAYLOAD];
}

AppId AppIdSession::get_application_ids_service()
{
    return application_ids[APP_PROTOID_SERVICE];
}

AppId AppIdSession::get_application_ids_client()
{
    return application_ids[APP_PROTOID_CLIENT];
}

AppId AppIdSession::get_application_ids_payload()
{
    return application_ids[APP_PROTOID_PAYLOAD];
}

AppId AppIdSession::get_application_ids_misc()
{
    return application_ids[APP_PROTOID_MISC];
}

bool AppIdSession::is_ssl_session_decrypted()
{
    return get_session_flags(APPID_SESSION_DECRYPTED);
}

void AppIdSession::reset_session_data()
{
    delete_session_data();
    netbios_name = nullptr;
    netbios_domain = nullptr;
    hsession = nullptr;

    tp_payload_app_id = APP_ID_UNKNOWN;
    tp_app_id = APP_ID_UNKNOWN;

#ifdef ENABLE_APPID_THIRD_PARTY
    if (this->tpsession)
        this->tpsession->reset();
#endif
}

bool AppIdSession::is_payload_appid_set()
{
    return ( payload.get_id() || tp_payload_app_id );
}

void AppIdSession::clear_http_flags()
{
    if (!get_session_flags(APPID_SESSION_SPDY_SESSION))
    {
        clear_session_flags(APPID_SESSION_CHP_INSPECTING);
#ifdef ENABLE_APPID_THIRD_PARTY
        if (this->tpsession)
            this->tpsession->clear_attr(TP_ATTR_CONTINUE_MONITORING);
#endif
    }
}

void AppIdSession::clear_http_data()
{
    if (!hsession)
        return;
    hsession->clear_all_fields();
}

AppIdHttpSession* AppIdSession::get_http_session()
{
    if ( !hsession )
        hsession = new AppIdHttpSession(*this);
    return hsession;
}

AppIdDnsSession* AppIdSession::get_dns_session()
{
    if ( !dsession )
        dsession = new AppIdDnsSession();
    return dsession;
}

bool AppIdSession::is_tp_appid_done() const
{
#ifdef ENABLE_APPID_THIRD_PARTY
    if ( TPLibHandler::have_tp() )
    {
        if (!tpsession)
            return false;

        unsigned state = tpsession->get_state();
        return (state  == TP_STATE_CLASSIFIED || state == TP_STATE_TERMINATED
               || state == TP_STATE_HA);
    }
#endif

    return true;
}

bool AppIdSession::is_tp_processing_done() const
{
#ifdef ENABLE_APPID_THIRD_PARTY
    if ( TPLibHandler::have_tp() &&
        !get_session_flags(APPID_SESSION_NO_TPI) &&
        (!is_tp_appid_done() ||
        get_session_flags(APPID_SESSION_APP_REINSPECT | APPID_SESSION_APP_REINSPECT_SSL)))
        return false;
#endif

    return true;
}

bool AppIdSession::is_tp_appid_available() const
{
#ifdef ENABLE_APPID_THIRD_PARTY
    if ( TPLibHandler::have_tp() )
    {
        unsigned state;

        if (tpsession)
            state = tpsession->get_state();
        else
            state = TP_STATE_INIT;

        return (state == TP_STATE_CLASSIFIED || state == TP_STATE_TERMINATED
               || state == TP_STATE_MONITORING);
    }
#endif

    return true;
}

