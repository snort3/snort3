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

// appid_session.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_session.h"

#include <string.h>

#include "app_forecast.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "app_info_table.h"
#include "appid_module.h"
#include "appid_stats.h"
#include "appid_utils/ip_funcs.h"
#include "service_plugins/service_ssl.h"
#include "thirdparty_appid_utils.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "stream/stream.h"
#include "target_based/snort_protocols.h"
#include "time/packet_time.h"

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

void AppIdSession::set_session_logging_state(const Packet* pkt, int direction)
{
    if (config->mod_config->session_log_filter.log_all_sessions)
    {
        session_logging_enabled = true;
    }
    else
    {
        if ( !pkt->ptrs.ip_api.get_src()->equals(config->mod_config->session_log_filter.sip) )
            return;

        if ( !pkt->ptrs.ip_api.get_dst()->equals(config->mod_config->session_log_filter.dip) )
            return;

        if ( !( pkt->ptrs.dp == config->mod_config->session_log_filter.dport ) )
            return;

        if ( !( pkt->ptrs.dp == config->mod_config->session_log_filter.dport ) )
            return;

        if ( !( pkt->ptrs.type == config->mod_config->session_log_filter.protocol ) )
            return;

        session_logging_enabled = true;
    }

    if (session_logging_enabled)
    {
        char src_ip_str[INET6_ADDRSTRLEN], dst_ip_str[INET6_ADDRSTRLEN];

        pkt->ptrs.ip_api.get_src()->ntop(src_ip_str, sizeof(src_ip_str));
        pkt->ptrs.ip_api.get_dst()->ntop(dst_ip_str, sizeof(dst_ip_str));
        snprintf(session_logging_id, MAX_SESSION_LOGGING_ID_LEN,
            "%s-%hu -> %s-%hu %u%s AS %u I %u",
            src_ip_str, pkt->ptrs.sp, dst_ip_str, pkt->ptrs.dp,
            (unsigned)pkt->ptrs.type, (direction == APP_ID_FROM_INITIATOR) ? "" : " R",
            (unsigned)pkt->pkth->address_space_id, get_instance_id());
    }
}

AppIdSession* AppIdSession::allocate_session(const Packet* p, IpProtocol proto, int direction)
{
    uint16_t port = 0;

    const SfIp* ip = (direction == APP_ID_FROM_INITIATOR)
        ? p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst();
    if ( ( proto == IpProtocol::TCP || proto == IpProtocol::UDP ) && ( p->ptrs.sp != p->ptrs.dp ) )
        port = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.sp : p->ptrs.dp;

    AppIdSession* asd = new AppIdSession(proto, ip, port);

    asd->flow = p->flow;
    asd->stats.first_packet_second = p->pkth->ts.tv_sec;
    asd->set_session_logging_state(p, direction);
    asd->snort_id = snortId_for_unsynchronized;
    p->flow->set_flow_data(asd);
    return asd;
}

AppIdSession::AppIdSession(IpProtocol proto, const SfIp* ip, uint16_t port)
    : FlowData(inspector_id), protocol(proto)
{
    service_ip.clear();
    session_id = ++appid_flow_data_id;
    common.flow_type = APPID_FLOW_TYPE_NORMAL;
    common.initiator_ip = *ip;
    common.initiator_port = port;
    config = AppIdInspector::get_inspector()->get_appid_config();
    app_info_mgr = &AppInfoManager::get_instance();
    if (thirdparty_appid_module)
        if (!(tpsession = thirdparty_appid_module->session_create()))
            ErrorMessage("Could not allocate third party session data");

    length_sequence.proto = IpProtocol::PROTO_NOT_SET;
    length_sequence.sequence_cnt = 0;
    memset(length_sequence.sequence, '\0', sizeof(length_sequence.sequence));
    session_logging_id[0] = '\0';
}

AppIdSession::~AppIdSession()
{
    if ( !in_expected_cache )
    {
        AppIdStatistics* stats_mgr = AppIdInspector::get_inspector()->get_stats_manager();
        if ( stats_mgr )
            stats_mgr->update(this);

        // fail any service detection that is in process for this flow
        if (flow &&
            !get_session_flags(APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_UDP_REVERSED) )
        {
            ServiceDiscoveryState* sds =
                AppIdServiceState::get(&service_ip, protocol, service_port, is_decrypted());
            if ( sds )
            {
                if (flow->server_ip.fast_eq6(service_ip))
                    sds->set_service_id_failed(this, &flow->client_ip,
                        STATE_ID_INCONCLUSIVE_SERVICE_WEIGHT);
                else
                    sds->set_service_id_failed(this, &flow->server_ip,
                        STATE_ID_INCONCLUSIVE_SERVICE_WEIGHT);
            }
        }
    }

    if (thirdparty_appid_module)
    {
        thirdparty_appid_module->session_delete(tpsession, 0);
        tpsession = nullptr;
    }

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
    int16_t app_id, int /*flags*/)
{
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    // FIXIT-M not needed  until crtlPkt expectedSession is supported
    //struct _ExpectNode** node;
    enum PktType type = get_pkt_type_from_ip_proto(proto);

    assert(type != PktType::NONE);

    // FIXIT-M - port parameter passed in as 0 since we may not know client port, verify this is
    // correct
    AppIdSession* asd = new AppIdSession(proto, cliIp, 0);
    asd->common.policyId = asd->config->appIdPolicyId;

    // FIXIT-M expect session control packet support not ported to snort3 yet
    //node = (flags & APPID_EARLY_SESSION_FLAG_FW_RULE) ? &ctrlPkt->expectedSession : nullptr;

    // FIXIT-M 2.9.x set_application_protocol_id_expected has several new parameters, need to look
    // into what is required to support those here.
    if ( Stream::set_application_protocol_id_expected(ctrlPkt, type, proto, cliIp, cliPort, srvIp,
        srvPort, app_id, asd) )
    {
        sfip_ntop(cliIp, src_ip, sizeof(src_ip));
        sfip_ntop(srvIp, dst_ip, sizeof(dst_ip));
        WarningMessage("AppIdDbg %s failed to create a related flow for %s-%u -> %s-%u %u\n",
            asd->session_logging_id, src_ip, (unsigned)cliPort, dst_ip,
            (unsigned)srvPort, (unsigned)proto);
        delete asd;
        asd = nullptr;
    }
    else
    {
        if (asd->session_logging_enabled)
        {
            sfip_ntop(cliIp, src_ip, sizeof(src_ip));
            sfip_ntop(srvIp, dst_ip, sizeof(dst_ip));
            LogMessage("AppIdDbg %s related flow created for %s-%u -> %s-%u %u\n",
                asd->session_logging_id,
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
        payload_app_id = referred_payload_app_id = tp_payload_app_id = APP_ID_NONE;
        clear_session_flags(APPID_SESSION_CONTINUE);
        if ( payload_version )
        {
            snort_free(payload_version);
            payload_version = nullptr;
        }
        if ( hsession && hsession->url )
        {
            snort_free(hsession->url);
            hsession->url = nullptr;
        }
    }

    //service
    if ( !get_session_flags(APPID_SESSION_STICKY_SERVICE) )
    {
        tp_app_id = service_app_id = port_service_id = APP_ID_NONE;
        if ( service_vendor )
        {
            snort_free(service_vendor);
            service_vendor = nullptr;
        }
        if ( service_version )
        {
            snort_free(service_version);
            service_version = nullptr;
        }

        service_ip.clear();
        service_port = 0;
        service_disco_state = APPID_DISCO_STATE_NONE;
        service_detector = nullptr;
        free_flow_data_by_mask(APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);
    }

    //client
    client_app_id = client_service_app_id = APP_ID_NONE;
    if ( client_version )
    {
        snort_free(client_version);
        client_version = nullptr;
    }
    client_disco_state = APPID_DISCO_STATE_NONE;
    free_flow_data_by_mask(APPID_SESSION_DATA_CLIENT_MODSTATE_BIT);

    //3rd party cleaning
    if (thirdparty_appid_module)
        thirdparty_appid_module->session_delete(tpsession, 1);
    init_tpPackets = 0;
    resp_tpPackets = 0;

    scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
    clear_session_flags(APPID_SESSION_SERVICE_DETECTED |APPID_SESSION_CLIENT_DETECTED |
        APPID_SESSION_SSL_SESSION|APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT);
}

void AppIdSession::sync_with_snort_id(AppId newAppId, Packet* p)
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
            int16_t tempSnortId = entry->snortId;
            // A particular APP_ID_xxx may not be assigned a service_snort_key value
            // in the rna_app.yaml file entry; so ignore the tempSnortId == 0 case.
            if ( tempSnortId == 0 && (newAppId == APP_ID_HTTP2))
                tempSnortId = snortId_for_http2;

            if ( tempSnortId != snort_id )
            {
                snort_id = tempSnortId;
                if (session_logging_enabled)
                    if (tempSnortId == snortId_for_http2)
                        LogMessage("AppIdDbg %s Telling Snort that it's HTTP/2\n",
                            session_logging_id);

                p->flow->ssn_state.application_protocol = tempSnortId;
            }
        }
    }
}

bool AppIdSession::is_ssl_decryption_enabled()
{
    if (get_session_flags(APPID_SESSION_DECRYPTED))
        return true;

    return flow->is_proxied();
}

void AppIdSession::check_app_detection_restart()
{
    if (get_session_flags(APPID_SESSION_DECRYPTED) || !is_ssl_decryption_enabled() )
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
        encrypted.service_app_id = service_id;
        encrypted.payload_app_id = pick_payload_app_id();
        encrypted.client_app_id = pick_client_app_id();
        encrypted.misc_app_id = pick_misc_app_id();
        encrypted.referred_app_id = pick_referred_payload_app_id();
        reinit_session_data();
        if (session_logging_enabled)
            LogMessage("AppIdDbg %s SSL decryption is available, restarting app Detection\n",
                session_logging_id);

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

void AppIdSession::set_client_app_id_data(AppId id, char* version)
{
    if ( id <= APP_ID_NONE || id == APP_ID_HTTP )
        return;

    if ( id != client_app_id )
    {
        if ( client_app_id )
        {
            unsigned prev_priority = app_info_mgr->get_app_info_priority(client_app_id);
            unsigned curr_priority = app_info_mgr->get_app_info_priority(id);

            if (prev_priority > curr_priority)
                return;
        }

        client_app_id = id;

        if ( client_version )
            snort_free(client_version);
        if (version)
            client_version = snort_strdup(version);
    }
    else if ( version )
    {
        if ( client_version )
            snort_free(client_version);
        client_version = snort_strdup(version);
    }
}

void AppIdSession::examine_ssl_metadata(Packet* p)
{
    int ret;
    AppId client_app_id = 0;
    AppId payload_app_id = 0;

    if ((scan_flags & SCAN_SSL_HOST_FLAG) && tsession->tls_host)
    {
        size_t size = strlen(tsession->tls_host);
        if ((ret = ssl_scan_hostname((const uint8_t*)tsession->tls_host, size,
                &client_app_id, &payload_app_id)))
        {
            set_client_app_id_data(client_app_id, nullptr);
            set_payload_app_id_data((ApplicationId)payload_app_id, nullptr);
            setSSLSquelch(p, ret, (ret == 1 ? payload_app_id : client_app_id));
        }
        scan_flags &= ~SCAN_SSL_HOST_FLAG;
    }
    if (tsession->tls_cname)
    {
        size_t size = strlen(tsession->tls_cname);
        if ((ret = ssl_scan_cname((const uint8_t*)tsession->tls_cname, size,
                &client_app_id, &payload_app_id)))
        {
            set_client_app_id_data(client_app_id, nullptr);
            set_payload_app_id_data((ApplicationId)payload_app_id, nullptr);
            setSSLSquelch(p, ret, (ret == 1 ? payload_app_id : client_app_id));
        }
        snort_free(tsession->tls_cname);
        tsession->tls_cname = nullptr;
    }
    if (tsession->tls_orgUnit)
    {
        size_t size = strlen(tsession->tls_orgUnit);
        if ((ret = ssl_scan_cname((const uint8_t*)tsession->tls_orgUnit, size,
                &client_app_id, &payload_app_id)))
        {
            set_client_app_id_data(client_app_id, nullptr);
            set_payload_app_id_data((ApplicationId)payload_app_id, nullptr);
            setSSLSquelch(p, ret, (ret == 1 ? payload_app_id : client_app_id));
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
        hsession = new AppIdHttpSession(this);

    if ( hsession->url )
    {
        HttpPatternMatchers* http_matchers = HttpPatternMatchers::get_instance();

        if ( ( ( http_matchers->get_appid_from_url(nullptr, hsession->url, &version,
            hsession->referer, &client_id, &service_id,
            &payload_id, &referred_payload_id, true) )
            ||
            ( http_matchers->get_appid_from_url(nullptr, hsession->url, &version,
            hsession->referer, &client_id, &service_id,
            &payload_id, &referred_payload_id, false) ) ) )
        {
            /* do not overwrite a previously-set client or service */
            if (client_app_id <= APP_ID_NONE)
                set_client_app_id_data(payload_id, nullptr);
            if (service_app_id <= APP_ID_NONE)
                set_service_appid_data(service_id, nullptr, nullptr);

            /* DO overwrite a previously-set data */
            set_payload_app_id_data((ApplicationId)payload_app_id, nullptr);
            set_referred_payload_app_id_data(referred_payload_id);
        }
    }
}

void AppIdSession::set_referred_payload_app_id_data(AppId id)
{
    if (id <= APP_ID_NONE)
        return;

    if (referred_payload_app_id != id)
        referred_payload_app_id = id;
}

void AppIdSession::set_payload_app_id_data(ApplicationId id, char* version)
{
    if ( id <= APP_ID_NONE )
        return;

    if ( payload_app_id != id )
    {
        if ( payload_app_id )
        {
            unsigned prev_priority = app_info_mgr->get_app_info_priority(payload_app_id);
            unsigned curr_priority = app_info_mgr->get_app_info_priority(id);
            if (prev_priority > curr_priority)
                return;
        }

        payload_app_id = id;

        if ( payload_version )
            snort_free(payload_version);
        if (version)
            payload_version = snort_strdup(version);
    }
    else if ( version )
    {
        if ( payload_version )
            snort_free(payload_version);
        payload_version = snort_strdup(version);
    }
}

void AppIdSession::set_service_appid_data(AppId id, char* vendor, char* version)
{
    if (id <= APP_ID_NONE)
        return;

    // 3rd party is in INIT state after processing first GET request.
    if (id == APP_ID_HTTP)
    {
        if (client_service_app_id == APP_ID_NONE)
            client_service_app_id = id;
        return;
    }

    if (service_app_id != id)
    {
        service_app_id = id;

        if (service_vendor)
            snort_free(service_vendor);
        service_vendor = vendor;

        if (service_version)
            snort_free(service_version);
        if (version)
            service_version = snort_strdup(version);
    }
    else if (vendor || version)
    {
        if (service_vendor)
            snort_free(service_vendor);
        service_vendor = vendor;

        if (service_version)
            snort_free(service_version);
        if (version)
            service_version = snort_strdup(version);
    }
}

void AppIdSession::free_dns_session_data()
{
    if (dsession )
    {
        if (dsession->host)
        {
            snort_free(dsession->host);
            dsession->host = nullptr;
        }
        snort_free(dsession);
        dsession = nullptr;
    }
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
    snort_free(client_version);
    snort_free(payload_version);
    snort_free(service_vendor);
    snort_free(service_version);
    snort_free(netbios_name);
    snort_free(username);
    snort_free(netbios_domain);

    AppIdServiceSubtype* rna_ss = subtype;
    while ( rna_ss )
    {
        subtype = rna_ss->next;
        snort_free(*(void**)&rna_ss->service);
        snort_free(*(void**)&rna_ss->vendor);
        snort_free(*(void**)&rna_ss->version);
        snort_free(rna_ss);
        rna_ss = subtype;
    }

    delete hsession;
    free_tls_session_data();
    free_dns_session_data();
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

void AppIdSession::stop_rna_service_inspection(Packet* p, int direction)
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
    set_session_flags(APPID_SESSION_SERVICE_DETECTED);
    clear_session_flags(APPID_SESSION_CONTINUE);
}

AppId AppIdSession::pick_service_app_id()
{
    AppId rval;

    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;

    if ( is_service_detected() )
    {
        bool deferred = app_info_mgr->get_app_info_flags(service_app_id, APPINFO_FLAG_DEFER)
            || app_info_mgr->get_app_info_flags(tp_app_id, APPINFO_FLAG_DEFER);

        if (service_app_id > APP_ID_NONE && !deferred)
            return service_app_id;
        if (is_third_party_appid_available(tpsession))
        {
            if (tp_app_id > APP_ID_NONE)
                return tp_app_id;
            else if (deferred)
                return service_app_id;
            else
                rval = APP_ID_UNKNOWN_UI;
        }
        else
            rval = tp_app_id;
    }
    else if (tp_app_id > APP_ID_NONE)
        return tp_app_id;
    else
        rval = APP_ID_NONE;

    if (client_service_app_id > APP_ID_NONE)
        return client_service_app_id;

    if (port_service_id > APP_ID_NONE)
        return port_service_id;

    return rval;
}

AppId AppIdSession::pick_only_service_app_id()
{
    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;

    bool deferred = app_info_mgr->get_app_info_flags(service_app_id, APPINFO_FLAG_DEFER)
        || app_info_mgr->get_app_info_flags(tp_app_id, APPINFO_FLAG_DEFER);

    if (service_app_id > APP_ID_NONE && !deferred)
        return service_app_id;

    if (is_third_party_appid_available(tpsession) && tp_app_id > APP_ID_NONE)
        return tp_app_id;
    else if (deferred)
        return service_app_id;

    if (service_app_id < APP_ID_NONE)
        return APP_ID_UNKNOWN_UI;

    return APP_ID_NONE;
}

AppId AppIdSession::pick_misc_app_id()
{
    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;
    if (misc_app_id > APP_ID_NONE)
        return misc_app_id;
    return APP_ID_NONE;
}

AppId AppIdSession::pick_client_app_id()
{
    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;
    if (client_app_id > APP_ID_NONE)
        return client_app_id;
    return APP_ID_NONE;
}

AppId AppIdSession::pick_payload_app_id()
{
    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;

    // if we have a deferred payload, just use it.
    // we are not worried about the APP_ID_UNKNOWN case here
    if (app_info_mgr->get_app_info_flags(tp_payload_app_id, APPINFO_FLAG_DEFER_PAYLOAD))
        return tp_payload_app_id;
    else if (payload_app_id > APP_ID_NONE)
        return payload_app_id;
    else if (tp_payload_app_id > APP_ID_NONE)
        return tp_payload_app_id;

    return APP_ID_NONE;
}

AppId AppIdSession::pick_referred_payload_app_id()
{
    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;
    if (referred_payload_app_id > APP_ID_NONE)
        return referred_payload_app_id;
    return APP_ID_NONE;
}

AppId AppIdSession::pick_fw_service_app_id()
{
    AppId appId = pick_service_app_id();
    if (appId == APP_ID_NONE || appId== APP_ID_UNKNOWN_UI)
        appId = encrypted.service_app_id;
    return appId;
}

AppId AppIdSession::pick_fw_misc_app_id()
{
    AppId appId = pick_misc_app_id();
    if (appId == APP_ID_NONE)
        appId = encrypted.misc_app_id;
    return appId;
}

AppId AppIdSession::pick_fw_client_app_id()
{
    AppId appId = pick_client_app_id();
    return appId;
}

AppId AppIdSession::pick_fw_payload_app_id()
{
    AppId appId = pick_payload_app_id();
    if (appId == APP_ID_NONE)
        appId = encrypted.payload_app_id;
    return appId;
}

AppId AppIdSession::pick_fw_referred_payload_app_id()
{
    AppId appId = pick_referred_payload_app_id();
    if (appId == APP_ID_NONE)
        appId = encrypted.referred_app_id;
    return appId;
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

bool AppIdSession::is_ssl_session_decrypted()
{
    return get_session_flags(APPID_SESSION_DECRYPTED);
}

void AppIdSession::reset_session_data()
{
    delete_session_data();
    client_version = nullptr;
    payload_version = nullptr;
    service_vendor = nullptr;
    service_version = nullptr;
    netbios_name = nullptr;
    netbios_domain = nullptr;
    username = nullptr;
    hsession = nullptr;

    payload_app_id = APP_ID_UNKNOWN;
    service_app_id = APP_ID_UNKNOWN;
    tp_payload_app_id = APP_ID_UNKNOWN;
    tp_app_id = APP_ID_UNKNOWN;

    if (thirdparty_appid_module)
        thirdparty_appid_module->session_delete(tpsession, 1);
}

bool AppIdSession::is_payload_appid_set()
{
    return ( payload_app_id || tp_payload_app_id );
}

void AppIdSession::clear_http_flags()
{
    if (!get_session_flags(APPID_SESSION_SPDY_SESSION))
    {
        clear_session_flags(APPID_SESSION_CHP_INSPECTING);
        if (thirdparty_appid_module)
            thirdparty_appid_module->session_attr_clear(tpsession,
                TP_ATTR_CONTINUE_MONITORING);
    }
}

