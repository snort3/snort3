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

#include "log/messages.h"
#include "main/snort_config.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "stream/stream.h"
#include "target_based/snort_protocols.h"
#include "time/packet_time.h"

#include "appid_inspector.h"
#include "app_forecast.h"
#include "app_info_table.h"
#include "appid_module.h"
#include "appid_stats.h"
#include "appid_utils/ip_funcs.h"
#include "client_plugins/client_detector.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/http_url_patterns.h"
#include "service_plugins/service_ssl.h"
#include "service_plugins/service_util.h"
#include "thirdparty_appid_utils.h"

ProfileStats httpPerfStats;

unsigned AppIdSession::flow_id = 0;
THREAD_LOCAL AppIdFlowData* AppIdSession::fd_free_list = nullptr;
THREAD_LOCAL uint32_t AppIdSession::appid_flow_data_id = 0;

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
        snprintf(session_logging_id, MAX_SESSION_LOGGING_ID_LEN,
            "%s-%hu -> %s-%hu %u%s AS %u I %u",
            pkt->ptrs.ip_api.get_src()->ntoa(), pkt->ptrs.sp,
            pkt->ptrs.ip_api.get_dst()->ntoa(), pkt->ptrs.dp,
            (unsigned)pkt->ptrs.type, (direction == APP_ID_FROM_INITIATOR) ? "" : " R",
            (unsigned)pkt->pkth->address_space_id, get_instance_id());
}

AppIdSession* AppIdSession::allocate_session(const Packet* p, IpProtocol proto, int direction)
{
    uint16_t port = 0;

    const SfIp* ip = (direction == APP_ID_FROM_INITIATOR)
        ? p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst();
    if ( ( proto == IpProtocol::TCP || proto == IpProtocol::UDP ) && ( p->ptrs.sp != p->ptrs.dp ) )
        port = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.sp : p->ptrs.dp;

    AppIdSession* data = new AppIdSession(proto, ip, port);

    data->flow = p->flow;
    data->stats.firstPktsecond = p->pkth->ts.tv_sec;
    data->set_session_logging_state(p, direction);
    data->snort_id = snortId_for_unsynchronized;
    p->flow->set_flow_data(data);
    return data;
}

AppIdSession::AppIdSession(IpProtocol proto, const SfIp* ip, uint16_t port)
    : FlowData(flow_id), protocol(proto)
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
    http_matchers = HttpPatternMatchers::get_instance();
}

AppIdSession::~AppIdSession()
{
    if ( !in_expected_cache)
    {
        AppIdStatistics* stats_mgr = AppIdInspector::get_inspector()->get_stats_manager();
        if ( stats_mgr )
            stats_mgr->update(this);

        if (flow)
            FailInProcessService(this, config);
    }

    delete_shared_data();
    free_flow_data();
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
    uint16_t cliPort,
    const SfIp* srvIp, uint16_t srvPort, IpProtocol proto, int16_t app_id, int /*flags*/)
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
        srvPort,
        app_id, asd) )
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

void AppIdSession::reinit_shared_data()
{
    misc_app_id = APP_ID_NONE;

    //data
    if (isSslServiceAppId(tp_app_id))
    {
        payload_app_id = referred_payload_app_id = tp_payload_app_id = APP_ID_NONE;
        clear_session_flags(APPID_SESSION_CONTINUE);
        if (payload_version)
        {
            snort_free(payload_version);
            payload_version = nullptr;
        }
        if (hsession && hsession->url)
        {
            snort_free(hsession->url);
            hsession->url = nullptr;
        }
    }

    //service
    if (!get_session_flags(APPID_SESSION_STICKY_SERVICE))
    {
        clear_session_flags(APPID_SESSION_STICKY_SERVICE);

        tp_app_id = serviceAppId = portServiceAppId = APP_ID_NONE;
        if (serviceVendor)
        {
            snort_free(serviceVendor);
            serviceVendor = nullptr;
        }
        if (serviceVersion)
        {
            snort_free(serviceVersion);
            serviceVersion = nullptr;
        }

        service_ip.clear();
        service_port = 0;
        rna_service_state = RNA_STATE_NONE;
        service_detector = nullptr;
        free_flow_data_by_mask(APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);
    }

    //client
    client_app_id = client_service_app_id = APP_ID_NONE;
    if (client_version)
    {
        snort_free(client_version);
        client_version = nullptr;
    }
    rna_client_state = RNA_STATE_NONE;
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
    if (get_session_flags(APPID_SESSION_DECRYPTED))
        return;

    if (!is_ssl_decryption_enabled())
        return;

    AppId serviceAppId = pick_service_app_id();
    bool isSsl = isSslServiceAppId(serviceAppId);

    // A asd could either:
    // 1. Start of as SSL - captured with isSsl flag, OR
    // 2. It could start of as a non-SSL asd and later change to SSL. For example, FTP->FTPS.
    //    In this case APPID_SESSION_ENCRYPTED flag is set by the protocol state machine.
    if (get_session_flags(APPID_SESSION_ENCRYPTED) || isSsl)
    {
        set_session_flags(APPID_SESSION_DECRYPTED);
        encrypted.serviceAppId = serviceAppId;
        encrypted.payloadAppId = pick_payload_app_id();
        encrypted.ClientAppId = pick_client_app_id();
        encrypted.miscAppId = pick_misc_app_id();
        encrypted.referredAppId = pick_referred_payload_app_id();
        reinit_shared_data();
        if (session_logging_enabled)
            LogMessage("AppIdDbg %s SSL decryption is available, restarting app Detection\n",
                session_logging_id);

        // APPID_SESSION_ENCRYPTED is set upon receiving a command which upgrades the asd to
        // SSL. Next packet after the command will have encrypted traffic.  In the case of a
        // asd which starts as SSL, current packet itself is encrypted. Set the special flag
        // APPID_SESSION_APP_REINSPECT_SSL which allows reinspection of this pcaket.
        if (isSsl)
            set_session_flags(APPID_SESSION_APP_REINSPECT_SSL);
    }
}

void AppIdSession::update_encrypted_app_id(AppId serviceAppId)
{
    switch (serviceAppId)
    {
    case APP_ID_HTTP:
        if (misc_app_id == APP_ID_NSIIOPS || misc_app_id == APP_ID_DDM_SSL
            || misc_app_id == APP_ID_MSFT_GC_SSL || misc_app_id ==
            APP_ID_SF_APPLIANCE_MGMT)
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

void AppIdSession::set_client_app_id_data(AppId id, char** version)
{
    if (id <= APP_ID_NONE || id == APP_ID_HTTP)
        return;

    if (id != client_app_id)
    {
        if (client_app_id)
        {
            unsigned prev_priority = app_info_mgr->get_app_info_priority(client_app_id);
            unsigned curr_priority = app_info_mgr->get_app_info_priority(id);

            if (prev_priority > curr_priority)
                return;
        }

        client_app_id = id;

        if (client_version)
            snort_free(client_version);

        if (version && *version)
        {
            client_version = *version;
            *version = nullptr;
        }
        else
            client_version = nullptr;
    }
    else if (version && *version)
    {
        if (client_version)
            snort_free(client_version);
        client_version = *version;
        *version = nullptr;
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
    AppId serviceAppId = 0;
    AppId client_app_id = 0;
    AppId payload_app_id = 0;
    AppId referredPayloadAppId = 0;
    char* version = nullptr;

    if (!hsession)
        hsession = (HttpSession*)snort_calloc(sizeof(HttpSession));

    if (hsession->url)
    {
        if (((http_matchers->get_appid_from_url(nullptr, hsession->url, &version,
            hsession->referer, &client_app_id, &serviceAppId,
            &payload_app_id, &referredPayloadAppId, 1)) ||
            (http_matchers->get_appid_from_url(nullptr, hsession->url, &version,
            hsession->referer, &client_app_id, &serviceAppId,
            &payload_app_id, &referredPayloadAppId, 0))) == 1)
        {
            /* do not overwrite a previously-set client or service */
            if (client_app_id <= APP_ID_NONE)
                set_client_app_id_data(client_app_id, nullptr);
            if (serviceAppId <= APP_ID_NONE)
                set_service_appid_data(serviceAppId, nullptr, nullptr);

            /* DO overwrite a previously-set data */
            set_payload_app_id_data((ApplicationId)payload_app_id, nullptr);
            set_referred_payload_app_id_data(referredPayloadAppId);
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

void AppIdSession::set_payload_app_id_data(ApplicationId id, char** version)
{
    if (id <= APP_ID_NONE)
        return;

    if (payload_app_id != id)
    {
        if (payload_app_id)
        {
            unsigned prev_priority = app_info_mgr->get_app_info_priority(payload_app_id);
            unsigned curr_priority = app_info_mgr->get_app_info_priority(id);
            if (prev_priority > curr_priority)
                return;
        }

        payload_app_id = id;

        if (payload_version)
            snort_free(payload_version);

        if (version && *version)
        {
            payload_version = *version;
            *version = nullptr;
        }
        else
            payload_version = nullptr;
    }
    else if (version && *version)
    {
        if (payload_version)
            snort_free(payload_version);
        payload_version = *version;
        *version = nullptr;
    }
}

void AppIdSession::set_service_appid_data(AppId id, char* vendor, char** version)
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

    if (serviceAppId != id)
    {
        serviceAppId = id;

        if (serviceVendor)
        {
            snort_free(serviceVendor);
            serviceVendor = nullptr;
        }
        if (serviceVersion)
        {
            snort_free(serviceVersion);
            serviceVersion = nullptr;
        }

        if (vendor)
            serviceVendor = vendor;

        if (version && *version)
        {
            serviceVersion = *version;
            *version = nullptr;
        }
    }
    else
    {
        if (vendor || version)
        {
            if (serviceVendor)
                snort_free(serviceVendor);
            if (serviceVersion)
                snort_free(serviceVersion);

            if (vendor)
                serviceVendor = vendor;
            else
                serviceVendor = nullptr;

            if (version && *version)
            {
                serviceVersion = *version;
                *version = nullptr;
            }
            else
                serviceVersion = nullptr;
        }
    }
}

void AppIdSession::clear_http_field()
{
    if (hsession == nullptr)
        return;

    if (hsession->x_working_with)
    {
        snort_free(hsession->x_working_with);
        hsession->x_working_with = nullptr;
    }
    if (hsession->referer)
    {
        snort_free(hsession->referer);
        hsession->referer = nullptr;
    }
    if (hsession->cookie)
    {
        snort_free(hsession->cookie);
        hsession->cookie = nullptr;
    }
    if (hsession->url)
    {
        snort_free(hsession->url);
        hsession->url = nullptr;
    }
    if (hsession->useragent)
    {
        snort_free(hsession->useragent);
        hsession->useragent = nullptr;
    }
    if (hsession->host)
    {
        snort_free(hsession->host);
        hsession->host = nullptr;
    }
    if (hsession->uri)
    {
        snort_free(hsession->uri);
        hsession->uri = nullptr;
    }
    if (hsession->content_type)
    {
        snort_free(hsession->content_type);
        hsession->content_type = nullptr;
    }
    if (hsession->location)
    {
        snort_free(hsession->location);
        hsession->location = nullptr;
    }
    if (hsession->body)
    {
        snort_free(hsession->body);
        hsession->body = nullptr;
    }
    if (hsession->req_body)
    {
        snort_free(hsession->req_body);
        hsession->req_body = nullptr;
    }
    if (hsession->xffAddr)
    {
        delete hsession->xffAddr;
        hsession->xffAddr = nullptr;
    }
}

void AppIdSession::free_http_session_data()
{
    if (hsession == nullptr)
        return;

    clear_http_field();

    if (hsession->new_field_contents)
        for ( unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
        {
            if (nullptr != hsession->new_field[i])
            {
                snort_free(hsession->new_field[i]);
                hsession->new_field[i] = nullptr;
            }
        }
    if (hsession->via)
    {
        snort_free(hsession->via);
        hsession->via = nullptr;
    }
    if (hsession->content_type)
    {
        snort_free(hsession->content_type);
        hsession->content_type = nullptr;
    }
    if (hsession->response_code)
    {
        snort_free(hsession->response_code);
        hsession->response_code = nullptr;
    }
    if (hsession->server)
    {
        snort_free(hsession->server);
        hsession->server = nullptr;
    }

    snort_free(hsession);
    hsession = nullptr;
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

void AppIdSession::free_flow_data()
{
    AppIdFlowData* tmp_fd;

    while ((tmp_fd = flowData))
    {
        flowData = tmp_fd->next;
        if (tmp_fd->fd_data && tmp_fd->fd_free)
            tmp_fd->fd_free(tmp_fd->fd_data);

        snort_free(tmp_fd);
    }
}

void AppIdSession::delete_shared_data()
{
    if (thirdparty_appid_module)
    {
        thirdparty_appid_module->session_delete(tpsession, 0);
        tpsession = nullptr;
    }

    snort_free(client_version);
    snort_free(serviceVendor);
    snort_free(serviceVersion);
    snort_free(netbios_name);

    RNAServiceSubtype* rna_ss = subtype;
    while ( rna_ss )
    {
        subtype = rna_ss->next;
        snort_free(*(void**)&rna_ss->service);
        snort_free(*(void**)&rna_ss->vendor);
        snort_free(*(void**)&rna_ss->version);
        snort_free(rna_ss);
        rna_ss = subtype;
    }

    service_candidates.clear();
    client_candidates.clear();
    snort_free(username);
    snort_free(netbios_domain);
    snort_free(payload_version);
    free_http_session_data();
    free_tls_session_data();
    free_dns_session_data();

    snort_free(firewallEarlyData);
    firewallEarlyData = nullptr;
}

void AppIdSession::release_free_list_flow_data()
{
    AppIdFlowData* tmp_fd;

    while ((tmp_fd = fd_free_list))
    {
        fd_free_list = fd_free_list->next;
        snort_free(tmp_fd);
    }
}

void* AppIdSession::get_flow_data(unsigned id)
{
    AppIdFlowData* tmp_fd;

    for (tmp_fd = flowData; tmp_fd && tmp_fd->fd_id != id; tmp_fd = tmp_fd->next)
        ;
    return tmp_fd ? tmp_fd->fd_data : nullptr;
}

void* AppIdSession::remove_flow_data(unsigned id)
{
    AppIdFlowData** pfd;
    AppIdFlowData* fd;

    for (pfd = &flowData; *pfd && (*pfd)->fd_id != id; pfd = &(*pfd)->next)
        ;
    if ((fd = *pfd))
    {
        *pfd = fd->next;
        fd->next = fd_free_list;
        fd_free_list = fd;
        return fd->fd_data;
    }
    return nullptr;
}

void AppIdSession::free_flow_data_by_id(unsigned id)
{
    AppIdFlowData** pfd;
    AppIdFlowData* fd;

    for (pfd = &flowData; *pfd && (*pfd)->fd_id != id; pfd = &(*pfd)->next)
        ;

    if ((fd = *pfd))
    {
        *pfd = fd->next;
        if (fd->fd_data && fd->fd_free)
            fd->fd_free(fd->fd_data);
        fd->next = fd_free_list;
        fd_free_list = fd;
    }
}

void AppIdSession::free_flow_data_by_mask(unsigned mask)
{
    AppIdFlowData** pfd = &flowData;
    while (*pfd)
    {
        if ((*pfd)->fd_id & mask)
        {
            AppIdFlowData* fd = *pfd;
            *pfd = fd->next;
            if (fd->fd_data && fd->fd_free)
                fd->fd_free(fd->fd_data);
            fd->next = fd_free_list;
            fd_free_list = fd;
        }
        else
        {
            pfd = &(*pfd)->next;
        }
    }
}

int AppIdSession::add_flow_data(void* data, unsigned id, AppIdFreeFCN fcn)
{
    AppIdFlowData* tmp_fd;

    if (fd_free_list)
    {
        tmp_fd = fd_free_list;
        fd_free_list = tmp_fd->next;
    }
    else
        tmp_fd = (AppIdFlowData*)snort_alloc(sizeof(AppIdFlowData));

    tmp_fd->fd_id = id;
    tmp_fd->fd_data = data;
    tmp_fd->fd_free = fcn;
    tmp_fd->next = flowData;
    flowData = tmp_fd;
    return 0;
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

    rna_service_state = RNA_STATE_FINISHED;
    set_session_flags(APPID_SESSION_SERVICE_DETECTED);
    clear_session_flags(APPID_SESSION_CONTINUE);
}

AppId AppIdSession::is_appid_detection_done()
{
    return get_session_flags(APPID_SESSION_SERVICE_DETECTED);
}

AppId AppIdSession::pick_service_app_id()
{
    AppId rval;

    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;

    if (get_session_flags(APPID_SESSION_SERVICE_DETECTED))
    {
        bool deferred = app_info_mgr->get_app_info_flags(serviceAppId, APPINFO_FLAG_DEFER)
            || app_info_mgr->get_app_info_flags(tp_app_id, APPINFO_FLAG_DEFER);

        if (serviceAppId > APP_ID_NONE && !deferred)
            return serviceAppId;
        if (is_third_party_appid_available(tpsession))
        {
            if (tp_app_id > APP_ID_NONE)
                return tp_app_id;
            else if (deferred)
                return serviceAppId;
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

    if (portServiceAppId > APP_ID_NONE)
        return portServiceAppId;

    return rval;
}

AppId AppIdSession::pick_only_service_app_id()
{
    if ( common.flow_type != APPID_FLOW_TYPE_NORMAL )
        return APP_ID_NONE;

    bool deferred = app_info_mgr->get_app_info_flags(serviceAppId, APPINFO_FLAG_DEFER)
        || app_info_mgr->get_app_info_flags(tp_app_id, APPINFO_FLAG_DEFER);

    if (serviceAppId > APP_ID_NONE && !deferred)
        return serviceAppId;

    if (is_third_party_appid_available(tpsession) && tp_app_id > APP_ID_NONE)
        return tp_app_id;
    else if (deferred)
        return serviceAppId;

    if (serviceAppId < APP_ID_NONE)
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
    if (appId == APP_ID_NONE)
        appId = encrypted.serviceAppId;
    return appId;
}

AppId AppIdSession::pick_fw_misc_app_id()
{
    AppId appId = pick_misc_app_id();
    if (appId == APP_ID_NONE)
        appId = encrypted.miscAppId;
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
        appId = encrypted.payloadAppId;
    return appId;
}

AppId AppIdSession::pick_fw_referred_payload_app_id()
{
    AppId appId = pick_referred_payload_app_id();
    if (appId == APP_ID_NONE)
        appId = encrypted.referredAppId;
    return appId;
}

bool AppIdSession::is_ssl_session_decrypted()
{
    return get_session_flags(APPID_SESSION_DECRYPTED);
}

static const char* httpFieldName[ NUMBER_OF_PTYPES ] = // for use in debug messages
{
    "useragent",
    "host",
    "referer",
    "uri",
    "cookie",
    "req_body",
    "content_type",
    "location",
    "body",
};

void AppIdSession::clear_app_id_data()
{
    payload_app_id = APP_ID_UNKNOWN;
    serviceAppId = APP_ID_UNKNOWN;
    tp_payload_app_id = APP_ID_UNKNOWN;
    tp_app_id = APP_ID_UNKNOWN;

    if (payload_version)
    {
        snort_free(payload_version);
        payload_version = nullptr;
    }

    if (serviceVendor)
    {
        snort_free(serviceVendor);
        serviceVendor = nullptr;
    }

    if (serviceVersion)
    {
        snort_free(serviceVersion);
        serviceVersion = nullptr;
    }

    if (tsession)
        free_tls_session_data();

    if (hsession)
        free_http_session_data();

    if (dsession)
        free_dns_session_data();

    if (thirdparty_appid_module)
        thirdparty_appid_module->session_delete(tpsession, 1);
}

int AppIdSession::initial_chp_sweep(char** chp_buffers, uint16_t* chp_buffer_lengths,
    MatchedCHPAction** ppmatches)
{
    CHPApp* cah = nullptr;
    int longest = 0;
    CHPTallyAndActions chp;
    chp.matches = *ppmatches;

    for (unsigned i = 0; i <= MAX_KEY_PATTERN; i++)
    {
        ppmatches[i] = nullptr;
        if (chp_buffers[i] && chp_buffer_lengths[i])
            http_matchers->scan_key_chp((PatternType)i, chp_buffers[i], chp_buffer_lengths[i],
                chp);
    }
    if (chp.match_tally.empty())
        return 0;

    for (auto& item: chp.match_tally)
    {
        // Only those items which have had their key_pattern_countdown field reduced to zero are a
        // full match
        if (item.key_pattern_countdown)
            continue;
        if (longest < item.key_pattern_length_sum)
        {
            // We've found a new longest pattern set
            longest = item.key_pattern_length_sum;
            cah = item.chpapp;
        }
    }

    if (cah == nullptr)
    {
        // We were planning to pass along the content of ppmatches to the second phase and let
        // them be freed inside scanCHP, but we have no candidate so we free here
        for (unsigned i = 0; i <= MAX_KEY_PATTERN; i++)
        {
            if (ppmatches[i])
            {
                http_matchers->free_matched_chp_actions(ppmatches[i]);
                ppmatches[i] = nullptr;
            }
        }
        return 0;
    }

    /***************************************************************
       candidate has been chosen and it is pointed to by cah
       we will preserve any match sets until the calls to scanCHP()
      ***************************************************************/
    for (unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
    {
        hsession->ptype_scan_counts[i] = cah->ptype_scan_counts[i];
        hsession->ptype_req_counts[i] = cah->ptype_req_counts[i] +
            cah->ptype_rewrite_insert_used[i];
        if (i > 3 && !cah->ptype_scan_counts[i]
            && !get_session_flags(APPID_SESSION_SPDY_SESSION))
        {
            clear_session_flags(APPID_SESSION_CHP_INSPECTING);
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_attr_clear(tpsession,
                    TP_ATTR_CONTINUE_MONITORING);
        }
    }
    hsession->chp_candidate = cah->appIdInstance;
    hsession->app_type_flags = cah->app_type_flags;
    hsession->num_matches = cah->num_matches;
    hsession->num_scans = cah->num_scans;

    if (thirdparty_appid_module)
    {
        if ((hsession->ptype_scan_counts[CONTENT_TYPE_PT]))
            thirdparty_appid_module->session_attr_set(tpsession, TP_ATTR_COPY_RESPONSE_CONTENT);
        else
            thirdparty_appid_module->session_attr_clear(tpsession, TP_ATTR_COPY_RESPONSE_CONTENT);

        if ((hsession->ptype_scan_counts[LOCATION_PT]))
            thirdparty_appid_module->session_attr_set(tpsession, TP_ATTR_COPY_RESPONSE_LOCATION);
        else
            thirdparty_appid_module->session_attr_clear(tpsession, TP_ATTR_COPY_RESPONSE_LOCATION);


        if ((hsession->ptype_scan_counts[BODY_PT]))
            thirdparty_appid_module->session_attr_set(tpsession, TP_ATTR_COPY_RESPONSE_BODY);
        else
            thirdparty_appid_module->session_attr_clear(tpsession, TP_ATTR_COPY_RESPONSE_BODY);
    }

    return 1;
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

void AppIdSession::process_chp_buffers(char** version, Packet* p)
{
    char* chp_buffers[NUMBER_OF_PTYPES] =
    {
        hsession->useragent,
        hsession->host,
        hsession->referer,
        hsession->uri,
        hsession->cookie,
        hsession->req_body,
        hsession->content_type,
        hsession->location,
        hsession->body,
    };

    uint16_t chp_buffer_lengths[NUMBER_OF_PTYPES] =
    {
        hsession->useragent_buflen,
        hsession->host_buflen,
        hsession->referer_buflen,
        hsession->uri_buflen,
        hsession->cookie_buflen,
        hsession->req_body_buflen,
        hsession->content_type_buflen,
        hsession->location_buflen,
        hsession->body_buflen,
    };

    char* chp_rewritten[NUMBER_OF_PTYPES] =
    {
        nullptr,nullptr,nullptr,
        nullptr,nullptr,nullptr,
        nullptr,nullptr,nullptr
    };

    MatchedCHPAction* chp_matches[NUMBER_OF_PTYPES] =
    {
        nullptr,nullptr,nullptr,
        nullptr,nullptr,nullptr,
        nullptr,nullptr,nullptr
    };

    if ( hsession->chp_hold_flow )
        hsession->chp_finished = 0;

    if ( !hsession->chp_candidate )
    {
        // remove artifacts from previous matches before we start again.
        for (unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
            if (hsession->new_field[i])
            {
                snort_free(hsession->new_field[i]);
                hsession->new_field[i] = nullptr;
            }

        if ( !initial_chp_sweep(chp_buffers, chp_buffer_lengths, chp_matches) )
            hsession->chp_finished = 1; // this is a failure case.
    }

    if ( !hsession->chp_finished && hsession->chp_candidate )
    {
        char* user = nullptr;

        for (unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
        {
            if ( !hsession->ptype_scan_counts[i] )
                continue;

            if ( chp_buffers[i] && chp_buffer_lengths[i] )
            {
                int found_in_buffer = 0;
                AppId ret = http_matchers->scan_chp((PatternType)i, chp_buffers[i],
                    chp_buffer_lengths[i], chp_matches[i], version, &user,
                    &chp_rewritten[i], &found_in_buffer, hsession, p, config->mod_config);
                chp_matches[i] = nullptr; // freed by scanCHP()
                hsession->total_found += found_in_buffer;
                if (!ret || found_in_buffer < hsession->ptype_req_counts[i])
                {
                    // No match at all or the required matches for the field was NOT made
                    if (!hsession->num_matches)
                    {
                        // num_matches == 0 means: all must succeed
                        // give up early
                        hsession->chp_candidate = 0;
                        break;
                    }
                }
            }
            else if ( !hsession->num_matches )
            {
                // num_matches == 0 means: all must succeed  give up early
                hsession->chp_candidate = 0;
                break;
            }

            // Decrement the expected scan count toward 0.
            hsession->ptype_scan_counts[i] = 0;
            hsession->num_scans--;
            // if we have reached the end of the list of scans (which have something to do), then
            // num_scans == 0
            if (hsession->num_scans == 0)
            {
                // we finished the last scan
                // either the num_matches value was zero and we failed early-on or we need to check
                // for the min.
                if (hsession->num_matches &&
                    hsession->total_found < hsession->num_matches)
                {
                    // There was a minimum scans match count (num_matches != 0)
                    // And we did not reach that minimum
                    hsession->chp_candidate = 0;
                    break;
                }
                // All required matches were met.
                hsession->chp_finished = 1;
                break;
            }
        }

        if ( !hsession->chp_candidate )
        {
            hsession->chp_finished = 1;
            if ( *version )
            {
                snort_free(*version);
                *version = nullptr;
            }

            if ( user )
            {
                snort_free(user);
                user = nullptr;
            }

            for (unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
            {
                if (nullptr != chp_rewritten[i])
                {
                    snort_free(chp_rewritten[i]);
                    chp_rewritten[i] = nullptr;
                }
            }
            memset(hsession->ptype_scan_counts, 0, NUMBER_OF_PTYPES * sizeof(int));

            // Make it possible for other detectors to run.
            hsession->skip_simple_detect = false;
            return;
        }

        if (hsession->chp_candidate && hsession->chp_finished)
        {
            AppId chp_final = hsession->chp_alt_candidate ? hsession->chp_alt_candidate
                : CHP_APPIDINSTANCE_TO_ID(hsession->chp_candidate);

            if (hsession->app_type_flags & APP_TYPE_SERVICE)
                set_service_appid_data(chp_final, nullptr, version);

            if (hsession->app_type_flags & APP_TYPE_CLIENT)
                set_client_app_id_data(chp_final, version);

            if ( hsession->app_type_flags & APP_TYPE_PAYLOAD )
                set_payload_app_id_data((ApplicationId)chp_final, version);

            if ( *version )
                *version = nullptr;

            if ( user )
            {
                username = user;
                user = nullptr;
                if (hsession->app_type_flags & APP_TYPE_SERVICE)
                    username_service = chp_final;
                else
                    username_service = serviceAppId;
                set_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
            }

            for (unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
                if ( chp_rewritten[i] )
                {
                    if (session_logging_enabled)
                        LogMessage("AppIdDbg %s rewritten %s: %s\n", session_logging_id,
                            httpFieldName[i], chp_rewritten[i]);
                    if (hsession->new_field[i])
                        snort_free(hsession->new_field[i]);
                    hsession->new_field[i] = chp_rewritten[i];
                    hsession->new_field_contents = true;
                    chp_rewritten[i] = nullptr;
                }

            hsession->chp_candidate = 0;
            //if we're doing safesearch rewrites, we want to continue to hold the flow
            if (!hsession->get_offsets_from_rebuilt)
                hsession->chp_hold_flow = 0;
            scan_flags &= ~SCAN_HTTP_VIA_FLAG;
            scan_flags &= ~SCAN_HTTP_USER_AGENT_FLAG;
            scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
            memset(hsession->ptype_scan_counts, 0,
                NUMBER_OF_PTYPES * sizeof(hsession->ptype_scan_counts[0]));
        }
        else /* if we have a candidate, but we're not finished */
        {
            if ( user )
            {
                snort_free(user);
                user = nullptr;
            }

            for (unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
                if (nullptr != chp_rewritten[i])
                {
                    snort_free(chp_rewritten[i]);
                    chp_rewritten[i] = nullptr;
                }
        }
    }
}

int AppIdSession::process_http_packet(int direction)
{
    Profile http_profile_context(httpPerfStats);
    constexpr auto RESPONSE_CODE_LENGTH = 3;
    int size;
    char* version = nullptr;
    char* vendorVersion = nullptr;
    char* vendor = nullptr;
    AppId service_id = 0;
    AppId client_id = 0;
    AppId payload_id = 0;

    if (!hsession)
    {
        clear_app_id_data();
        if (session_logging_enabled)
            LogMessage("AppIdDbg %s attempt to process HTTP packet with no HTTP data\n",
                session_logging_id);

        return 0;
    }

    // For fragmented HTTP headers, do not process if none of the fields are set.
    // These fields will get set when the HTTP header is reassembled.
    if ((!hsession->useragent) && (!hsession->host) && (!hsession->referer) &&
        (!hsession->uri))
    {
        if (!hsession->skip_simple_detect)
            clear_http_flags();

        return 0;
    }

    if (direction == APP_ID_FROM_RESPONDER && !get_session_flags(
        APPID_SESSION_RESPONSE_CODE_CHECKED))
    {
        if (hsession->response_code)
        {
            set_session_flags(APPID_SESSION_RESPONSE_CODE_CHECKED);
            if (hsession->response_code_buflen != RESPONSE_CODE_LENGTH)
            {
                /* received bad response code. Stop processing this session */
                clear_app_id_data();
                if (session_logging_enabled)
                    LogMessage("AppIdDbg %s bad http response code\n", session_logging_id);

                return 0;
            }
        }
#if RESPONSE_CODE_PACKET_THRESHHOLD
        else if (++(hsession->response_code_packets) == RESPONSE_CODE_PACKET_THRESHHOLD)
        {
            set_session_flags(APPID_SESSION_RESPONSE_CODE_CHECKED);
            /* didn't receive response code in first X packets. Stop processing this asd */
            clear_app_id_data(asd);
            if (session_logging_enabled)
                LogMessage("AppIdDbg %s no response code received\n", session_logging_id);
            PREPROC_PROFILE_END(httpPerfStats);
            return 0;
        }
#endif
    }
    char* host = hsession->host;
    char* url = hsession->url;
    char* via = hsession->via;
    char* useragent = hsession->useragent;
    char* referer = hsession->referer;

    if (serviceAppId == APP_ID_NONE)
        serviceAppId = APP_ID_HTTP;

    if (session_logging_enabled)
        LogMessage("AppIdDbg %s chp_finished %d chp_hold_flow %d\n", session_logging_id,
            hsession->chp_finished, hsession->chp_hold_flow);

    if (!hsession->chp_finished || hsession->chp_hold_flow)
        process_chp_buffers(&version, nullptr);

    if (!hsession->skip_simple_detect)  // true if processCHP found match
    {
        if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
        {
            // Scan Server Header for Vendor & Version
            // FIXIT-M: Should we be checking the scan_flags even when
            //     thirdparty_appid_module is off?
            if ((thirdparty_appid_module && (scan_flags & SCAN_HTTP_VENDOR_FLAG) &&
                hsession->server) ||
                (!thirdparty_appid_module && hsession->server))
            {
                if (serviceAppId == APP_ID_NONE || serviceAppId == APP_ID_HTTP)
                {
                    RNAServiceSubtype* local_subtype = nullptr;
                    RNAServiceSubtype** tmpSubtype;

                    http_matchers->get_server_vendor_version((uint8_t*)hsession->server,
                        strlen(hsession->server), &vendorVersion, &vendor, &subtype);
                    if (vendor || vendorVersion)
                    {
                        if (serviceVendor)
                        {
                            snort_free(serviceVendor);
                            serviceVendor = nullptr;
                        }
                        if (serviceVersion)
                        {
                            snort_free(serviceVersion);
                            serviceVersion = nullptr;
                        }
                        if (vendor)
                            serviceVendor = vendor;
                        if (vendorVersion)
                            serviceVersion = vendorVersion;
                        scan_flags &= ~SCAN_HTTP_VENDOR_FLAG;
                    }
                    if (local_subtype)
                    {
                        for (tmpSubtype = &subtype; *tmpSubtype; tmpSubtype = &(*tmpSubtype)->next)
                            ;

                        *tmpSubtype = local_subtype;
                    }
                }
            }

            if (hsession->is_webdav)
            {
                if (session_logging_enabled and payload_app_id != APP_ID_WEBDAV)
                    LogMessage("AppIdDbg %s data is webdav\n", session_logging_id);
                set_payload_app_id_data(APP_ID_WEBDAV, nullptr);
            }

            // Scan User-Agent for Browser types or Skype
            if ((scan_flags & SCAN_HTTP_USER_AGENT_FLAG) && client_app_id <= APP_ID_NONE
                && useragent && hsession->useragent_buflen)
            {
                if (version)
                {
                    snort_free(version);
                    version = nullptr;
                }
                http_matchers->identify_user_agent((uint8_t*)useragent, hsession->useragent_buflen,
                    &service_id, &client_id, &version);
                if (session_logging_enabled && service_id > APP_ID_NONE &&
                    service_id != APP_ID_HTTP && serviceAppId != service_id)
                    LogMessage("AppIdDbg %s User Agent is service %d\n", session_logging_id,
                        service_id);
                set_service_appid_data(service_id, nullptr, nullptr);
                if (session_logging_enabled && client_id > APP_ID_NONE &&
                    client_id != APP_ID_HTTP && client_app_id != client_id)
                    LogMessage("AppIdDbg %s User Agent is client %d\n", session_logging_id,
                        client_id);
                set_client_app_id_data(client_id, &version);
                scan_flags &= ~SCAN_HTTP_USER_AGENT_FLAG;
            }

            /* Scan Via Header for squid */
            if (!is_payload_appid_set() && (scan_flags & SCAN_HTTP_VIA_FLAG) && via &&
                (size = strlen(via)) > 0)
            {
                if (version)
                {
                    snort_free(version);
                    version = nullptr;
                }
                payload_id = http_matchers->get_appid_by_pattern((uint8_t*)via, size, &version);
                if (session_logging_enabled && payload_id > APP_ID_NONE &&
                    payload_app_id != payload_id)
                    LogMessage("AppIdDbg %s VIA is data %d\n", session_logging_id,
                        payload_id);
                set_payload_app_id_data((ApplicationId)payload_id, nullptr);
                scan_flags &= ~SCAN_HTTP_VIA_FLAG;
            }
        }

        /* Scan X-Working-With HTTP header */
        // FIXIT-M: Should we be checking the scan_flags even when
        //     thirdparty_appid_module is off?
        if ((thirdparty_appid_module && (scan_flags & SCAN_HTTP_XWORKINGWITH_FLAG) &&
            hsession->x_working_with) ||
            (!thirdparty_appid_module && hsession->x_working_with))
        {
            AppId appId;

            appId = http_matchers->scan_header_x_working_with((uint8_t*)hsession->x_working_with,
                strlen(hsession->x_working_with), &version);
            if (appId)
            {
                if (direction == APP_ID_FROM_INITIATOR)
                {
                    if (session_logging_enabled && client_id > APP_ID_NONE && client_id !=
                        APP_ID_HTTP && client_app_id != client_id)
                        LogMessage("AppIdDbg %s X is client %d\n", session_logging_id, appId);
                    set_client_app_id_data(appId, &version);
                }
                else
                {
                    if (session_logging_enabled && service_id > APP_ID_NONE && service_id !=
                        APP_ID_HTTP && serviceAppId != service_id)
                        LogMessage("AppIdDbg %s X is service %d\n", session_logging_id, appId);
                    set_service_appid_data(appId, nullptr, &version);
                }
                scan_flags &= ~SCAN_HTTP_XWORKINGWITH_FLAG;
            }
        }

        // Scan Content-Type Header for multimedia types and scan contents
        // FIXIT-M: Should we be checking the scan_flags even when
        //     thirdparty_appid_module is off?
        if ((thirdparty_appid_module && (scan_flags & SCAN_HTTP_CONTENT_TYPE_FLAG)
            && hsession->content_type  && !is_payload_appid_set()) ||
            (!thirdparty_appid_module && !is_payload_appid_set() &&
            hsession->content_type))
        {
            payload_id = http_matchers->get_appid_by_content_type((uint8_t*)hsession->content_type,
                strlen(hsession->content_type));
            if (session_logging_enabled && payload_id > APP_ID_NONE
                && payload_app_id != payload_id)
                LogMessage("AppIdDbg %s Content-Type is data %d\n", session_logging_id,
                    payload_id);
            set_payload_app_id_data((ApplicationId)payload_id, nullptr);
            scan_flags &= ~SCAN_HTTP_CONTENT_TYPE_FLAG;
        }

        if (scan_flags & SCAN_HTTP_HOST_URL_FLAG)
        {
            AppId referredPayloadAppId = 0;

            if (version)
            {
                snort_free(version);
                version = nullptr;
            }

            if (http_matchers->get_appid_from_url(host, url, &version, referer, &client_id,
                &service_id,
                &payload_id, &referredPayloadAppId, 0) == 1)
            {
                // do not overwrite a previously-set client or service
                if (client_app_id <= APP_ID_NONE)
                {
                    if (session_logging_enabled && client_id > APP_ID_NONE && client_id !=
                        APP_ID_HTTP && client_app_id != client_id)
                        LogMessage("AppIdDbg %s URL is client %d\n", session_logging_id,
                            client_id);
                    set_client_app_id_data(client_id, nullptr);
                }
                if (serviceAppId <= APP_ID_NONE)
                {
                    if (session_logging_enabled && service_id > APP_ID_NONE && service_id !=
                        APP_ID_HTTP && serviceAppId != service_id)
                        LogMessage("AppIdDbg %s URL is service %d\n", session_logging_id,
                            service_id);
                    set_service_appid_data(service_id, nullptr, nullptr);
                }
                // DO overwrite a previously-set data
                if (session_logging_enabled && payload_id > APP_ID_NONE &&
                    payload_app_id != payload_id)
                    LogMessage("AppIdDbg %s URL is data %d\n", session_logging_id, payload_id);
                set_payload_app_id_data((ApplicationId)payload_app_id, &version);
                set_referred_payload_app_id_data(referredPayloadAppId);
            }
            scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
        }

        if (client_app_id == APP_ID_APPLE_CORE_MEDIA)
        {
            AppInfoTableEntry* entry;

            if (tp_payload_app_id > APP_ID_NONE)
            {
                entry = app_info_mgr->get_app_info_entry(tp_payload_app_id);
                // only move tpPayloadAppId to client if its got a client_app_id
                if (entry && entry->clientId > APP_ID_NONE)
                {
                    misc_app_id = client_app_id;
                    client_app_id = tp_payload_app_id;
                }
            }
            else if (payload_app_id > APP_ID_NONE)
            {
                entry =  app_info_mgr->get_app_info_entry(payload_app_id);
                // only move payload_app_id to client if it has a ClientAppid
                if (entry && entry->clientId > APP_ID_NONE)
                {
                    misc_app_id = client_app_id;
                    client_app_id = payload_app_id;
                }
            }
        }

        clear_http_flags();
    }  // end DON'T skip_simple_detect

    snort_free(version);
    return 0;
}

