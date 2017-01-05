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

// appid_session.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_session.h"

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
#include "appid_module.h"
#include "appid_stats.h"
#include "appid_utils/ip_funcs.h"
#include "client_plugins/client_app_base.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/detector_http.h"
#include "host_port_app_cache.h"
#include "service_plugins/service_base.h"
#include "service_plugins/service_ssl.h"

ProfileStats tpPerfStats;
ProfileStats tpLibPerfStats;
ProfileStats httpPerfStats;
ProfileStats clientMatchPerfStats;
ProfileStats serviceMatchPerfStats;

unsigned AppIdSession::flow_id = 0;
THREAD_LOCAL AppIdFlowData* AppIdSession::fd_free_list = nullptr;
THREAD_LOCAL uint32_t AppIdSession::appid_flow_data_id = 0;

static int16_t snortId_for_unsynchronized;
static int16_t snortId_for_ftp_data;
static int16_t snortId_for_http2;

inline int ThirdPartyAppIDFoundProto(AppId proto, AppId* proto_list)
{
    unsigned int proto_cnt = 0;
    while (proto_list[proto_cnt] != APP_ID_NONE)
        if (proto_list[proto_cnt++] == proto)
            return 1;       // found

    return 0;            // not found
}

inline int testSSLAppIdForReinspect(AppId app_id)
{
    if (app_id <= SF_APPID_MAX &&
            (app_id == APP_ID_SSL || AppInfoManager::get_instance().get_app_info_flags(app_id, APPINFO_FLAG_SSL_INSPECT)))
        return 1;
    else
        return 0;
}

void AppIdSession::add_user(AppIdSession* asd, const char* username, AppId appId, int success)
{
    if (asd->username)
        snort_free(asd->username);
    asd->username = snort_strdup(username);
    asd->username_service = appId;
    if (success)
        asd->set_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
    else
        asd->clear_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
}

void AppIdSession::add_payload(AppIdSession* asd, AppId payload_id)
{
    asd->payload_app_id = payload_id;
}

void map_app_names_to_snort_ids()
{
    /* init globals for snortId compares */
    snortId_for_unsynchronized = snort_conf->proto_ref->add("unsynchronized");
    snortId_for_ftp_data = snort_conf->proto_ref->find("ftp-data");
    snortId_for_http2    = snort_conf->proto_ref->find("http2");
}

void AppIdSession::set_session_logging_state(const Packet* pkt, int direction)
{
    if(config->mod_config->session_log_filter.log_all_sessions)
    {
        session_logging_enabled = true;
    }
    else
    {
        if( !pkt->ptrs.ip_api.get_src()->equals(config->mod_config->session_log_filter.sip) )
            return;

        if( !pkt->ptrs.ip_api.get_dst()->equals(config->mod_config->session_log_filter.dip) )
                return;

        if( !( pkt->ptrs.dp == config->mod_config->session_log_filter.dport ) )
            return;

        if( !( pkt->ptrs.dp == config->mod_config->session_log_filter.dport ) )
            return;

        if( !( pkt->ptrs.type == config->mod_config->session_log_filter.protocol ) )
            return;

        session_logging_enabled = true;
    }

    if(session_logging_enabled)
        snprintf(session_logging_id, MAX_SESSION_LOGGING_ID_LEN, "%s-%hu -> %s-%hu %u%s AS %u I %u",
            pkt->ptrs.ip_api.get_src()->ntoa(), pkt->ptrs.sp,
            pkt->ptrs.ip_api.get_dst()->ntoa(), pkt->ptrs.dp,
            (unsigned)pkt->ptrs.type, (direction == APP_ID_FROM_INITIATOR) ? "" : " R",
            (unsigned)pkt->pkth->address_space_id, get_instance_id());

    return;
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
    config = AppIdConfig::get_appid_config();
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
	if( !in_expected_cache)
	{
	    update_appid_statistics(this);
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

AppIdSession* AppIdSession::create_future_session(const Packet* ctrlPkt, const SfIp* cliIp, uint16_t cliPort,
    const SfIp* srvIp, uint16_t srvPort, IpProtocol proto, int16_t app_id, int /*flags*/)
{
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    // FIXIT-M not needed  until crtlPkt expectedSession is supported
    //struct _ExpectNode** node;
    enum PktType type = get_pkt_type_from_ip_proto(proto);

    assert(type != PktType::NONE);

    // FIXIT-M - port parameter passed in as 0 since we may not know client port, verify this is correct
    AppIdSession* asd = new AppIdSession(proto, cliIp, 0);
    asd->common.policyId = appIdPolicyId;

    // FIXIT-M expect session control packet support not ported to snort3 yet
    //node = (flags & APPID_EARLY_SESSION_FLAG_FW_RULE) ? &ctrlPkt->expectedSession : nullptr;

    // FIXIT-M 2.9.x set_application_protocol_id_expected has several new parameters, need to look
    // into what is required to support those here.
    if ( Stream::set_application_protocol_id_expected(ctrlPkt, type, proto, cliIp, cliPort, srvIp, srvPort,
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
        rnaServiceState = RNA_STATE_NONE;
        serviceData = nullptr;
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

int AppIdSession::exec_client_detectors(Packet* p, int direction)
{
    int ret = CLIENT_APP_INPROCESS;

    if (rna_client_data != nullptr)
    {
        ret = rna_client_data->validate(p->data, p->dsize, direction, this, p,
            rna_client_data->userData);
        if (session_logging_enabled)
            LogMessage("AppIdDbg %s %s client detector returned %d\n", session_logging_id,
                rna_client_data->name ? rna_client_data->name : "UNKNOWN", ret);
    }
    else if (    (candidate_client_list != nullptr)
        && (sflist_count(candidate_client_list) > 0) )
    {
        SF_LNODE* node;
        RNAClientAppModule* client;

        ret = CLIENT_APP_INPROCESS;
        (void)sflist_first(candidate_client_list, &node);
        while (node != nullptr)
        {
            int result;
            SF_LNODE* node_tmp;

            client = (RNAClientAppModule*)node->ndata;
            result = client->validate(p->data, p->dsize, direction, this, p, client->userData);
            if (session_logging_enabled)
                LogMessage("AppIdDbg %s %s client detector returned %d\n", session_logging_id,
                    client->name ? client->name : "UNKNOWN", result);

            node_tmp = node;
            sflist_next(&node);
            if (result == CLIENT_APP_SUCCESS)
            {
                ret = CLIENT_APP_SUCCESS;
                rna_client_data = client;
                sflist_free(candidate_client_list);
                candidate_client_list = nullptr;
                break;    /* done */
            }
            else if (result != CLIENT_APP_INPROCESS)    /* fail */
            {
                sflist_remove_node(candidate_client_list, node_tmp);
            }
        }
    }

    return ret;
}

bool AppIdSession::is_packet_ignored(Packet* p)
{
    if(!p->flow)
    {
        appid_stats.ignored_packets++;
        return true;
    }
    AppIdSession* asd = appid_api.get_appid_data(p->flow);

// FIXIT-M - Need to convert this _dpd stream api call to the correct snort++ method
#ifdef REMOVED_WHILE_NOT_IN_USE
    bool is_http2     = false; // _dpd.streamAPI->is_session_http2(p->flow);
#else
    bool is_http2     = false;
#endif
    if (is_http2)
    {
        if (asd)
            asd->is_http2 = true;
        if ( !p->is_rebuilt() )
        {
            // For HTTP/2, we only want to look at the ones that are rebuilt from
            // Stream / HTTP Inspect as HTTP/1 packets.
            appid_stats.ignored_packets++;
            return true;
        }
    }
    else    // not HTTP/2
    {
        if ( p->is_rebuilt() && !p->flow->is_proxied() )
        {
            // FIXIT-M - latest 2.9 checks direction in this if statement below:
            //             ( (direction == APP_ID_FROM_INITIATOR) &&... ) do we need to add this?
            if (asd && asd->hsession && asd->hsession->get_offsets_from_rebuilt)
            {
                httpGetNewOffsetsFromPacket(p, asd->hsession);
                if (asd->session_logging_enabled)
                    LogMessage(
                        "AppIdDbg %s offsets from rebuilt packet: uri: %u-%u cookie: %u-%u\n",
                        asd->session_logging_id,
                        asd->hsession->fieldOffset[REQ_URI_FID], asd->hsession->fieldEndOffset[REQ_URI_FID],
                        asd->hsession->fieldOffset[REQ_COOKIE_FID], asd->hsession->fieldEndOffset[REQ_COOKIE_FID]);
            }
            appid_stats.ignored_packets++;
            return true;
        }
    }

    return false;
}

#ifdef REMOVED_WHILE_NOT_IN_USE
static inline bool checkThirdPartyReinspect(const Packet* p, AppIdSession* asd)
{
    return p->dsize && !asd->get_session_flags(APPID_SESSION_NO_TPI) &&
                    asd->get_session_flags(APPID_SESSION_HTTP_SESSION) && TPIsAppIdDone(asd->tpsession);
}

#else
static inline bool checkThirdPartyReinspect(const Packet*, AppIdSession*)
{
    return false;
}
#endif

#ifdef REMOVED_WHILE_NOT_IN_USE
void AppIdSession::ProcessThirdPartyResults(Packet* p, int confidence,
        AppId* proto_list, ThirdPartyAppIDAttributeData* attribute_data)
{
    int size;
    AppId serviceAppId = 0;
    AppId client_app_id = 0;
    AppId payload_app_id = 0;
    AppId referred_payload_app_id = 0;

    if (ThirdPartyAppIDFoundProto(APP_ID_EXCHANGE, proto_list))
    {
        if (!payload_app_id)
            payload_app_id = APP_ID_EXCHANGE;
    }

    if (ThirdPartyAppIDFoundProto(APP_ID_HTTP, proto_list))
    {
        if (session_logging_enabled)
            LogMessage("AppIdDbg %s flow is HTTP\n", session_logging_id);
        set_session_flags(APPID_SESSION_HTTP_SESSION);
    }
    if (ThirdPartyAppIDFoundProto(APP_ID_SPDY, proto_list))
    {
        if (session_logging_enabled)
            LogMessage("AppIdDbg %s flow is SPDY\n", session_logging_id);

        set_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_SPDY_SESSION);
    }

    if (get_session_flags(APPID_SESSION_HTTP_SESSION))
    {
        if (!hsession)
        {
            hsession = (httpSession*)snort_calloc(sizeof(httpSession));
            memset(hsession->ptype_scan_counts, 0,
                NUMBER_OF_PTYPES * sizeof(hsession->ptype_scan_counts[0]));
        }

        if (get_session_flags(APPID_SESSION_SPDY_SESSION))
        {
            if (attribute_data->spdyRequestScheme &&
                attribute_data->spdyRequestHost &&
                attribute_data->spdyRequestPath)
            {
                static const char httpsScheme[] = "https";
                static const char httpScheme[] = "http";
                const char* scheme;

                if (hsession->url)
                {
                    snort_free(hsession->url);
                    hsession->chp_finished = 0;
                }
                if (get_session_flags(APPID_SESSION_DECRYPTED)
                    && memcmp(attribute_data->spdyRequestScheme, httpScheme, sizeof(httpScheme)-
                    1) == 0)
                {
                    scheme = httpsScheme;
                }
                else
                {
                    scheme = attribute_data->spdyRequestScheme;
                }

                size = strlen(scheme) +
                    strlen(attribute_data->spdyRequestHost) +
                    strlen(attribute_data->spdyRequestPath) +
                    sizeof("://");    // see sprintf() format
                hsession->url = (char*)snort_calloc(size);
                sprintf(hsession->url, "%s://%s%s",
                    scheme, attribute_data->spdyRequestHost, attribute_data->spdyRequestPath);
                scan_flags |= SCAN_HTTP_HOST_URL_FLAG;

                snort_free(attribute_data->spdyRequestScheme);
                attribute_data->spdyRequestScheme = nullptr;
            }
            else if (attribute_data->spdyRequestScheme)
            {
                snort_free(attribute_data->spdyRequestScheme);
                attribute_data->spdyRequestScheme = nullptr;
            }

            if (attribute_data->spdyRequestHost)
            {
                if (hsession->host)
                {
                    snort_free(hsession->host);
                    hsession->chp_finished = 0;
                }
                hsession->host = attribute_data->spdyRequestHost;
                attribute_data->spdyRequestHost = nullptr;
                hsession->fieldOffset[REQ_HOST_FID] = attribute_data->spdyRequestHostOffset;
                hsession->fieldEndOffset[REQ_HOST_FID] = attribute_data->spdyRequestHostEndOffset;
                if(session_logging_enabled)
                    LogMessage("AppIdDbg %s SPDY Host (%u-%u) is %s\n", session_logging_id,
                                hsession->fieldOffset[REQ_HOST_FID], hsession->fieldEndOffset[REQ_HOST_FID], hsession->host);
                scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }

            if (attribute_data->spdyRequestPath)
            {
                if (hsession->uri)
                {
                    free(hsession->uri);
                    hsession->chp_finished = 0;
                }
                hsession->uri = attribute_data->spdyRequestPath;
                attribute_data->spdyRequestPath = nullptr;
                hsession->fieldOffset[REQ_URI_FID] = attribute_data->spdyRequestPathOffset;
                hsession->fieldEndOffset[REQ_URI_FID] = attribute_data->spdyRequestPathEndOffset;
                if(session_logging_enabled)
                    LogMessage("AppIdDbg %s SPDY URI (%u-%u) is %s\n", session_logging_id,
                                hsession->fieldOffset[REQ_URI_FID], hsession->fieldEndOffset[REQ_URI_FID], hsession->uri);
            }
        }
        else
        {
            if (attribute_data->httpRequestHost)
            {
                if (hsession->host)
                {
                    snort_free(hsession->host);
                    if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                        hsession->chp_finished = 0;
                }
                hsession->host = attribute_data->httpRequestHost;
                hsession->host_buflen = attribute_data->httpRequestHostLen;
                hsession->fieldOffset[REQ_HOST_FID] = attribute_data->httpRequestHostOffset;
                hsession->fieldEndOffset[REQ_HOST_FID] = attribute_data->httpRequestHostEndOffset;
                attribute_data->httpRequestHost = nullptr;
                if (session_logging_enabled)
                    LogMessage("AppIdDbg %s HTTP host is %s\n",
                               session_logging_id, attribute_data->httpRequestHost);
                scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
            if (attribute_data->httpRequestUrl)
            {
                static const char httpScheme[] = "http://";

                if (hsession->url)
                {
                    snort_free(hsession->url);
                    if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                        hsession->chp_finished = 0;
                }

                //change http to https if session was decrypted.
                if (get_session_flags(APPID_SESSION_DECRYPTED)
                    &&
                    memcmp(attribute_data->httpRequestUrl, httpScheme, sizeof(httpScheme)-1) == 0)
                {
                    hsession->url = (char*)snort_calloc(strlen(attribute_data->httpRequestUrl) + 2);

                    if (hsession->url)
                        sprintf(hsession->url, "https://%s",
                            attribute_data->httpRequestUrl + sizeof(httpScheme)-1);

                    snort_free(attribute_data->httpRequestUrl);
                    attribute_data->httpRequestUrl = nullptr;
                }
                else
                {
                    hsession->url = attribute_data->httpRequestUrl;
                    attribute_data->httpRequestUrl = nullptr;
                }

                scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
            if (attribute_data->httpRequestUri)
            {
                if (hsession->uri)
                {
                    snort_free(hsession->uri);
                    if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                        hsession->chp_finished = 0;
                }
                hsession->uri = attribute_data->httpRequestUri;
                hsession->uri_buflen = attribute_data->httpRequestUriLen;
                hsession->fieldOffset[REQ_URI_FID] = attribute_data->httpRequestUriOffset;
                hsession->fieldEndOffset[REQ_URI_FID] = attribute_data->httpRequestUriEndOffset;
                attribute_data->httpRequestUri = nullptr;
                if (session_logging_enabled)
                    LogMessage("AppIdDbg %s uri (%u-%u) is %s\n", session_logging_id,
                               hsession->fieldOffset[REQ_URI_FID], hsession->fieldEndOffset[REQ_URI_FID],
                               hsession->uri);
            }
        }
        if (attribute_data->httpRequestVia)
        {
            if (hsession->via)
            {
                snort_free(hsession->via);
                if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->chp_finished = 0;
            }
            hsession->via = attribute_data->httpRequestVia;
            attribute_data->httpRequestVia = nullptr;
            scan_flags |= SCAN_HTTP_VIA_FLAG;
        }
        else if (attribute_data->httpResponseVia)
        {
            if (hsession->via)
            {
                snort_free(hsession->via);
                if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->chp_finished = 0;
            }
            hsession->via = attribute_data->httpResponseVia;
            attribute_data->httpResponseVia = nullptr;
            scan_flags |= SCAN_HTTP_VIA_FLAG;
        }
        if (attribute_data->httpRequestUserAgent)
        {
            if (hsession->useragent)
            {
                snort_free(hsession->useragent);
                if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->chp_finished = 0;
            }
            hsession->useragent = attribute_data->httpRequestUserAgent;
            attribute_data->httpRequestUserAgent = nullptr;
            scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
        }
        // Check to see if third party discovered HTTP/2.
        //  - once it supports it...
        if (attribute_data->httpResponseVersion)
        {
            if (session_logging_enabled)
                LogMessage("AppIdDbg %s HTTP response version is %s\n", session_logging_id,
                    attribute_data->httpResponseVersion);
            if (strncmp(attribute_data->httpResponseVersion, "HTTP/2", 6) == 0)
            {
                if (session_logging_enabled)
                    LogMessage("AppIdDbg %s 3rd party detected and parsed HTTP/2\n",
                        session_logging_id);
                is_http2 = true;
            }
            snort_free(attribute_data->httpResponseVersion);
            attribute_data->httpResponseVersion = nullptr;
        }
        if (attribute_data->httpResponseCode)
        {
            if (session_logging_enabled)
                LogMessage("AppIdDbg %s HTTP response code is %s\n", session_logging_id,
                    attribute_data->httpResponseCode);
            if (hsession->response_code)
            {
                snort_free(hsession->response_code);
                if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->chp_finished = 0;
            }
            hsession->response_code = attribute_data->httpResponseCode;
            hsession->response_code_buflen = attribute_data->httpResponseCodeLen;
            attribute_data->httpResponseCode = nullptr;
        }
        // Check to see if we've got an upgrade to HTTP/2 (if enabled).
        //  - This covers the "without prior knowledge" case (i.e., the client
        //    asks the server to upgrade to HTTP/2).
        if (attribute_data->httpResponseUpgrade)
        {
            if (session_logging_enabled)
                LogMessage("AppIdDbg %s HTTP response upgrade is %s\n", session_logging_id,
                    attribute_data->httpResponseUpgrade);
            if (config->mod_config->http2_detection_enabled)
                if (hsession->response_code && (strncmp(
                    hsession->response_code, "101", 3) == 0))
                    if (strncmp(attribute_data->httpResponseUpgrade, "h2c", 3) == 0)
                    {
                        if (session_logging_enabled)
                            LogMessage("AppIdDbg %s Got an upgrade to HTTP/2\n",
                                session_logging_id);
                        is_http2 = true;
                    }
            snort_free(attribute_data->httpResponseUpgrade);
            attribute_data->httpResponseUpgrade = nullptr;
        }
        if (attribute_data->httpRequestReferer)
        {
            if (session_logging_enabled)
                LogMessage("AppIdDbg %s referrer is %s\n", session_logging_id,
                    attribute_data->httpRequestReferer);
            if (hsession->referer)
            {
                snort_free(hsession->referer);
                if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->chp_finished = 0;
            }
            hsession->referer = attribute_data->httpRequestReferer;
            hsession->referer_buflen = attribute_data->httpRequestRefererLen;
            attribute_data->httpRequestReferer = nullptr;
            hsession->fieldOffset[REQ_REFERER_FID] = attribute_data->httpRequestRefererOffset;
            hsession->fieldEndOffset[REQ_REFERER_FID] = attribute_data->httpRequestRefererEndOffset;
            if (session_logging_enabled)
                LogMessage("AppIdDbg %s Referer (%u-%u) is %s\n", session_logging_id,
                             hsession->fieldOffset[REQ_REFERER_FID], hsession->fieldEndOffset[REQ_REFERER_FID],
                             hsession->referer);
        }

        if (attribute_data->httpRequestCookie)
        {
            if (hsession->cookie)
            {
                snort_free(hsession->cookie);
                if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->chp_finished = 0;
            }
            hsession->cookie = attribute_data->httpRequestCookie;
            hsession->cookie_buflen = attribute_data->httpRequestCookieLen;
            hsession->fieldOffset[REQ_COOKIE_FID] = attribute_data->httpRequestCookieOffset;
            hsession->fieldEndOffset[REQ_COOKIE_FID] = attribute_data->httpRequestCookieEndOffset;
            attribute_data->httpRequestCookie = nullptr;
            attribute_data->httpRequestCookieOffset = 0;
            attribute_data->httpRequestCookieEndOffset = 0;
            if (session_logging_enabled)
                LogMessage("AppIdDbg %s cookie (%u-%u) is %s\n", session_logging_id,
                           hsession->fieldOffset[REQ_COOKIE_FID], hsession->fieldEndOffset[REQ_COOKIE_FID],
                           hsession->cookie);
        }
        if (attribute_data->httpResponseContent)
        {
            if (hsession->content_type)
            {
                snort_free(hsession->content_type);
                if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->chp_finished = 0;
            }
            hsession->content_type = attribute_data->httpResponseContent;
            hsession->content_type_buflen = attribute_data->httpResponseContentLen;
            attribute_data->httpResponseContent = nullptr;
            scan_flags |= SCAN_HTTP_CONTENT_TYPE_FLAG;
        }
        if (hsession->ptype_scan_counts[LOCATION_PT] && attribute_data->httpResponseLocation)
        {
            if (hsession->location)
            {
                snort_free(hsession->location);
                if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->chp_finished = 0;
            }
            hsession->location = attribute_data->httpResponseLocation;
            hsession->location_buflen = attribute_data->httpResponseLocationLen;
            attribute_data->httpResponseLocation = nullptr;
        }
        if (attribute_data->httpRequestBody)
        {
            if (session_logging_enabled)
                LogMessage("AppIdDbg %s got a request body %s\n", session_logging_id,
                    attribute_data->httpRequestBody);
            if (hsession->req_body)
            {
                snort_free(hsession->req_body);
                if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->chp_finished = 0;
            }
            hsession->req_body = attribute_data->httpRequestBody;
            hsession->req_body_buflen = attribute_data->httpRequestBodyLen;
            attribute_data->httpRequestBody = nullptr;
        }
        if (hsession->ptype_scan_counts[BODY_PT] && attribute_data->httpResponseBody)
        {
            if (hsession->body)
            {
                snort_free(hsession->body);
                if (!get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->chp_finished = 0;
            }
            hsession->body = attribute_data->httpResponseBody;
            hsession->body_buflen = attribute_data->httpResponseBodyLen;
            attribute_data->httpResponseBody = nullptr;
        }
        if (attribute_data->numXffFields)
        {
            pickHttpXffAddress(p, attribute_data);
        }
        if (!hsession->chp_finished || hsession->chp_hold_flow)
        {
            set_session_flags(APPID_SESSION_CHP_INSPECTING);
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_attr_set(tpsession,
                    TP_ATTR_CONTINUE_MONITORING);
        }
        if (attribute_data->httpResponseServer)
        {
            if (hsession->server)
                snort_free(hsession->server);
            hsession->server = attribute_data->httpResponseServer;
            attribute_data->httpResponseServer = nullptr;
            scan_flags |= SCAN_HTTP_VENDOR_FLAG;
        }
        if (attribute_data->httpRequestXWorkingWith)
        {
            if (hsession->x_working_with)
                snort_free(hsession->x_working_with);
            hsession->x_working_with = attribute_data->httpRequestXWorkingWith;
            attribute_data->httpRequestXWorkingWith = nullptr;
            scan_flags |= SCAN_HTTP_XWORKINGWITH_FLAG;
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_RTMP, proto_list) ||
        ThirdPartyAppIDFoundProto(APP_ID_RTSP, proto_list))
    {
        if (!hsession)
            hsession = (httpSession*)snort_calloc(sizeof(httpSession));

        if (!hsession->url)
        {
            if (attribute_data->httpRequestUrl)
            {
                hsession->url = attribute_data->httpRequestUrl;
                attribute_data->httpRequestUrl = nullptr;
                scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
        }

        if (!config->mod_config->referred_appId_disabled &&
            !hsession->referer)
        {
            if (attribute_data->httpRequestReferer)
            {
                hsession->referer = attribute_data->httpRequestReferer;
                attribute_data->httpRequestReferer = nullptr;
            }
        }

        if (hsession->url || (confidence == 100 &&
            session_packet_count > config->mod_config->rtmp_max_packets))
        {
            if (hsession->url)
            {
                if (((get_appid_from_url(nullptr, hsession->url, nullptr,
                    hsession->referer, &client_app_id, &serviceAppId,
                    &payload_app_id, &referred_payload_app_id, 1)) ||
                    (get_appid_from_url(nullptr, hsession->url, nullptr,
                    hsession->referer, &client_app_id, &serviceAppId,
                    &payload_app_id, &referred_payload_app_id, 0))) == 1)
                {
                    // do not overwrite a previously-set client or service
                    if (client_app_id <= APP_ID_NONE)
                        set_client_app_id_data(client_app_id, nullptr);
                    if (serviceAppId <= APP_ID_NONE)
                        set_service_appid_data(serviceAppId, nullptr, nullptr);

                    // DO overwrite a previously-set data
                    set_payload_app_id_data((ApplicationId)payload_app_id, nullptr);
                    set_referred_payload_app_id_data(referred_payload_app_id);
                }
            }

            if (thirdparty_appid_module)
            {
                thirdparty_appid_module->disable_flags(tpsession,
                    TP_SESSION_FLAG_ATTRIBUTE | TP_SESSION_FLAG_TUNNELING |
                    TP_SESSION_FLAG_FUTUREFLOW);
                thirdparty_appid_module->session_delete(tpsession, 1);
            }
            tpsession = nullptr;
            clear_session_flags(APPID_SESSION_APP_REINSPECT);
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_SSL, proto_list))
    {
        AppId tmpAppId = APP_ID_NONE;

        if (thirdparty_appid_module && tpsession)
            tmpAppId = thirdparty_appid_module->session_appid_get(tpsession);

        set_session_flags(APPID_SESSION_SSL_SESSION);

        if (!tsession)
            tsession = (tlsSession*)snort_calloc(sizeof(tlsSession));

        if (!client_app_id)
            set_client_app_id_data(APP_ID_SSL_CLIENT, nullptr);

        if (attribute_data->tlsHost)
        {
            if (tsession->tls_host)
                snort_free(tsession->tls_host);
            tsession->tls_host = attribute_data->tlsHost;
            attribute_data->tlsHost = nullptr;
            if (testSSLAppIdForReinspect(tmpAppId))
                scan_flags |= SCAN_SSL_HOST_FLAG;
        }
        if (testSSLAppIdForReinspect(tmpAppId))
        {
            if (attribute_data->tlsCname)
            {
                if (tsession->tls_cname)
                    snort_free(tsession->tls_cname);
                tsession->tls_cname = attribute_data->tlsCname;
                attribute_data->tlsCname = nullptr;
            }
            if (attribute_data->tlsOrgUnit)
            {
                if (tsession->tls_orgUnit)
                    snort_free(tsession->tls_orgUnit);
                tsession->tls_orgUnit = attribute_data->tlsOrgUnit;
                attribute_data->tlsOrgUnit = nullptr;
            }
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_FTP_CONTROL, proto_list))
    {
        if (!config->mod_config->ftp_userid_disabled && attribute_data->ftpCommandUser)
        {
            if (username)
                snort_free(username);
            username = attribute_data->ftpCommandUser;
            attribute_data->ftpCommandUser = nullptr;
            username_service = APP_ID_FTP_CONTROL;
            set_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
        }
    }
}

void AppIdSession::checkTerminateTpModule(uint16_t tpPktCount)
{
    if ((tpPktCount >= config->mod_config->max_tp_flow_depth) ||
        (get_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT) ==
        (APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT) &&
        hsession && hsession->uri && (!hsession->chp_candidate || hsession->chp_finished)))
    {
        if (tp_app_id == APP_ID_NONE)
            tp_app_id = APP_ID_UNKNOWN;
        if (payload_app_id == APP_ID_NONE)
            payload_app_id = APP_ID_UNKNOWN;
        if (thirdparty_appid_module)
            thirdparty_appid_module->session_delete(tpsession, 1);
    }
}

bool AppIdSession::do_third_party_discovery(IpProtocol protocol, const SfIp* ip,
        Packet* p, int& direction)
{
    ThirdPartyAppIDAttributeData* tp_attribute_data;
    AppId* tp_proto_list;
    int tp_confidence;
    bool isTpAppidDiscoveryDone = false;

    /*** Start of third-party processing. ***/
    if (thirdparty_appid_module && !get_session_flags(APPID_SESSION_NO_TPI)
            && (!TPIsAppIdDone(tpsession)
                    || get_session_flags(APPID_SESSION_APP_REINSPECT | APPID_SESSION_APP_REINSPECT_SSL)))
    {
        // First SSL decrypted packet is now being inspected. Reset the flag so that SSL decrypted
        // traffic
        // gets processed like regular traffic from next packet onwards
        if (get_session_flags(APPID_SESSION_APP_REINSPECT_SSL))
            clear_session_flags(APPID_SESSION_APP_REINSPECT_SSL);

        if (p->dsize || config->mod_config->tp_allow_probes)
        {
            if (protocol != IpProtocol::TCP || (p->packet_flags & PKT_STREAM_ORDER_OK)
                            || config->mod_config->tp_allow_probes)
            {

                Profile tpLibPerfStats_profile_context(tpLibPerfStats);
                if (!tpsession)
                {
                    if (!(tpsession = thirdparty_appid_module->session_create()))
                        FatalError("Could not allocate tpsession data");
                }; // debug output of packet content
                thirdparty_appid_module->session_process(tpsession, p, direction, &tp_app_id, &tp_confidence,
                                                         &tp_proto_list, &tp_attribute_data);

                isTpAppidDiscoveryDone = true;
                if (thirdparty_appid_module->session_state_get(tpsession) == TP_STATE_CLASSIFIED)
                    clear_session_flags(APPID_SESSION_APP_REINSPECT);

                if (session_logging_enabled)
                    LogMessage("AppIdDbg %s 3rd party returned %d\n", session_logging_id, tp_app_id);

                // For now, third party can detect HTTP/2 (w/o metadata) for
                // some cases.  Treat it like HTTP w/ is_http2 flag set.
                if ((tp_app_id == APP_ID_HTTP2) && (tp_confidence == 100))
                {
                    if (session_logging_enabled)
                        LogMessage("AppIdDbg %s 3rd party saw HTTP/2\n", session_logging_id);

                    tp_app_id = APP_ID_HTTP;
                    is_http2 = true;
                }
                // if the third-party appId must be treated as a client, do it now
                if (app_info_mgr->get_app_info_flags(tp_app_id, APPINFO_FLAG_TP_CLIENT))
                    client_app_id = tp_app_id;

                ProcessThirdPartyResults(p, tp_confidence, tp_proto_list, tp_attribute_data);

                if (get_session_flags(APPID_SESSION_SSL_SESSION) &&
                                !(scan_flags & SCAN_SSL_HOST_FLAG))
                {
                    setSSLSquelch(p, 1, tp_app_id);
                }

                if (app_info_mgr->get_app_info_flags(tp_app_id, APPINFO_FLAG_IGNORE))
                {
                    if (session_logging_enabled)
                        LogMessage("AppIdDbg %s 3rd party ignored\n", session_logging_id);

                    if (get_session_flags(APPID_SESSION_HTTP_SESSION))
                        tp_app_id = APP_ID_HTTP;
                    else
                        tp_app_id = APP_ID_NONE;
                }
            }
            else
            {
                tp_app_id = APP_ID_NONE;
                if (session_logging_enabled && !get_session_flags(APPID_SESSION_TPI_OOO_LOGGED))
                {
                    set_session_flags(APPID_SESSION_TPI_OOO_LOGGED);
                    LogMessage("AppIdDbg %s 3rd party packet out-of-order\n", session_logging_id);
                }
            }

            if (thirdparty_appid_module->session_state_get(tpsession) == TP_STATE_MONITORING)
            {
                thirdparty_appid_module->disable_flags(tpsession,
                        TP_SESSION_FLAG_ATTRIBUTE | TP_SESSION_FLAG_TUNNELING | TP_SESSION_FLAG_FUTUREFLOW);
            }

            if (tp_app_id == APP_ID_SSL &&
                (Stream::get_application_protocol_id(p->flow) == snortId_for_ftp_data))
            {
                //  If we see SSL on an FTP data channel set tpAppId back
                //  to APP_ID_NONE so the FTP preprocessor picks up the flow.
                tp_app_id = APP_ID_NONE;
            }

            if (tp_app_id > APP_ID_NONE
                    && (!get_session_flags(APPID_SESSION_APP_REINSPECT) || payload_app_id > APP_ID_NONE))
            {
                AppId snort_app_id;
                // if the packet is HTTP, then search for via pattern
                if (get_session_flags(APPID_SESSION_HTTP_SESSION) && hsession)
                {
                    snort_app_id = APP_ID_HTTP;
                    //data should never be APP_ID_HTTP
                    if (tp_app_id != APP_ID_HTTP)
                        tp_payload_app_id = tp_app_id;

                    tp_app_id = APP_ID_HTTP;
                    // Handle HTTP tunneling and SSL possibly then being used in that tunnel
                    if (tp_app_id == APP_ID_HTTP_TUNNEL)
                        set_payload_app_id_data(APP_ID_HTTP_TUNNEL, NULL);
                    if ((payload_app_id == APP_ID_HTTP_TUNNEL) && (tp_app_id == APP_ID_SSL))
                        set_payload_app_id_data(APP_ID_HTTP_SSL_TUNNEL, NULL);

                    process_http_packet(p, direction, nullptr);

                    // If SSL over HTTP tunnel, make sure Snort knows that it's encrypted.
                    if (payload_app_id == APP_ID_HTTP_SSL_TUNNEL)
                        snort_app_id = APP_ID_SSL;

                    if (is_third_party_appid_available(tpsession) && tp_app_id == APP_ID_HTTP
                            && !get_session_flags(APPID_SESSION_APP_REINSPECT))
                    {
                        rna_client_state = RNA_STATE_FINISHED;
                        set_session_flags(APPID_SESSION_CLIENT_DETECTED | APPID_SESSION_SERVICE_DETECTED);
                        rnaServiceState = RNA_STATE_FINISHED;
                        clear_session_flags(APPID_SESSION_CONTINUE);
                        if (direction == APP_ID_FROM_INITIATOR)
                        {
                            ip = p->ptrs.ip_api.get_dst();
                            service_ip = *ip;
                            service_port = p->ptrs.dp;
                        }
                        else
                        {
                            ip = p->ptrs.ip_api.get_src();
                            service_ip = *ip;
                            service_port = p->ptrs.sp;
                        }
                    }
                }
                else if (get_session_flags(APPID_SESSION_SSL_SESSION) && tsession)
                {
                    examine_ssl_metadata(p);
                    uint16_t serverPort;
                    AppId porAppId;
                    serverPort = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.dp : p->ptrs.sp;
                    porAppId = serverPort;
                    if (tp_app_id == APP_ID_SSL)
                    {
                        tp_app_id = porAppId;
                        //SSL policy determines IMAPS/POP3S etc before appId sees first server packet
                        portServiceAppId = porAppId;
                        if (session_logging_enabled)
                            LogMessage("AppIdDbg %s SSL is service %d, portServiceAppId %d\n", session_logging_id,
                                    tp_app_id, portServiceAppId);
                    }
                    else
                    {
                        tp_payload_app_id = tp_app_id;
                        tp_app_id = porAppId;
                        if (session_logging_enabled)
                            LogMessage("AppIdDbg %s SSL is %d\n", session_logging_id, tp_app_id);
                    }
                    snort_app_id = APP_ID_SSL;
                }
                else
                {
                    //for non-http protocols, tp id is treated like serviceId
                    snort_app_id = tp_app_id;
                }

                sync_with_snort_id(snort_app_id, p);
            }
            else
            {
                if (protocol != IpProtocol::TCP ||
                                (p->packet_flags & (PKT_STREAM_ORDER_OK | PKT_STREAM_ORDER_BAD)))
                {
                    if (direction == APP_ID_FROM_INITIATOR)
                    {
                        init_tpPackets++;
                        checkTerminateTpModule(init_tpPackets);
                    }
                    else
                    {
                        resp_tpPackets++;
                        checkTerminateTpModule(resp_tpPackets);
                    }
                }
            }
        }
    }

    return isTpAppidDiscoveryDone;
}

void AppIdSession::pickHttpXffAddress(Packet*, ThirdPartyAppIDAttributeData* attribute_data)
{
    int i;
    static const char* defaultXffPrecedence[] =
    {
        HTTP_XFF_FIELD_X_FORWARDED_FOR,
        HTTP_XFF_FIELD_TRUE_CLIENT_IP
    };

    // XFF precedence configuration cannot change for a session. Do not get it again if we already
    // got it.
// FIXIT-M:
#ifdef REMOVED_WHILE_NOT_IN_USE
    if (!hsession->xffPrecedence)
        hsession->xffPrecedence = _dpd.sessionAPI->get_http_xff_precedence(
            p->flow, p->packet_flags, &hsession->numXffFields);
#endif

    if (!hsession->xffPrecedence)
    {
        hsession->xffPrecedence = defaultXffPrecedence;
        hsession->numXffFields = sizeof(defaultXffPrecedence) /
            sizeof(defaultXffPrecedence[0]);
    }

    if (session_logging_enabled)
    {
        for (i = 0; i < attribute_data->numXffFields; i++)
            LogMessage("AppIdDbg %s %s : %s\n", app_id_debug_session,
                attribute_data->xffFieldValue[i].field, attribute_data->xffFieldValue[i].value);
    }

    // xffPrecedence array is sorted based on precedence
    for (i = 0; (i < hsession->numXffFields) &&
        hsession->xffPrecedence[i]; i++)
    {
        int j;
        for (j = 0; j < attribute_data->numXffFields; j++)
        {
            if (hsession->xffAddr)
            {
                delete hsession->xffAddr;
                hsession->xffAddr = nullptr;
            }

            if (strncasecmp(attribute_data->xffFieldValue[j].field,
                hsession->xffPrecedence[i], UINT8_MAX) == 0)
            {
                char* tmp = strchr(attribute_data->xffFieldValue[j].value, ',');

                // For a comma-separated list of addresses, pick the first address
                if (tmp)
                    attribute_data->xffFieldValue[j].value[tmp -
                        attribute_data->xffFieldValue[j].value] = '\0';
                hsession->xffAddr = new SfIp();
                if (hsession->xffAddr->set(attribute_data->xffFieldValue[j].value) != SFIP_SUCCESS)
                {
                    delete hsession->xffAddr;
                    hsession->xffAddr = nullptr;
                }
                break;
            }
        }
        if (hsession->xffAddr)
            break;
    }
}

#endif

bool AppIdSession::do_service_discovery(IpProtocol protocol, int direction, AppId client_app_id,
        AppId payload_app_id, Packet* p)
{
    AppInfoTableEntry* entry = nullptr;
    bool isTpAppidDiscoveryDone = false;

    if (rnaServiceState != RNA_STATE_FINISHED)
    {
        Profile serviceMatchPerfStats_profile_context(serviceMatchPerfStats);
        uint32_t prevRnaServiceState = rnaServiceState;
        //decision to directly call validator or go through elaborate service_state tracking
        //is made once at the beginning of sesssion.
        if (rnaServiceState == RNA_STATE_NONE && p->dsize)
        {
            if (p->flow->get_session_flags() & SSNFLAG_MIDSTREAM)
            {
                // Unless it could be ftp control
                if (protocol == IpProtocol::TCP && (p->ptrs.sp == 21 || p->ptrs.dp == 21)
                        && !(p->ptrs.tcph->is_fin() || p->ptrs.tcph->is_rst()))
                {
                    set_session_flags(APPID_SESSION_CLIENT_DETECTED | APPID_SESSION_NOT_A_SERVICE
                            | APPID_SESSION_SERVICE_DETECTED);
                    if (!AddFTPServiceState(this))
                    {
                        set_session_flags(APPID_SESSION_CONTINUE);
                        if (p->ptrs.dp != 21)
                            set_session_flags(APPID_SESSION_RESPONDER_SEEN);
                    }
                    rnaServiceState = RNA_STATE_STATEFUL;
                }
                else
                {
                    set_session_flags(APPID_SESSION_MID | APPID_SESSION_SERVICE_DETECTED);
                    rnaServiceState = RNA_STATE_FINISHED;
                }
            }
            else if (is_third_party_appid_available(tpsession))
            {
                if (tp_app_id > APP_ID_NONE)
                {
                    //tp has positively identified appId, Dig deeper only if sourcefire
                    // detector identifies additional information or flow is UDP reveresed.
                    if ((entry = app_info_mgr->get_app_info_entry(tp_app_id)) && entry->svrValidator
                            && ((entry->flags & APPINFO_FLAG_SERVICE_ADDITIONAL)
                                    || ((entry->flags & APPINFO_FLAG_SERVICE_UDP_REVERSED)
                                            && protocol == IpProtocol::UDP
                                            && get_session_flags(
                                                    APPID_SESSION_INITIATOR_MONITORED
                                                            | APPID_SESSION_RESPONDER_MONITORED))))
                    {
                        free_flow_data_by_mask(APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);
                        serviceData = entry->svrValidator;
                        rnaServiceState = RNA_STATE_STATEFUL;
                    }
                    else
                        stop_rna_service_inspection(p, direction);
                }
                else
                    rnaServiceState = RNA_STATE_STATEFUL;
            }
            else
                rnaServiceState = RNA_STATE_STATEFUL;
        }
        //stop rna inspection as soon as tp has classified a valid AppId later in the session
        if (rnaServiceState == RNA_STATE_STATEFUL&&
        prevRnaServiceState == RNA_STATE_STATEFUL &&
        !get_session_flags(APPID_SESSION_NO_TPI) &&
        is_third_party_appid_available(tpsession) &&
        tp_app_id > APP_ID_NONE && tp_app_id < SF_APPID_MAX)
        {
            entry = app_info_mgr->get_app_info_entry(tp_app_id);
            if (entry && entry->svrValidator && !(entry->flags & APPINFO_FLAG_SERVICE_ADDITIONAL))
            {
                if (session_logging_enabled)
                    LogMessage("AppIdDbg %s Stop service detection\n", session_logging_id);
                stop_rna_service_inspection(p, direction);
            }
        }

        if (rnaServiceState == RNA_STATE_STATEFUL)
        {
            AppIdDiscoverService(p, direction, this);
            isTpAppidDiscoveryDone = true;
            //to stop executing validator after service has been detected by RNA.
            if (get_session_flags(APPID_SESSION_SERVICE_DETECTED |
            APPID_SESSION_CONTINUE) == APPID_SESSION_SERVICE_DETECTED)
                rnaServiceState = RNA_STATE_FINISHED;

            if (serviceAppId == APP_ID_DNS && config->mod_config->dns_host_reporting
                    && dsession && dsession->host)
            {
                size_t size = dsession->host_len;
                dns_host_scan_hostname((const uint8_t*) (dsession->host), size, &client_app_id, &payload_app_id);
                set_client_app_id_data(client_app_id, nullptr);
            }
            else if (serviceAppId == APP_ID_RTMP)
                examine_rtmp_metadata();
            else if (get_session_flags(APPID_SESSION_SSL_SESSION) && tsession)
                examine_ssl_metadata(p);

            if (tp_app_id <= APP_ID_NONE && get_session_flags(APPID_SESSION_SERVICE_DETECTED |
            APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_IGNORE_HOST) ==
            APPID_SESSION_SERVICE_DETECTED)
            {
                sync_with_snort_id(serviceAppId, p);
            }
        }
    }

    return isTpAppidDiscoveryDone;
}

bool AppIdSession::do_client_discovery(int direction, Packet* p)
{
    bool isTpAppidDiscoveryDone = false;
    AppInfoTableEntry* entry;

    if (rna_client_state != RNA_STATE_FINISHED)
    {
        Profile clientMatchPerfStats_profile_context(clientMatchPerfStats);
        uint32_t prevRnaClientState = rna_client_state;
        bool was_http2 = is_http2;
        bool was_service = get_session_flags(APPID_SESSION_SERVICE_DETECTED) ? true : false;
        //decision to directly call validator or go through elaborate service_state tracking
        //is made once at the beginning of sesssion.
        if (rna_client_state == RNA_STATE_NONE && p->dsize && direction == APP_ID_FROM_INITIATOR)
        {
            if (p->flow->get_session_flags() & SSNFLAG_MIDSTREAM)
                rna_client_state = RNA_STATE_FINISHED;
            else if (is_third_party_appid_available(tpsession) && ( tp_app_id > APP_ID_NONE )
                    && ( tp_app_id < SF_APPID_MAX ) )
            {
                entry = app_info_mgr->get_app_info_entry(tp_app_id);
                if ( entry && entry->clntValidator
                     && ( ( entry->flags & APPINFO_FLAG_CLIENT_ADDITIONAL )
                           || ( ( entry->flags & APPINFO_FLAG_CLIENT_USER)
                                  && get_session_flags(APPID_SESSION_DISCOVER_USER) ) ) )
                {
                    //tp has positively identified appId, Dig deeper only if sourcefire
                    // detector identifies additional information
                    rna_client_data = entry->clntValidator;
                    rna_client_state = RNA_STATE_DIRECT;
                }
                else
                {
                    set_session_flags(APPID_SESSION_CLIENT_DETECTED);
                    rna_client_state = RNA_STATE_FINISHED;
                }
            }
            else if (get_session_flags(APPID_SESSION_HTTP_SESSION))
                rna_client_state = RNA_STATE_FINISHED;
            else
                rna_client_state = RNA_STATE_STATEFUL;
        }
        //stop rna inspection as soon as tp has classified a valid AppId later in the session
        if ((rna_client_state == RNA_STATE_STATEFUL || rna_client_state == RNA_STATE_DIRECT)
                && rna_client_state == prevRnaClientState && !get_session_flags(APPID_SESSION_NO_TPI)
                && is_third_party_appid_available(tpsession) && tp_app_id > APP_ID_NONE && tp_app_id < SF_APPID_MAX)
        {
            entry = app_info_mgr->get_app_info_entry(tp_app_id);
            if (!(entry && entry->clntValidator && entry->clntValidator == rna_client_data
                    && (entry->flags & (APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER))))
            {
                rna_client_state = RNA_STATE_FINISHED;
                set_session_flags(APPID_SESSION_CLIENT_DETECTED);
            }
        }
        if (rna_client_state == RNA_STATE_DIRECT)
        {
            int ret = CLIENT_APP_INPROCESS;
            if (direction == APP_ID_FROM_INITIATOR)
            {
                /* get out if we've already tried to validate a client app */
                if (!get_session_flags(APPID_SESSION_CLIENT_DETECTED))
                {
                    ret = exec_client_detectors(p, direction);
                }
            }
            else if (rnaServiceState != RNA_STATE_STATEFUL
                    && get_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))
            {
                ret = exec_client_detectors(p, direction);
            }

            switch (ret)
            {
            case CLIENT_APP_INPROCESS:
                break;
            default:
                rna_client_state = RNA_STATE_FINISHED;
                break;
            }
        }
        else if (rna_client_state == RNA_STATE_STATEFUL)
        {
            AppIdDiscoverClientApp(p, direction, this);
            isTpAppidDiscoveryDone = true;
            if (candidate_client_list != nullptr)
            {
                if (sflist_count(candidate_client_list) > 0)
                {
                    int ret = 0;
                    if (direction == APP_ID_FROM_INITIATOR)
                    {
                        /* get out if we've already tried to validate a client app */
                        if (!get_session_flags(APPID_SESSION_CLIENT_DETECTED))
                            ret = exec_client_detectors(p, direction);
                    }
                    else if (rnaServiceState != RNA_STATE_STATEFUL
                            && get_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))
                        ret = exec_client_detectors(p, direction);

                    if (ret < 0)
                        set_session_flags(APPID_SESSION_CLIENT_DETECTED);
                }
                else
                    set_session_flags(APPID_SESSION_CLIENT_DETECTED);
            }
        }

        if (session_logging_enabled)
            if (!was_http2 && is_http2)
                LogMessage("AppIdDbg %s Got a preface for HTTP/2\n", session_logging_id);

        if (!was_service && get_session_flags(APPID_SESSION_SERVICE_DETECTED))
            sync_with_snort_id(serviceAppId, p);
    }

    return isTpAppidDiscoveryDone;
}

void AppIdSession::do_application_discovery(Packet* p)
{
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
    AppId client_app_id = 0;
    AppId payload_app_id = 0;
    bool isTpAppidDiscoveryDone = false;
    int direction = 0;
    const SfIp* ip = nullptr;

    if( is_packet_ignored(p) )
        return;

    AppIdSession* asd = (AppIdSession*) p->flow->get_flow_data(AppIdSession::flow_id);
    if (asd)
    {
        if (asd->common.flow_type == APPID_FLOW_TYPE_IGNORE)
            return;

        if (asd->common.flow_type == APPID_FLOW_TYPE_NORMAL)
        {
            protocol = asd->protocol;
            asd->flow = p->flow;
        }
        else if (p->is_tcp())
            protocol = IpProtocol::TCP;
        else
            protocol = IpProtocol::UDP;

        ip = p->ptrs.ip_api.get_src();
        if (asd->common.initiator_port)
            direction = (asd->common.initiator_port == p->ptrs.sp) ?
				APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
        else
            direction = ip->fast_equals_raw(asd->common.initiator_ip) ?
                APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

        asd->in_expected_cache = false;
    }
    else
    {
        if (p->is_tcp())
            protocol = IpProtocol::TCP;
        else if (p->is_udp())
            protocol = IpProtocol::UDP;
        else if ( p->is_ip4() || p->is_ip6() )
            protocol = p->get_ip_proto_next();
        else
            return;

        // FIXIT-L Refactor to use direction symbols defined by snort proper
        direction = p->is_from_client() ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    }

    uint64_t flow_flags = AppIdSession::is_session_monitored(p, direction, asd);
    if (!(flow_flags & (APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED)))
    {
        if (!asd)
        {
            uint16_t port = 0;

            ip = (direction == APP_ID_FROM_INITIATOR) ?
                            p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst();
            if ((protocol == IpProtocol::TCP || protocol == IpProtocol::UDP)
                 && p->ptrs.sp != p->ptrs.dp)
             {
                 port = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.sp : p->ptrs.dp;
             }

            AppIdSession* tmp_session = new AppIdSession(protocol, ip, port);

            if ((flow_flags & APPID_SESSION_BIDIRECTIONAL_CHECKED) ==
            APPID_SESSION_BIDIRECTIONAL_CHECKED)
                tmp_session->common.flow_type = APPID_FLOW_TYPE_IGNORE;
            else
                tmp_session->common.flow_type = APPID_FLOW_TYPE_TMP;
            tmp_session->common.flags = flow_flags;
            tmp_session->common.policyId = appIdPolicyId;
            p->flow->set_flow_data(tmp_session);
        }
        else
        {
            asd->common.flags = flow_flags;
            if ((flow_flags & APPID_SESSION_BIDIRECTIONAL_CHECKED) ==
            APPID_SESSION_BIDIRECTIONAL_CHECKED)
                asd->common.flow_type = APPID_FLOW_TYPE_IGNORE;
            asd->common.policyId = appIdPolicyId;
        }

        return;
    }

    if (!asd || asd->common.flow_type == APPID_FLOW_TYPE_TMP)
    {
        /* This call will free the existing temporary session, if there is one */
        asd = AppIdSession::allocate_session(p, protocol, direction);
        if (asd->session_logging_enabled)
            LogMessage("AppIdDbg %s new session\n", asd->session_logging_id);
    }

    // FIXIT-L - from this point on we always have a valid ptr to an AppIdSession and a Packet
    //           refactor to pass these as refs and delete any checks for null
    appid_stats.processed_packets++;
    asd->session_packet_count++;

    if (direction == APP_ID_FROM_INITIATOR)
        asd->stats.initiatorBytes += p->pkth->pktlen;
    else
        asd->stats.responderBytes += p->pkth->pktlen;

    asd->common.flags = flow_flags;
    asd->common.policyId = appIdPolicyId;

    if (asd->get_session_flags(APPID_SESSION_IGNORE_FLOW))
    {
        if (asd->session_logging_enabled && !asd->get_session_flags(APPID_SESSION_IGNORE_FLOW_LOGGED))
        {
            asd->set_session_flags(APPID_SESSION_IGNORE_FLOW_LOGGED);
            LogMessage("AppIdDbg %s Ignoring connection with service %d\n",
                    asd->session_logging_id, asd->serviceAppId);
        }

        return;
    }

    if (p->packet_flags & PKT_STREAM_ORDER_BAD)
        asd->set_session_flags(APPID_SESSION_OOO);

    else if ( p->is_tcp() && p->ptrs.tcph )
    {
        uint16_t port = 0;
        const auto* tcph = p->ptrs.tcph;
        if ( tcph->is_rst() && asd->previous_tcp_flags == TH_SYN )
        {
            asd->set_session_flags(APPID_SESSION_SYN_RST);
            if (asd->service_ip.is_set())
            {
                ip = &asd->service_ip;
                port = asd->service_port;
            }
            else
            {
                ip = p->ptrs.ip_api.get_src();
                port = p->ptrs.sp;
            }

            AppIdServiceIDState* id_state = AppIdServiceState::get(ip, IpProtocol::TCP, port,
                get_service_detect_level(asd));

            if (id_state)
            {
                if (!id_state->reset_time)
                    id_state->reset_time = packet_time();
                else if ((packet_time() - id_state->reset_time) >= 60)
                {
                    AppIdServiceState::remove(ip, IpProtocol::TCP, port,
                            get_service_detect_level(asd));
                    asd->set_session_flags(APPID_SESSION_SERVICE_DELETED);
                }
            }
        }

        asd->previous_tcp_flags = p->ptrs.tcph->th_flags;
    }

    /*HostPort based AppId.  */
    if (!(asd->scan_flags & SCAN_HOST_PORT_FLAG))
    {
        HostPortVal* hv = nullptr;
        uint16_t port = 0;

        asd->scan_flags |= SCAN_HOST_PORT_FLAG;
        if (direction == APP_ID_FROM_INITIATOR)
        {
            ip = p->ptrs.ip_api.get_dst();
            port = p->ptrs.dp;
        }
        else
        {
            ip = p->ptrs.ip_api.get_src();
            port = p->ptrs.sp;
        }

        if ((hv = HostPortCache::find(ip, port, protocol)))
        {
            switch (hv->type)
            {
            case 1:
                asd->client_app_id = hv->appId;
                asd->rna_client_state = RNA_STATE_FINISHED;
                break;
            case 2:
                asd->payload_app_id = hv->appId;
                break;
            default:
                asd->serviceAppId = hv->appId;
                asd->sync_with_snort_id(hv->appId, p);
                asd->rnaServiceState = RNA_STATE_FINISHED;
                asd->rna_client_state = RNA_STATE_FINISHED;
                asd->set_session_flags(APPID_SESSION_SERVICE_DETECTED);
                if (thirdparty_appid_module)
                    thirdparty_appid_module->session_delete(asd->tpsession, 1);
                asd->tpsession = nullptr;
            }
        }
    }

    asd->check_app_detection_restart();

    //restart inspection by 3rd party
    if (!asd->tp_reinspect_by_initiator && (direction == APP_ID_FROM_INITIATOR) && checkThirdPartyReinspect(p, asd))
    {
        asd->tp_reinspect_by_initiator = true;
        asd->set_session_flags(APPID_SESSION_APP_REINSPECT);
        if (asd->session_logging_enabled)
            LogMessage("AppIdDbg %s 3rd party allow reinspect http\n",
                    asd->session_logging_id);
        asd->clear_http_field();
    }

    if (asd->tp_app_id == APP_ID_SSH && asd->payload_app_id != APP_ID_SFTP &&
        asd->session_packet_count >= MIN_SFTP_PACKET_COUNT &&
        asd->session_packet_count < MAX_SFTP_PACKET_COUNT)
    {
        if ( p->ptrs.ip_api.tos() == 8 )
        {
            asd->payload_app_id = APP_ID_SFTP;
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s data is SFTP\n", asd->session_logging_id);
        }
    }

    Profile tpPerfStats_profile_context(tpPerfStats);

#ifdef REMOVED_WHILE_NOT_IN_USE
    // do third party detector processing
    isTpAppidDiscoveryDone = asd->do_third_party_discovery(protocol, ip, p, direction);
#endif

    if ( asd->tp_reinspect_by_initiator && checkThirdPartyReinspect(p, asd) )
    {
        asd->clear_session_flags(APPID_SESSION_APP_REINSPECT);
        if (direction == APP_ID_FROM_RESPONDER)
            asd->tp_reinspect_by_initiator = false; //toggle at OK response
    }

    if ( !asd->get_session_flags(APPID_SESSION_PORT_SERVICE_DONE) )
    {
        switch (protocol)
        {
        case IpProtocol::TCP:
            if (asd->get_session_flags(APPID_SESSION_SYN_RST)) // TCP-specific exception
                break;
            // fall through to next test
        case IpProtocol::UDP:
            // Both TCP and UDP need this test to be made
            //  against only the p->src_port of the response.
            // For all other cases the port parameter is never checked.
            if (direction != APP_ID_FROM_RESPONDER)
                break;
            // fall through to all other cases
        // All protocols other than TCP and UDP come straight here.
        default:
            {
                asd->portServiceAppId = getPortServiceId(protocol, p->ptrs.sp, asd->config);
                if (asd->session_logging_enabled)
                     LogMessage("AppIdDbg %s port service %d\n",
                                asd->session_logging_id, asd->portServiceAppId);
                asd->set_session_flags(APPID_SESSION_PORT_SERVICE_DONE);
            }
            break;
        }
    }

    /* Length-based detectors. */
    /* Only check if:
     *  - Port service didn't find anything (and we haven't yet either).
     *  - We haven't hit the max packets allowed for detector sequence matches.
     *  - Packet has data (we'll ignore 0-sized packets in sequencing). */
    if ( (asd->portServiceAppId <= APP_ID_NONE)
        && (asd->length_sequence.sequence_cnt < LENGTH_SEQUENCE_CNT_MAX)
        && (p->dsize > 0))
    {
        uint8_t index = asd->length_sequence.sequence_cnt;
        asd->length_sequence.proto = protocol;
        asd->length_sequence.sequence_cnt++;
        asd->length_sequence.sequence[index].direction = direction;
        asd->length_sequence.sequence[index].length    = p->dsize;
        asd->portServiceAppId = find_length_app_cache(&asd->length_sequence);
        if (asd->portServiceAppId > APP_ID_NONE)
            asd->set_session_flags(APPID_SESSION_PORT_SERVICE_DONE);
    }

    /* exceptions for rexec and any other service detector that needs to see SYN and SYN/ACK */
    if (asd->get_session_flags(APPID_SESSION_REXEC_STDERR))
    {
        AppIdDiscoverService(p, direction, asd);
        if (asd->serviceAppId == APP_ID_DNS &&
            asd->config->mod_config->dns_host_reporting &&
            asd->dsession && asd->dsession->host )
        {
            size_t size = asd->dsession->host_len;
            dns_host_scan_hostname((const uint8_t*)asd->dsession->host, size,
            		&client_app_id, &payload_app_id);
            asd->set_client_app_id_data(client_app_id, nullptr);
        }
        else if (asd->serviceAppId == APP_ID_RTMP)
            asd->examine_rtmp_metadata();
        else if (asd->get_session_flags(APPID_SESSION_SSL_SESSION) && asd->tsession)
            asd->examine_ssl_metadata(p);
    }
    // FIXIT-M - snort 2.x has added a check for midstream pickup to this if, do we need that?
    else if (protocol != IpProtocol::TCP || !p->dsize || (p->packet_flags & PKT_STREAM_ORDER_OK))
    {
        // FIXIT-M commented out assignment causes analysis warning
        /*isTpAppidDiscoveryDone = */
            asd->do_service_discovery(protocol, direction, client_app_id, payload_app_id, p);
        isTpAppidDiscoveryDone = asd->do_client_discovery(direction, p);
        asd->set_session_flags(APPID_SESSION_ADDITIONAL_PACKET);
    }
    else
    {
        if (asd->session_logging_enabled && p->dsize &&
            !asd->get_session_flags(APPID_SESSION_OOO_LOGGED))
        {
            asd->set_session_flags(APPID_SESSION_OOO_LOGGED);
            LogMessage("AppIdDbg %s packet out-of-order\n", asd->session_logging_id);
        }
    }

    AppId serviceAppId = asd->pick_service_app_id();
    payload_app_id = asd->pick_payload_app_id();

    if (serviceAppId > APP_ID_NONE)
    {
        if (asd->get_session_flags(APPID_SESSION_DECRYPTED))
        {
            if (asd->misc_app_id == APP_ID_NONE)
                asd->update_encrypted_app_id(serviceAppId);
        }
// FIXIT-M Need to determine what api to use for this _dpd function
#if 1
        UNUSED(isTpAppidDiscoveryDone);
#else
        else if (isTpAppidDiscoveryDone && isSslServiceAppId(serviceAppId) &&
            _dpd.isSSLPolicyEnabled(nullptr))
            asd->set_session_flags(APPID_SESSION_CONTINUE);
#endif
    }

    p->flow->set_application_ids(serviceAppId, asd->pick_client_app_id(), payload_app_id, asd->pick_misc_app_id());

    /* Set the field that the Firewall queries to see if we have a search engine. */
    if (asd->search_support_type == UNKNOWN_SEARCH_ENGINE && payload_app_id > APP_ID_NONE)
    {
        uint flags = AppInfoManager::get_instance().get_app_info_flags(payload_app_id, APPINFO_FLAG_SEARCH_ENGINE |
            APPINFO_FLAG_SUPPORTED_SEARCH);
        asd->search_support_type =
            (flags & APPINFO_FLAG_SEARCH_ENGINE) ?
            ((flags & APPINFO_FLAG_SUPPORTED_SEARCH) ? SUPPORTED_SEARCH_ENGINE :
            UNSUPPORTED_SEARCH_ENGINE )
            : NOT_A_SEARCH_ENGINE;
        if (asd->session_logging_enabled)
        {
            const char* typeString;
            switch ( asd->search_support_type )
            {
            case NOT_A_SEARCH_ENGINE: typeString = "NOT_A_SEARCH_ENGINE"; break;
            case SUPPORTED_SEARCH_ENGINE: typeString = "SUPPORTED_SEARCH_ENGINE"; break;
            case UNSUPPORTED_SEARCH_ENGINE: typeString = "UNSUPPORTED_SEARCH_ENGINE"; break;
            default: typeString = "unknown"; break;
            }

            LogMessage("AppIdDbg %s appId: %u (safe)search_support_type=%s\n",
                    asd->session_logging_id, payload_app_id, typeString);
        }
    }

    if ( serviceAppId !=  APP_ID_NONE )
    {
        if ( payload_app_id != APP_ID_NONE && payload_app_id != asd->pastIndicator)
        {
            asd->pastIndicator = payload_app_id;
            check_session_for_AF_indicator(p, direction, (ApplicationId)payload_app_id);
        }

        if (asd->payload_app_id == APP_ID_NONE && asd->pastForecast != serviceAppId &&
            asd->pastForecast != APP_ID_UNKNOWN)
        {
            asd->pastForecast = check_session_for_AF_forecast(asd, p, direction,
                (ApplicationId)serviceAppId);
        }
    }
}

static inline int PENetworkMatch(const SfIp* pktAddr, const PortExclusion* pe)
{
    const uint32_t* pkt = pktAddr->get_ip6_ptr();
    const uint32_t* nm = pe->netmask.u6_addr32;
    const uint32_t* peIP = pe->ip.u6_addr32;
    return (((pkt[0] & nm[0]) == peIP[0])
           && ((pkt[1] & nm[1]) == peIP[1])
           && ((pkt[2] & nm[2]) == peIP[2])
           && ((pkt[3] & nm[3]) == peIP[3]));
}

static inline int check_port_exclusion(const Packet* pkt, bool reversed)
{
    AppIdPortExclusions* src_port_exclusions;
    AppIdPortExclusions* dst_port_exclusions;
    SF_LIST* pe_list;
    PortExclusion* pe;
    const SfIp* s_ip;
    AppIdConfig* config = AppIdConfig::get_appid_config();

    if ( pkt->is_tcp() )
    {
        src_port_exclusions = &config->tcp_port_exclusions_src;
        dst_port_exclusions = &config->tcp_port_exclusions_dst;
    }
    else if ( pkt->is_udp() )
    {
        src_port_exclusions = &config->udp_port_exclusions_src;
        dst_port_exclusions = &config->udp_port_exclusions_dst;
    }
    else
        return 0;

    /* check the source port */
    uint16_t port = reversed ? pkt->ptrs.dp : pkt->ptrs.sp;
    if ( port && (pe_list = (*src_port_exclusions)[port]) != nullptr )
    {
        s_ip = reversed ? pkt->ptrs.ip_api.get_dst() : pkt->ptrs.ip_api.get_src();

        SF_LNODE* node;

        /* walk through the list of port exclusions for this port */
        for ( pe = (PortExclusion*)sflist_first(pe_list, &node);
            pe;
            pe = (PortExclusion*)sflist_next(&node) )
        {
            if ( PENetworkMatch(s_ip, pe))
                return 1;
        }
    }

    /* check the dest port */
    port = reversed ? pkt->ptrs.sp : pkt->ptrs.dp;
    if ( port && (pe_list = (*dst_port_exclusions)[port]) != nullptr )
    {
        s_ip = reversed ? pkt->ptrs.ip_api.get_src() : pkt->ptrs.ip_api.get_dst();

        SF_LNODE* node;
        /* walk through the list of port exclusions for this port */
        for ( pe = (PortExclusion*)sflist_first(pe_list, &node);
            pe;
            pe = (PortExclusion*)sflist_next(&node) )
        {
            if ( PENetworkMatch(s_ip, pe))
                return 1;
        }
    }

    return 0;
}

static inline unsigned get_ipfuncs_flags(const Packet* p, bool dst)
{
    const SfIp* sf_ip;
    NetworkSet* net_list;
    unsigned flags;
    int32_t zone;
    NSIPv6Addr ip6;
    AppIdConfig* config = AppIdConfig::get_appid_config();

    if (!dst)
    {
        zone = p->pkth->ingress_group;
        sf_ip = p->ptrs.ip_api.get_src();
    }
    else
    {
        zone = (p->pkth->egress_index == DAQ_PKTHDR_UNKNOWN) ?
                        p->pkth->ingress_group : p->pkth->egress_group;
        if (zone == DAQ_PKTHDR_FLOOD)
            return 0;
        sf_ip = p->ptrs.ip_api.get_dst();
    }

    if (zone >= 0 && zone < MAX_ZONES && config->net_list_by_zone[zone])
        net_list = config->net_list_by_zone[zone];
    else
        net_list = config->net_list;

    if ( sf_ip->is_ip4() )
    {
        if (sf_ip->get_ip4_value() == 0xFFFFFFFF)
            return IPFUNCS_CHECKED;
        NetworkSetManager::contains_ex(net_list, ntohl(sf_ip->get_ip4_value()), &flags);
    }
    else
    {
        memcpy(&ip6, sf_ip->get_ip6_ptr(), sizeof(ip6));
        NetworkSetManager::ntoh_ipv6(&ip6);
        NetworkSetManager::contains6_ex(net_list, &ip6, &flags);
    }

    return flags | IPFUNCS_CHECKED;
}

static inline bool is_special_session_monitored(const Packet* p)
{
    if ( p->is_ip4() )
    {
        if (p->is_udp() && ((p->ptrs.sp == 68 && p->ptrs.dp == 67)
            || (p->ptrs.sp == 67 &&  p->ptrs.dp == 68)))
        {
            return true;
        }
    }
    return false;
}

bool AppIdSession::is_ssl_decryption_enabled()
{
    if (get_session_flags(APPID_SESSION_DECRYPTED))
        return true;

    return flow->is_proxied();
}


uint64_t AppIdSession::is_session_monitored(const Packet* p, int dir, AppIdSession* asd)
{
    uint64_t flags = 0;
    uint64_t flow_flags = APPID_SESSION_DISCOVER_APP;

    flow_flags |= (dir == APP_ID_FROM_INITIATOR) ?
            APPID_SESSION_INITIATOR_SEEN : APPID_SESSION_RESPONDER_SEEN;
    if (asd)
    {
        flow_flags |= asd->common.flags;
        if (asd->common.policyId != appIdPolicyId)
        {
            if (check_port_exclusion(p, dir == APP_ID_FROM_RESPONDER))
            {
                flow_flags |= APPID_SESSION_INITIATOR_SEEN | APPID_SESSION_RESPONDER_SEEN |
                    APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_RESPONDER_CHECKED;
                flow_flags &= ~(APPID_SESSION_INITIATOR_MONITORED |
                    APPID_SESSION_RESPONDER_MONITORED);
                return flow_flags;
            }
            if (dir == APP_ID_FROM_INITIATOR)
            {
                if (asd->get_session_flags(APPID_SESSION_INITIATOR_CHECKED))
                {
                    flags = get_ipfuncs_flags(p, false);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_INITIATOR_MONITORED;
                }

                if (asd->get_session_flags(APPID_SESSION_RESPONDER_CHECKED))
                {
                    flags = get_ipfuncs_flags(p, true);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_RESPONDER_MONITORED;
                }
            }
            else
            {
                if (asd->get_session_flags(APPID_SESSION_RESPONDER_CHECKED))
                {
                    flags = get_ipfuncs_flags(p, false);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_RESPONDER_MONITORED;
                }

                if (asd->get_session_flags(APPID_SESSION_INITIATOR_CHECKED))
                {
                    flags = get_ipfuncs_flags(p, true);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_INITIATOR_MONITORED;
                }
            }
        }

        if (asd->get_session_flags(APPID_SESSION_BIDIRECTIONAL_CHECKED) ==
            APPID_SESSION_BIDIRECTIONAL_CHECKED)
            return flow_flags;

        if (dir == APP_ID_FROM_INITIATOR)
        {
            if (!asd->get_session_flags(APPID_SESSION_INITIATOR_CHECKED))
            {
                flags = get_ipfuncs_flags(p, false);
                flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                if (flags & IPFUNCS_USER_IP)
                    flow_flags |= APPID_SESSION_DISCOVER_USER;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;

                if (is_special_session_monitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
            if (!(flow_flags & APPID_SESSION_DISCOVER_APP)
                    && !asd->get_session_flags(APPID_SESSION_RESPONDER_CHECKED))
            {
                flags = get_ipfuncs_flags(p, true);
                if (flags & IPFUNCS_CHECKED)
                    flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;
                if (is_special_session_monitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
        }
        else
        {
            if (!asd->get_session_flags(APPID_SESSION_RESPONDER_CHECKED))
            {
                flags = get_ipfuncs_flags(p, false);
                flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;
                if (is_special_session_monitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
            if (!(flow_flags & APPID_SESSION_DISCOVER_APP)
                    && !asd->get_session_flags(APPID_SESSION_INITIATOR_CHECKED))
            {
                flags = get_ipfuncs_flags(p, true);
                if (flags & IPFUNCS_CHECKED)
                    flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                if (flags & IPFUNCS_USER_IP)
                    flow_flags |= APPID_SESSION_DISCOVER_USER;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;
                if (is_special_session_monitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
        }
    }
    else if (check_port_exclusion(p, false))
    {
        flow_flags |= APPID_SESSION_INITIATOR_SEEN | APPID_SESSION_RESPONDER_SEEN |
            APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_RESPONDER_CHECKED;
    }
    else if (dir == APP_ID_FROM_INITIATOR)
    {
        flags = get_ipfuncs_flags(p, false);
        flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
        if (flags & IPFUNCS_HOSTS_IP)
            flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
        if (flags & IPFUNCS_USER_IP)
            flow_flags |= APPID_SESSION_DISCOVER_USER;
        if (flags & IPFUNCS_APPLICATION)
            flow_flags |= APPID_SESSION_DISCOVER_APP;
        if (!(flow_flags & APPID_SESSION_DISCOVER_APP))
        {
            flags = get_ipfuncs_flags(p, true);
            if (flags & IPFUNCS_CHECKED)
                flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
        }
        if (is_special_session_monitored(p))
        {
            flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
        }
    }
    else
    {
        flags = get_ipfuncs_flags(p, false);
        flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
        if (flags & IPFUNCS_HOSTS_IP)
            flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
        if (flags & IPFUNCS_APPLICATION)
            flow_flags |= APPID_SESSION_DISCOVER_APP;
        if (!(flow_flags & APPID_SESSION_DISCOVER_APP))
        {
            flags = get_ipfuncs_flags(p, true);
            if (flags & IPFUNCS_CHECKED)
                flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
            if (flags & IPFUNCS_USER_IP)
                flow_flags |= APPID_SESSION_DISCOVER_USER;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
        }

        if (is_special_session_monitored(p))
        {
            flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
        }
    }

    return flow_flags;
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
        unsigned prev_priority = app_info_mgr->get_app_info_priority(client_app_id);
        unsigned curr_priority = app_info_mgr->get_app_info_priority(id);

        if ((client_app_id) && (prev_priority > curr_priority ))
            return;
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

        AppInfoTableEntry *entry = app_info_mgr->get_app_info_entry(newAppId);
        if ( entry )
        {
            int16_t tempSnortId = entry->snortId;
            // A particular APP_ID_xxx may not be assigned a service_snort_key value
            // in the rna_app.yaml file entry; so ignore the tempSnortId == 0 case.
            if( tempSnortId == 0 && (newAppId == APP_ID_HTTP2))
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

void AppIdSession::examine_ssl_metadata(Packet* p)
{
    size_t size;
    int ret;
    AppId client_app_id = 0;
    AppId payload_app_id = 0;

    if ((scan_flags & SCAN_SSL_HOST_FLAG) && tsession->tls_host)
    {
        size = strlen(tsession->tls_host);
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
        size = strlen(tsession->tls_cname);
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
        size = strlen(tsession->tls_orgUnit);
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
        hsession = (httpSession*)snort_calloc(sizeof(httpSession));

    if (hsession->url)
    {
        if (((get_appid_from_url(nullptr, hsession->url, &version,
            hsession->referer, &client_app_id, &serviceAppId,
            &payload_app_id, &referredPayloadAppId, 1)) ||
            (get_appid_from_url(nullptr, hsession->url, &version,
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
        unsigned prev_priority = app_info_mgr->get_app_info_priority(payload_app_id);
        unsigned curr_priority = app_info_mgr->get_app_info_priority(id);

        if ((payload_app_id ) && (prev_priority > curr_priority ))
            return;

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

        /* Clear out previous values of vendor & version */
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
            /* Clear previous values */
            if (serviceVendor)
                snort_free(serviceVendor);
            if (serviceVersion)
                snort_free(serviceVersion);

            /* set vendor */
            if (vendor)
                serviceVendor = vendor;
            else
                serviceVendor = nullptr;

            /* set version */
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
    int i;

    if (hsession == nullptr)
        return;

    clear_http_field();

    if (hsession->new_field_contents)
        for (i = 0; i < NUMBER_OF_PTYPES; i++)
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

        snort_free( tmp_fd );
        //tmp_fd->next = fd_free_list;
        //fd_free_list = tmp_fd;
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

    if (candidate_service_list)
    {
        sflist_free(candidate_service_list);
        candidate_service_list = nullptr;
    }

    if (candidate_client_list)
    {
        sflist_free(candidate_client_list);
        candidate_client_list = nullptr;
    }
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
    AppIdFlowData** pfd;
    AppIdFlowData* fd;

    pfd = &flowData;
    while (*pfd)
    {
        if ((*pfd)->fd_id & mask)
        {
            fd = *pfd;
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

int AppIdSession::add_flow_data_id(uint16_t port, const RNAServiceElement* svc_element)
{
    if (serviceData)
        return -1;
    serviceData = svc_element;
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

    rnaServiceState = RNA_STATE_FINISHED;
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

AppId AppIdSession::fw_pick_service_app_id()
{
    AppId appId;
    appId = pick_service_app_id();
    if (appId == APP_ID_NONE)
        appId = encrypted.serviceAppId;
    return appId;
}

AppId AppIdSession::fw_pick_misc_app_id()
{
    AppId appId;
    appId = pick_misc_app_id();
    if (appId == APP_ID_NONE)
        appId = encrypted.miscAppId;
    return appId;
}

AppId AppIdSession::fw_pick_client_app_id()
{
    AppId appId;
    appId = pick_client_app_id();
    return appId;
}

AppId AppIdSession::fw_pick_payload_app_id()
{
    AppId appId;
    appId = pick_payload_app_id();
    if (appId == APP_ID_NONE)
        appId = encrypted.payloadAppId;
    return appId;
}

AppId AppIdSession::fw_pick_referred_payload_app_id()
{
    AppId appId;
    appId = pick_referred_payload_app_id();
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

int AppIdSession::initial_CHP_sweep(char** chp_buffers, uint16_t* chp_buffer_lengths, MatchedCHPAction** ppmatches)
{
    CHPApp* cah = nullptr;
    int longest = 0;
    CHPTallyAndActions chp;
    chp.matches = *ppmatches;

    for (unsigned i = 0; i <= MAX_KEY_PATTERN; i++)
    {
        ppmatches[i] = nullptr;
        if (chp_buffers[i] && chp_buffer_lengths[i])
            scan_key_chp((PatternType)i, chp_buffers[i], chp_buffer_lengths[i], chp);
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
                free_matched_chp_actions(ppmatches[i]);
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

void AppIdSession::clearMiscHttpFlags()
{
    if (!get_session_flags(APPID_SESSION_SPDY_SESSION))
    {
        clear_session_flags(APPID_SESSION_CHP_INSPECTING);
        if (thirdparty_appid_module)
            thirdparty_appid_module->session_attr_clear(tpsession,
                TP_ATTR_CONTINUE_MONITORING);
    }
}

void AppIdSession::processCHP(char** version, Packet* p)
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

    uint16_t chp_buffer_lengths[NUMBER_OF_PTYPES] = {
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

        if ( !initial_CHP_sweep(chp_buffers, chp_buffer_lengths, chp_matches) )
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
                AppId ret = scan_chp((PatternType)i, chp_buffers[i], chp_buffer_lengths[i], chp_matches[i], version, &user,
                               &chp_rewritten[i], &found_in_buffer, hsession, p);
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
            else
            {
                if ( !hsession->num_matches )
                {
                    // num_matches == 0 means: all must succeed  give up early
                    hsession->chp_candidate = 0;
                    break;
                }
            }

            // Decrement the expected scan count toward 0.
            hsession->ptype_scan_counts[i] = 0;
            hsession->num_scans--;
            // if we have reached the end of the list of scans (which have something to do), then num_scans == 0
            if (hsession->num_scans == 0)
            {
                // we finished the last scan
                // either the num_matches value was zero and we failed early-on or we need to check for the min.
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
    HeaderMatchedPatterns hmp;
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
            clearMiscHttpFlags();

        return 0;
    }

    if (direction == APP_ID_FROM_RESPONDER && !get_session_flags(
        APPID_SESSION_RESPONSE_CODE_CHECKED))
    {
        if (hsession->response_code)
        {
            set_session_flags(APPID_SESSION_RESPONSE_CODE_CHECKED);
            if (hsession->response_code_buflen != RESPONSE_CODE_LENGTH)            {
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
    memset(&hmp, 0, sizeof(hmp));

    if (serviceAppId == APP_ID_NONE)
        serviceAppId = APP_ID_HTTP;

    if (session_logging_enabled)
        LogMessage("AppIdDbg %s chp_finished %d chp_hold_flow %d\n", session_logging_id,
            hsession->chp_finished, hsession->chp_hold_flow);

    if (!hsession->chp_finished || hsession->chp_hold_flow)
        processCHP(&version, nullptr);

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

                    get_server_vendor_version((uint8_t*)hsession->server,
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

            if (is_webdav_found(&hmp))
            {
                if (session_logging_enabled && payload_id > APP_ID_NONE &&
                    payload_app_id != payload_id)
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
                identify_user_agent((uint8_t*)useragent, hsession->useragent_buflen,
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
                payload_id = get_appid_by_pattern((uint8_t*)via, size, &version);
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

            appId = scan_header_x_working_with((uint8_t*)hsession->x_working_with,
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
            payload_id = get_appid_by_content_type((uint8_t*)hsession->content_type,
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

            if (get_appid_from_url(host, url, &version, referer, &client_id, &service_id,
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

        clearMiscHttpFlags();
    }  // end DON'T skip_simple_detect

    snort_free(version);
    return 0;
}

