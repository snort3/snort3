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

// service_discovery.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_discovery.h"

#include <algorithm>

#include "appid_config.h"
#include "appid_session.h"
#include "app_info_table.h"
#include "lua_detector_api.h"

#include "service_battle_field.h"
#include "service_bgp.h"
#include "service_bit.h"
#include "service_bootp.h"
#include "service_dcerpc.h"
#include "service_direct_connect.h"
#include "service_flap.h"
#include "service_ftp.h"
#include "service_irc.h"
#include "service_lpr.h"
#include "service_mysql.h"
#include "service_mdns.h"
#include "service_netbios.h"
#include "service_nntp.h"
#include "service_ntp.h"
#include "service_radius.h"
#include "service_rexec.h"
#include "service_rlogin.h"
#include "service_rfb.h"
#include "service_rpc.h"
#include "service_rshell.h"
#include "service_rsync.h"
#include "service_rtmp.h"
#include "service_snmp.h"
#include "service_ssh.h"
#include "service_ssl.h"
#include "service_tftp.h"
#include "service_timbuktu.h"
#include "service_tns.h"
#include "service_telnet.h"
#include "thirdparty_appid_utils.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/detector_http.h"
#include "detector_plugins/detector_imap.h"
#include "detector_plugins/detector_kerberos.h"
#include "detector_plugins/detector_pattern.h"
#include "detector_plugins/detector_pop3.h"
#include "detector_plugins/detector_sip.h"
#include "detector_plugins/detector_smtp.h"

#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

static THREAD_LOCAL ServiceDetector* ftp_service = nullptr;
ProfileStats serviceMatchPerfStats;

ServiceDiscovery::ServiceDiscovery()
{
    initialize();
}

ServiceDiscovery::~ServiceDiscovery()
{
}

ServiceDiscovery& ServiceDiscovery::get_instance()
{
    static THREAD_LOCAL ServiceDiscovery* discovery_manager = new ServiceDiscovery;
    return *discovery_manager;
}

void ServiceDiscovery::initialize()
{
    new BattleFieldServiceDetector(this);
    new BgpServiceDetector(this);
    new BitServiceDetector(this);
    new BootpServiceDetector(this);
    new DceRpcServiceDetector(this);
    new DirectConnectServiceDetector(this);
    new DnsTcpServiceDetector(this);
    new DnsUdpServiceDetector(this);
    new FlapServiceDetector(this);
    new FtpServiceDetector(this);
    new HttpServiceDetector(this);
    new ImapServiceDetector(this);
    new IrcServiceDetector(this);
    new KerberosServiceDetector(this);
    new LprServiceDetector(this);
    new MdnsServiceDetector(this);
    new MySqlServiceDetector(this);
    new NbssServiceDetector(this);
    new NbnsServiceDetector(this);
    new NbdgmServiceDetector(this);
    new NntpServiceDetector(this);
    new NtpServiceDetector(this);
    new PatternServiceDetector(this);
    new Pop3ServiceDetector(this);
    new RadiusServiceDetector(this);
    new RadiusAcctServiceDetector(this);
    new RexecServiceDetector(this);
    new RfbServiceDetector(this);
    new RloginServiceDetector(this);
    new RpcServiceDetector(this);
    new RshellServiceDetector(this);
    new RsyncServiceDetector(this);
    new RtmpServiceDetector(this);
    new SipServiceDetector(this);
    new SmtpServiceDetector(this);
    new SnmpServiceDetector(this);
    new SshServiceDetector(this);
    new SslServiceDetector(this);
    new TelnetServiceDetector(this);
    new TftpServiceDetector(this);
    new TimbuktuServiceDetector(this);
    new TnsServiceDetector(this);

    for ( auto kv : tcp_detectors )
        kv.second->initialize();

    for ( auto kv : udp_detectors )
        kv.second->initialize();
}

void ServiceDiscovery::finalize_service_patterns()
{
    if (tcp_patterns)
        tcp_patterns->prep();
    if (udp_patterns)
        udp_patterns->prep();
}

int ServiceDiscovery::add_service_port(AppIdDetector* detector, const ServiceDetectorPort& pp)
{
    ServiceDetector* service = static_cast<ServiceDetector*>(detector);

    if (pp.proto == IpProtocol::TCP)
    {
        if (pp.port == 21 && !ftp_service)
        {
            ftp_service = service;
            detector->ref_count++;
        }

        tcp_services[ pp.port ].push_back(service);
    }
    else if (pp.proto == IpProtocol::UDP)
    {
        if (!pp.reversed_validation)
            udp_services[ pp.port ].push_back(service);
        else
            udp_reversed_services[ pp.port ].push_back(service);
    }
    else
    {
        ErrorMessage("Invalid protocol (%u) specified for service %s.\n",
            (unsigned)pp.proto, service->name.c_str());
        return 0;
    }

    service->ref_count++;
    return 0;
}

/* Handle some exception cases on failure:
 *  - valid_count: If we have a detector that should be valid, but it keeps
 *    failing, consider restarting the detector search.
 *  - invalid_client_count: If our service detector search had trouble
 *    simply because of unrecognized client data, then consider retrying
 *    the search again. */
static void HandleFailure(AppIdSession* asd, ServiceDiscoveryState* id_state,
    const SfIp* client_ip, unsigned timeout)
{
    /* If we had a valid detector, check for too many fails.  If so, start
     * search sequence again. */
    if (id_state->state == SERVICE_ID_VALID)
    {
        /* Too many invalid clients?  If so, count it as an invalid detect. */
        if (id_state->invalid_client_count >= STATE_ID_INVALID_CLIENT_THRESHOLD)
        {
            if (id_state->valid_count <= 1)
            {
                id_state->state = SERVICE_ID_NEW;
                id_state->invalid_client_count = 0;
                id_state->last_invalid_client.clear();
                id_state->valid_count = 0;
                id_state->detract_count = 0;
                id_state->last_detract.clear();
            }
            else
            {
                id_state->valid_count--;
                id_state->last_invalid_client = *client_ip;
                id_state->invalid_client_count = 0;
            }
        }
        /* Just a plain old fail.  If too many of these happen, start
         * search process over. */
        else if (id_state->invalid_client_count == 0)
        {
            if (id_state->last_detract.fast_eq6(*client_ip))
                id_state->detract_count++;
            else
                id_state->last_detract = *client_ip;

            if (id_state->detract_count >= STATE_ID_NEEDED_DUPE_DETRACT_COUNT)
            {
                if (id_state->valid_count <= 1)
                {
                    id_state->state = SERVICE_ID_NEW;
                    id_state->invalid_client_count = 0;
                    id_state->last_invalid_client.clear();
                    id_state->valid_count = 0;
                    id_state->detract_count = 0;
                    id_state->last_detract.clear();
                }
                else
                    id_state->valid_count--;
            }
        }
    }
    /* If we were port/pattern searching and timed out, just restart over next
     * time. */
    else if ( timeout && asd->service_candidates.size() )
    {
        id_state->state = SERVICE_ID_NEW;
    }
    else if ( (asd->service_candidates.size() )
        && (id_state->state == SERVICE_ID_BRUTE_FORCE) )
    {
        /* If we're getting some invalid clients, defer brute force search and keep retrying
         * port/pattern search until we either find something or until we
         * just see too many invalid clients. */
        if (    (id_state->invalid_client_count > 0)
            && (id_state->invalid_client_count < STATE_ID_INVALID_CLIENT_THRESHOLD) )
        {
            id_state->state = SERVICE_ID_NEW;
        }
    }

    /* Done looking for this session. */
    id_state->searching = false;
}

/**Changes in_process service state to failed state when a flow is terminated.
 *
 * RNA used to repeat the same service detector if the detector remained in process till the flow terminated. Thus RNA
 * got stuck on this one detector and never tried another service detector. This function will treat such a detector
 * as returning incompatibleData when the flow is terminated. The intent here to make RNA try other service detectors but
 * unlike incompatibleData status, we dont want to undermine confidence in the service.
 *
 * @note Packet may be nullptr when this function is called upon session timeout.
 */
void FailInProcessService(AppIdSession* asd, const AppIdConfig*)
{
    if (asd->get_session_flags(APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_UDP_REVERSED))
        return;

    ServiceDiscoveryState* id_state = AppIdServiceState::get(&asd->service_ip, asd->protocol,
        asd->service_port, get_service_detect_level(asd));

    APPID_LOG_FILTER_SERVICE_PORT(asd->service_port,
        "FailInProcess %" PRIx64 ", %08X:%u proto %u\n", asd->common.flags,
        asd->common.initiator_ip.ip32[3], (unsigned)asd->service_port,
        (unsigned)asd->protocol);

    if (!id_state || (id_state->service && !id_state->service->current_ref_count))
        return;

    APPID_LOG_FILTER_SERVICE_PORT(asd->service_port,
        "FailInProcess: State %s for protocol %u on port %u, count %u, %s\n",
        service_id_state_name[id_state->state], (unsigned)asd->protocol,
        (unsigned)asd->service_port, id_state->invalid_client_count,
        (id_state->service) ? id_state->service->name.c_str() : "UNKNOWN");

    id_state->invalid_client_count += STATE_ID_INCONCLUSIVE_SERVICE_WEIGHT;
    if (asd->flow->server_ip.fast_eq6(asd->service_ip))
        HandleFailure(asd, id_state, &asd->flow->client_ip, 1);
    else
        HandleFailure(asd, id_state, &asd->flow->server_ip, 1);

    APPID_LOG_FILTER_SERVICE_PORT(asd->service_port,
        "FailInProcess: Changed State to %s for protocol %u on port %u, count %u, %s\n",
        service_id_state_name[id_state->state], (unsigned)asd->protocol,
        (unsigned)asd->service_port, id_state->invalid_client_count,
        (id_state->service) ? id_state->service->name.c_str() : "UNKNOWN");
}

static int AppIdPatternPrecedence(const void* a, const void* b)
{
    const ServiceMatch* sm1 = (ServiceMatch*)a;
    const ServiceMatch* sm2 = (ServiceMatch*)b;

    /*higher precedence should be before lower precedence */
    if (sm1->count != sm2->count)
        return (sm2->count - sm1->count);
    else
        return (sm2->size - sm1->size);
}

static int pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    ServiceMatch** matches = (ServiceMatch**)data;
    AppIdPatternMatchNode* pd = (AppIdPatternMatchNode*)id;
    ServiceMatch* sm;

    // Ignore matches that don't start at the expected position.
    if ( pd->pattern_start_pos >= 0 && pd->pattern_start_pos != (match_end_pos - (int)pd->size) )
        return 0;

    for (sm = *matches; sm; sm = sm->next)
        if (sm->service == (ServiceDetector*)pd->service)
            break;

    if (sm)
        sm->count++;
    else
    {
        sm = (ServiceMatch*)snort_calloc(sizeof(ServiceMatch));
        sm->count++;
        sm->service = static_cast<ServiceDetector*>(pd->service);
        sm->size = pd->size;
        sm->next = *matches;
        *matches = sm;
    }
    return 0;
}

/**Perform pattern match of a packet and construct a list of services sorted in order of
 * precedence criteria. Criteria is count and then size. The first service in the list is
 * returned. The list itself is saved in ServiceDiscoveryState. If
 * appId is already identified, then use it instead of searching again. RNA will capability
 * to try out other inferior matches. If appId is unknown i.e. searched and not found by FRE then
 * dont do any pattern match. This is a way degrades RNA detector selection if FRE is running on
 * this sensor.
*/
void ServiceDiscovery::match_services_by_pattern(AppIdSession* asd, const Packet* pkt, IpProtocol
    proto)
{
    SearchTool* patterns = nullptr;

    if (proto == IpProtocol::TCP)
        patterns = tcp_patterns;
    else
        patterns = udp_patterns;

    if (!patterns)
    {
        APPID_LOG_SERVICE("Pattern bailing due to no patterns\n");
        return;
    }

    /*FRE didn't search */
    ServiceMatch* match_list = nullptr;
    patterns->find_all((char*)pkt->data, pkt->dsize, &pattern_match, false, (void*)&match_list);

    std::vector<ServiceMatch*> smOrderedList;
    for (ServiceMatch* sm = match_list; sm; sm = sm->next)
        smOrderedList.push_back(sm);

    if (smOrderedList.size() )
    {
        std::sort(smOrderedList.begin(), smOrderedList.end(), AppIdPatternPrecedence);
        for ( auto& sm : smOrderedList )
        {
            if ( std::find(asd->service_candidates.begin(), asd->service_candidates.end(),
                sm->service)
                == asd->service_candidates.end() )
            {
                asd->service_candidates.push_back(sm->service);
                asd->num_candidate_services_tried++;
            }
            snort_free(sm);
        }
    }
}

static inline uint16_t sslPortRemap(uint16_t port)
{
    switch (port)
    {
    case 465:
        return 25;
    case 563:
        return 119;
    case 585:
    case 993:
        return 143;
    case 990:
        return 21;
    case 992:
        return 23;
    case 994:
        return 6667;
    case 995:
        return 110;
    default:
        return 0;
    }
}

void ServiceDiscovery::get_port_based_services(IpProtocol protocol, uint16_t port,
    AppIdSession* asd)
{
    if (get_service_detect_level(asd) == 1)
    {
        unsigned mapped_port = sslPortRemap(port);
        if (mapped_port)
        {
            if ( ServiceDiscovery::get_instance().tcp_services.find(mapped_port) !=
                ServiceDiscovery::get_instance().tcp_services.end() )
            {
                asd->service_candidates =
                    ServiceDiscovery::get_instance().tcp_services[mapped_port];
                asd->num_candidate_services_tried +=
                    ServiceDiscovery::get_instance().tcp_services[mapped_port].size();
            }
        }
    }
    else if (protocol == IpProtocol::TCP)
    {
        if ( ServiceDiscovery::get_instance().tcp_services.find(port) !=
            ServiceDiscovery::get_instance().tcp_services.end() )
        {
            asd->service_candidates = ServiceDiscovery::get_instance().tcp_services[port];
            asd->num_candidate_services_tried +=
                ServiceDiscovery::get_instance().tcp_services[port].size();
        }
    }
    else
    {
        if ( ServiceDiscovery::get_instance().udp_services.find(port) !=
            ServiceDiscovery::get_instance().udp_services.end() )
        {
            asd->service_candidates = ServiceDiscovery::get_instance().udp_services[port];
            asd->num_candidate_services_tried +=
                ServiceDiscovery::get_instance().udp_services[port].size();
        }
    }
}

/* This function should be called to find the next service detector to try when
 * we have not yet found a valid detector in the host tracker.  It will try
 * both port and/or pattern (but not brute force - that should be done outside
 * of this function).  This includes UDP reversed services.  A valid id_state
 * (even if just initialized to the NEW state) should exist before calling this
 * function.  The state coming out of this function will reflect the state in
 * which the next detector was found.  If nothing is found, it'll indicate that
 * brute force should be tried next as a state (and return nullptr).  This
 * function can be called once or multiple times (to run multiple detectors in
 * parallel) per flow.  Do not call this function if a detector has already
 * been specified (service_detector).  Basically, this function handles going
 * through the main port/pattern search (and returning which detector to add
 * next to the list of detectors to try (even if only 1)). */
void ServiceDiscovery::get_next_service(const Packet* p, const int dir,
    AppIdSession* asd, ServiceDiscoveryState* id_state)
{
    auto proto = asd->protocol;

    /* If NEW, just advance onto trying ports. */
    if (id_state->state == SERVICE_ID_NEW)
    {
        id_state->state = SERVICE_ID_PORT;
        id_state->service   = nullptr;
    }

    /* See if there are any port detectors to try.  If not, move onto patterns. */
    if (id_state->state == SERVICE_ID_PORT)
        get_port_based_services(proto, (uint16_t)((dir ==  APP_ID_FROM_RESPONDER) ? p->ptrs.sp :
            p->ptrs.dp), asd);

    id_state->state = SERVICE_ID_PATTERN;

    if (id_state->state == SERVICE_ID_PATTERN)
    {
        /* If we haven't found anything yet, try to see if we get any hits
         * first with UDP reversed services before moving onto pattern matches. */
        if (dir == APP_ID_FROM_INITIATOR)
        {
            if (!asd->get_session_flags(APPID_SESSION_ADDITIONAL_PACKET)
                && (proto == IpProtocol::UDP) && !asd->tried_reverse_service )
            {
                asd->tried_reverse_service = true;
                ServiceDiscoveryState* id_state = AppIdServiceState::get(p->ptrs.ip_api.get_src(),
                    proto, p->ptrs.sp, get_service_detect_level(asd));
                if ( id_state && id_state->service )
                    asd->service_candidates.push_back(id_state->service);
                else if ( udp_reversed_services[p->ptrs.sp].size() )
                {
                    asd->service_candidates.insert(asd->service_candidates.end(),
                        udp_reversed_services[p->ptrs.sp].begin(),
                        udp_reversed_services[p->ptrs.sp].end());
                }
                else if ( p->dsize )
                {
                    match_services_by_pattern(asd, p, proto);
                }
                return;
            }
        }
        else
        {
            match_services_by_pattern(asd, p, proto);
            id_state->state = SERVICE_ID_BRUTE_FORCE;
            return;
        }
    }

    /* Don't do anything if it was in VALID or BRUTE FORCE. */
}

int ServiceDiscovery::AppIdDiscoverService(Packet* p, const int dir, AppIdSession* asd)
{
    const SfIp* ip = nullptr;
    int ret = APPID_NOMATCH;
    uint16_t port = 0;

    /* Get packet info. */
    auto proto = asd->protocol;
    if (asd->service_ip.is_set())
    {
        ip   = &asd->service_ip;
        port = asd->service_port;
    }
    else
    {
        if (dir == APP_ID_FROM_RESPONDER)
        {
            ip   = p->ptrs.ip_api.get_src();
            port = p->ptrs.sp;
        }
        else
        {
            ip   = p->ptrs.ip_api.get_dst();
            port = p->ptrs.dp;
        }
    }

    /* Get host tracker state. */
    ServiceDiscoveryState* id_state = AppIdServiceState::get(ip, proto, port,
        get_service_detect_level(asd));
    if ( !id_state )
        id_state = AppIdServiceState::add(ip, proto, port, get_service_detect_level(asd));

    if ( !asd->service_detector )
    {
        /* If a valid service already exists in host tracker, give it a try. */
        if (id_state->service && (id_state->state == SERVICE_ID_VALID))
            asd->service_detector = id_state->service;

        /* If we've gotten to brute force, give next detector a try. */
        else if ((id_state->state == SERVICE_ID_BRUTE_FORCE)
            && (asd->num_candidate_services_tried == 0)
            && !id_state->searching )
        {
            if (!id_state->brute_force_mgr)
                id_state->brute_force_mgr = new AppIdDetectorList(proto);

            id_state->service = id_state->brute_force_mgr->next();
            asd->service_detector = id_state->service;
        }
    }

    AppIdDiscoveryArgs args(p->data, p->dsize, dir, asd, p);
    args.config = asd->config;
    args.session_logging_enabled = asd->session_logging_enabled;
    args.session_logging_id = asd->session_logging_id;

    /* If we already have a service to try, then try it out. */
    if (asd->service_detector)
    {
        ret = asd->service_detector->validate(args);
        if (ret == APPID_NOT_COMPATIBLE)
            asd->got_incompatible_services = true;
        if (asd->session_logging_enabled)
            LogMessage("AppIdDbg %s %s returned %d\n", asd->session_logging_id,
                asd->service_detector->name.c_str(), ret);
    }
    else
    {
        if ( !asd->service_candidates.size() )
        {
            asd->num_candidate_services_tried = 0;

            /* This is our first time in for this session, and we're about to
             * search for a service, because we don't have any solid history on
             * this IP/port yet.  If some other session is also currently
             * searching on this host tracker entry, reset state here, so that
             * we can start search over again with this session. */
            if (id_state->searching)
                id_state->state = SERVICE_ID_NEW;
            id_state->searching = true;
        }

        /* See if we've got more detector(s) to add to the candidate list. */
        if ( (id_state->state == SERVICE_ID_NEW)
            || (id_state->state == SERVICE_ID_PORT)
            || ((id_state->state == SERVICE_ID_PATTERN) && (dir == APP_ID_FROM_RESPONDER)) )
        {
            get_next_service(p, dir, asd, id_state);
        }

        /* Run all of the detectors that we currently have. */
        ret = APPID_INPROCESS;
        auto it = asd->service_candidates.begin();
        while ( it != asd->service_candidates.end() )
        {
            ServiceDetector* service = (ServiceDetector*)*it;
            int result;

            result = service->validate(args);
            if (result == APPID_NOT_COMPATIBLE)
                asd->got_incompatible_services = true;
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s %s returned %d\n",
                    asd->session_logging_id, service->name.c_str(), result);

            if (result == APPID_SUCCESS)
            {
                ret = APPID_SUCCESS;
                asd->service_detector = service;
                asd->service_candidates.empty();
                break;    /* done */
            }
            else if (result != APPID_INPROCESS)    /* fail */
                asd->service_candidates.erase(it);
            else
                ++it;
        }

        /* If we tried everything and found nothing, then fail. */
        if (ret != APPID_SUCCESS)
        {
            if ( (asd->service_candidates.size() == 0)
                && ((asd->num_candidate_services_tried >= MAX_CANDIDATE_SERVICES)
                || (id_state->state == SERVICE_ID_BRUTE_FORCE) ) )
            {
                fail_service(asd, p, dir, nullptr);
                ret = APPID_NOMATCH;
            }
        }
    }

    if (asd->service_detector != nullptr)
    {
        id_state->reset_time = 0;
    }
    else if (dir == APP_ID_FROM_RESPONDER)    // bidirectional exchange unknown service
    {
        if (asd->session_logging_enabled)
            LogMessage("AppIdDbg %s no RNA service detector\n", asd->session_logging_id);

        fail_service(asd, p, dir, nullptr);
        ret = APPID_NOMATCH;
    }

    /* Handle failure exception cases in states. */
    if ((ret != APPID_INPROCESS) && (ret != APPID_SUCCESS))
    {
        const SfIp* tmp_ip;
        if (dir == APP_ID_FROM_RESPONDER)
            tmp_ip = p->ptrs.ip_api.get_dst();
        else
            tmp_ip = p->ptrs.ip_api.get_src();

        if (asd->got_incompatible_services)
        {
            if (id_state->invalid_client_count < STATE_ID_INVALID_CLIENT_THRESHOLD)
            {
                if (id_state->last_invalid_client.fast_equals_raw(*tmp_ip))
                    id_state->invalid_client_count++;
                else
                {
                    id_state->invalid_client_count += 3;
                    id_state->last_invalid_client = *tmp_ip;
                }
            }
        }

        HandleFailure(asd, id_state, tmp_ip, 0);
    }

    return ret;
}

int AddFTPServiceState(AppIdSession* asd)
{
    if (!ftp_service)
        return -1;
    return asd->add_flow_data_id(21, ftp_service);
}

bool ServiceDiscovery::do_service_discovery(AppIdSession& asd, IpProtocol protocol, int direction,
    AppId client_app_id, AppId payload_app_id, Packet* p)
{
    AppInfoTableEntry* entry = nullptr;
    bool isTpAppidDiscoveryDone = false;

    if (asd.rna_service_state != RNA_STATE_FINISHED)
    {
        Profile serviceMatchPerfStats_profile_context(serviceMatchPerfStats);
        uint32_t prevRnaServiceState = asd.rna_service_state;
        //decision to directly call validator or go through elaborate service_state tracking
        //is made once at the beginning of sesssion.
        if (asd.rna_service_state == RNA_STATE_NONE && p->dsize)
        {
            if (p->flow->get_session_flags() & SSNFLAG_MIDSTREAM)
            {
                // Unless it could be ftp control
                if (protocol == IpProtocol::TCP && (p->ptrs.sp == 21 || p->ptrs.dp == 21)
                    && !(p->ptrs.tcph->is_fin() || p->ptrs.tcph->is_rst()))
                {
                    asd.set_session_flags(APPID_SESSION_CLIENT_DETECTED |
                        APPID_SESSION_NOT_A_SERVICE
                        | APPID_SESSION_SERVICE_DETECTED);
                    if (!AddFTPServiceState(&asd))
                    {
                        asd.set_session_flags(APPID_SESSION_CONTINUE);
                        if (p->ptrs.dp != 21)
                            asd.set_session_flags(APPID_SESSION_RESPONDER_SEEN);
                    }
                    asd.rna_service_state = RNA_STATE_STATEFUL;
                }
                else
                {
                    asd.set_session_flags(APPID_SESSION_MID | APPID_SESSION_SERVICE_DETECTED);
                    asd.rna_service_state = RNA_STATE_FINISHED;
                }
            }
            else if (is_third_party_appid_available(asd.tpsession))
            {
                if (asd.tp_app_id > APP_ID_NONE)
                {
                    //tp has positively identified appId, Dig deeper only if sourcefire
                    // detector identifies additional information or flow is UDP reveresed.
                    if ((entry = asd.app_info_mgr->get_app_info_entry(asd.tp_app_id)) &&
                        entry->service_detector
                        && ((entry->flags & APPINFO_FLAG_SERVICE_ADDITIONAL)
                        || ((entry->flags & APPINFO_FLAG_SERVICE_UDP_REVERSED)
                        && protocol == IpProtocol::UDP
                        && asd.get_session_flags(
                        APPID_SESSION_INITIATOR_MONITORED
                        | APPID_SESSION_RESPONDER_MONITORED))))
                    {
                        asd.free_flow_data_by_mask(APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);
                        asd.service_detector = entry->service_detector;
                        asd.rna_service_state = RNA_STATE_STATEFUL;
                    }
                    else
                        asd.stop_rna_service_inspection(p, direction);
                }
                else
                    asd.rna_service_state = RNA_STATE_STATEFUL;
            }
            else
                asd.rna_service_state = RNA_STATE_STATEFUL;
        }
        //stop rna inspection as soon as tp has classified a valid AppId later in the session
        if (asd.rna_service_state == RNA_STATE_STATEFUL &&
            prevRnaServiceState == RNA_STATE_STATEFUL &&
            !asd.get_session_flags(APPID_SESSION_NO_TPI) &&
            is_third_party_appid_available(asd.tpsession) &&
            asd.tp_app_id > APP_ID_NONE && asd.tp_app_id < SF_APPID_MAX)
        {
            entry = asd.app_info_mgr->get_app_info_entry(asd.tp_app_id);
            if (entry && entry->service_detector && !(entry->flags &
                APPINFO_FLAG_SERVICE_ADDITIONAL))
            {
                if (asd.session_logging_enabled)
                    LogMessage("AppIdDbg %s Stop service detection\n", asd.session_logging_id);
                asd.stop_rna_service_inspection(p, direction);
            }
        }

        if (asd.rna_service_state == RNA_STATE_STATEFUL)
        {
            AppIdDiscoverService(p, direction, &asd);
            isTpAppidDiscoveryDone = true;
            //to stop executing validator after service has been detected by RNA.
            if (asd.get_session_flags(APPID_SESSION_SERVICE_DETECTED |
                APPID_SESSION_CONTINUE) == APPID_SESSION_SERVICE_DETECTED)
                asd.rna_service_state = RNA_STATE_FINISHED;

            if (asd.serviceAppId == APP_ID_DNS && asd.config->mod_config->dns_host_reporting
                && asd.dsession && asd.dsession->host)
            {
                size_t size = asd.dsession->host_len;
                dns_host_scan_hostname((const uint8_t*)(asd.dsession->host), size, &client_app_id,
                    &payload_app_id);
                asd.set_client_app_id_data(client_app_id, nullptr);
            }
            else if (asd.serviceAppId == APP_ID_RTMP)
                asd.examine_rtmp_metadata();
            else if (asd.get_session_flags(APPID_SESSION_SSL_SESSION) && asd.tsession)
                asd.examine_ssl_metadata(p);

            if (asd.tp_app_id <= APP_ID_NONE && asd.get_session_flags(
                APPID_SESSION_SERVICE_DETECTED |
                APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_IGNORE_HOST) ==
                APPID_SESSION_SERVICE_DETECTED)
            {
                asd.sync_with_snort_id(asd.serviceAppId, p);
            }
        }
    }

    return isTpAppidDiscoveryDone;
}

/**Called when service can not be identified on a flow but the checks failed on client request
 * rather than server response. When client request fails a check, it may be specific to a client
 * therefore we should not fail the service right away. If the same behavior is seen from the same
 * client ultimately we will have to fail the service. If the same behavior is seen from different
 * clients going to same service then this most likely the service is something else.
 */
int ServiceDiscovery::incompatible_data(AppIdSession* asd, const Packet* pkt, int dir,
    ServiceDetector* service)
{
    const SfIp* ip = pkt->ptrs.ip_api.get_src();
    uint16_t port = asd->service_port ? asd->service_port : pkt->ptrs.sp;
    ServiceDiscoveryState* id_state = AppIdServiceState::get(ip, asd->protocol, port,
        get_service_detect_level(asd));

    if ( service )
        asd->free_flow_data_by_id(service->flow_data_index);

    /* If we're still working on a port/pattern list of detectors, then ignore
     * individual fails until we're done looking at everything. */
    if ( (asd->service_detector == nullptr) && (id_state != nullptr) )
    {
        if (asd->service_candidates.size())
            return APPID_SUCCESS;
        else if ((asd->num_candidate_services_tried >= MAX_CANDIDATE_SERVICES)
            || (id_state->state == SERVICE_ID_BRUTE_FORCE) )
            return APPID_SUCCESS;
    }

    asd->set_session_flags(APPID_SESSION_SERVICE_DETECTED);
    asd->clear_session_flags(APPID_SESSION_CONTINUE);

    asd->serviceAppId = APP_ID_NONE;

    if ( asd->get_session_flags(APPID_SESSION_IGNORE_HOST | APPID_SESSION_UDP_REVERSED)
        || (service && !service->current_ref_count) )
        return APPID_SUCCESS;

    if (dir == APP_ID_FROM_INITIATOR)
    {
        asd->set_session_flags(APPID_SESSION_INCOMPATIBLE);
        return APPID_SUCCESS;
    }

    if ( !id_state )
    {
        id_state = AppIdServiceState::add(ip, asd->protocol, port, get_service_detect_level(asd));
        id_state->state = SERVICE_ID_NEW;
        id_state->service = service;
        asd->service_ip = *ip;
        asd->service_port = port;
    }
    else
    {
        if (!asd->service_ip.is_set())
        {
            asd->service_ip = *(pkt->ptrs.ip_api.get_src());
            if (!asd->service_port)
                asd->service_port = pkt->ptrs.sp;

            APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
                "service_IC: Changed State to %s for protocol %u on port %u (%u->%u), count %u, %s\n",
                service_id_state_name[id_state->state], (unsigned)asd->protocol,
                (unsigned)asd->service_port,
                (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp, id_state->invalid_client_count,
                (id_state->svc && id_state->svc->name) ? id_state->svc->name : "UNKNOWN");
        }
        id_state->reset_time = 0;
    }

    APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
        "service_IC: State %s for protocol %u on port %u (%u->%u), count %u, %s\n",
        service_id_state_name[id_state->state], (unsigned)asd->protocol,
        (unsigned)asd->service_port,
        (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp, id_state->invalid_client_count,
        (id_state->svc && id_state->svc->name) ? id_state->svc->name : "UNKNOWN");

    APPID_LOG_IP_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp, asd->service_ip,
        "Incompat: %s:%u:%u %p %d %s\n",
        ipstr, (unsigned)asd->protocol, (unsigned)asd->service_port, (void*)id_state,
        (int)id_state->state,
        (id_state->svc && id_state->svc->name) ? id_state->svc->name : "UNKNOWN");

    return APPID_SUCCESS;
}

int ServiceDiscovery::fail_service(AppIdSession* asd, const Packet* pkt, int dir,
    ServiceDetector* service)
{
    const SfIp* ip = pkt->ptrs.ip_api.get_src();
    uint16_t port = asd->service_port ? asd->service_port : pkt->ptrs.sp;
    ServiceDiscoveryState* id_state = AppIdServiceState::get(ip, asd->protocol, port,
        get_service_detect_level(asd));

    if ( service )
        asd->free_flow_data_by_id(service->flow_data_index);

    /* If we're still working on a port/pattern list of detectors, then ignore
     * individual fails until we're done looking at everything. */
    if ( (asd->service_detector == nullptr) && (id_state != nullptr) )
    {
        if ( asd->service_candidates.size() )
            return APPID_SUCCESS;
        else if ( (asd->num_candidate_services_tried >= MAX_CANDIDATE_SERVICES)
            || (id_state->state == SERVICE_ID_BRUTE_FORCE) )
            return APPID_SUCCESS;
    }

    asd->serviceAppId = APP_ID_NONE;
    asd->set_session_flags(APPID_SESSION_SERVICE_DETECTED);
    asd->clear_session_flags(APPID_SESSION_CONTINUE);

    /* detectors should be careful in marking session UDP_REVERSED otherwise the same detector
     * gets all future flows. UDP_REVERSE should be marked only when detector positively
     * matches opposite direction patterns. */
    if ( asd->get_session_flags(APPID_SESSION_IGNORE_HOST | APPID_SESSION_UDP_REVERSED)
        || (service && !service->current_ref_count) )
        return APPID_SUCCESS;

    /* For subsequent packets, avoid marking service failed on client packet,
     * otherwise the service will show up on client side. */
    if (dir == APP_ID_FROM_INITIATOR)
    {
        asd->set_session_flags(APPID_SESSION_INCOMPATIBLE);
        return APPID_SUCCESS;
    }

    if ( !id_state )
    {
        id_state = AppIdServiceState::add(ip, asd->protocol, port, get_service_detect_level(asd));
        id_state->state = SERVICE_ID_NEW;
        id_state->service = service;
        asd->service_ip = *ip;
        asd->service_port = port;
    }
    else
    {
        if (!asd->service_ip.is_set())
        {
            asd->service_ip = *(pkt->ptrs.ip_api.get_src());
            if (!asd->service_port)
                asd->service_port = pkt->ptrs.sp;
        }
    }
    id_state->reset_time = 0;

    APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
        "service_fail: State %s for protocol %u on port %u (%u->%u), count %u, valid count %u, currSvc %s\n",
        service_id_state_name[id_state->state], (unsigned)asd->protocol,
        (unsigned)asd->service_port, (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp,
        id_state->invalid_client_count, id_state->valid_count, name.c_str());

    APPID_LOG_IP_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp, asd->service_ip,
        "Fail: %s:%u:%u %p %d %s\n",
        ipstr, (unsigned)asd->protocol, (unsigned)asd->service_port, (void*)id_state,
        (int)id_state->state, name.c_str());

    return APPID_SUCCESS;
}

