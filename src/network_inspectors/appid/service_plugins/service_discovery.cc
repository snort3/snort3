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

// service_discovery.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_discovery.h"

#include <algorithm>

#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

#include "app_info_table.h"
#include "appid_config.h"
#include "appid_debug.h"
#include "appid_dns_session.h"
#include "appid_inspector.h"
#include "appid_session.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/detector_imap.h"
#include "detector_plugins/detector_kerberos.h"
#include "detector_plugins/detector_pattern.h"
#include "detector_plugins/detector_pop3.h"
#include "detector_plugins/detector_sip.h"
#include "detector_plugins/detector_smtp.h"
#include "lua_detector_api.h"
#include "service_bgp.h"
#include "service_bit.h"
#include "service_bootp.h"
#include "service_dcerpc.h"
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
#include "service_ssl.h"
#include "service_telnet.h"
#include "service_tftp.h"
#include "service_timbuktu.h"
#include "service_tns.h"

#ifdef REG_TEST
#include "service_regtest.h"
#endif

#include "tp_appid_session_api.h"

using namespace snort;

static ServiceDetector* ftp_service;

void ServiceDiscovery::initialize(AppIdInspector& inspector)
{
    new BgpServiceDetector(this);
    new BitServiceDetector(this);
    new BootpServiceDetector(this);
    new DceRpcServiceDetector(this);
    new DnsTcpServiceDetector(this);
    new DnsUdpServiceDetector(this);
    new FtpServiceDetector(this);
    new ImapServiceDetector(this);
    new IrcServiceDetector(this);
    new KerberosServiceDetector(this);
    new LprServiceDetector(this);
    new MdnsServiceDetector(this);
    new MySqlServiceDetector(this);
    new NbnsServiceDetector(this);
    new NbdgmServiceDetector(this);
    new NntpServiceDetector(this);
    new NtpServiceDetector(this);
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
    new SslServiceDetector(this);
    new TelnetServiceDetector(this);
    new TftpServiceDetector(this);
    new TimbuktuServiceDetector(this);
    new TnsServiceDetector(this);
#ifdef REG_TEST
    new RegTestServiceDetector(this);
    new RegTestServiceDetector1(this);
    new RegTestServiceDetector2(this);
#endif

    for ( auto kv : tcp_detectors )
    {
        kv.second->initialize(inspector);
        service_detector_list.emplace_back(kv.second);
    }
    for ( auto kv : udp_detectors )
    {
        kv.second->initialize(inspector);
        service_detector_list.emplace_back(kv.second);
    }
}

void ServiceDiscovery::reload()
{
    for ( auto kv : tcp_detectors )
        kv.second->reload();
    for ( auto kv : udp_detectors )
        kv.second->reload();
}

void ServiceDiscovery::finalize_service_patterns()
{
    tcp_patterns.prep();
    udp_patterns.prep();
}

void ServiceDiscovery::reload_service_patterns()
{
    tcp_patterns.reload();
    udp_patterns.reload();
}

int ServiceDiscovery::add_service_port(AppIdDetector* detector, const ServiceDetectorPort& pp)
{
    ServiceDetector* service = static_cast<ServiceDetector*>(detector);

    if (pp.proto == IpProtocol::TCP)
    {
        if (pp.port == 21 && !ftp_service)
            ftp_service = service;

        tcp_services[ pp.port ].emplace_back(service);
    }
    else if (pp.proto == IpProtocol::UDP)
    {
        if (!pp.reversed_validation)
            udp_services[ pp.port ].emplace_back(service);
        else
            udp_reversed_services[ pp.port ].emplace_back(service);
    }
    else
    {
        ErrorMessage("Invalid protocol (%u) specified for service %s.\n",
            (unsigned)pp.proto, service->get_name().c_str());
        return 0;
    }

    return 0;
}

static int AppIdPatternPrecedence(const void* a, const void* b)
{
    const ServiceMatch* sm1 = (const ServiceMatch*)a;
    const ServiceMatch* sm2 = (const ServiceMatch*)b;

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

    if ( pd->valid_match(match_end_pos) )
    {
        ServiceMatch* sm;

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
    }

    return 0;
}

/**Perform pattern match of a packet and construct a list of services sorted in order of
 * precedence criteria. Criteria is count and then size. The first service in the list is
 * returned. The list itself is saved in ServiceDiscoveryState. If
 * appId is already identified, then use it instead of searching again. AppId has capability
 * to try out other inferior matches. If appId is unknown i.e. searched and not found by FRE then
 * don't do any pattern match. This is a way to degrade detector if FRE is running.
*/
void ServiceDiscovery::match_by_pattern(AppIdSession& asd, const Packet* pkt, IpProtocol proto)
{
    SearchTool* patterns = nullptr;

    if (proto == IpProtocol::TCP)
        patterns = &tcp_patterns;
    else
        patterns = &udp_patterns;

    if (patterns)
    {
        ServiceMatch* match_list = nullptr;
        patterns->find_all((const char*)pkt->data, pkt->dsize, &pattern_match, false,
            (void*)&match_list);

        std::vector<ServiceMatch*> smOrderedList;
        for (ServiceMatch* sm = match_list; sm; sm = sm->next)
            smOrderedList.emplace_back(sm);

        if (!smOrderedList.empty() )
        {
            std::sort(smOrderedList.begin(), smOrderedList.end(), AppIdPatternPrecedence);
            for ( auto& sm : smOrderedList )
            {
                if ( std::find(asd.service_candidates.begin(), asd.service_candidates.end(),
                    sm->service) == asd.service_candidates.end() )
                {
                    asd.service_candidates.emplace_back(sm->service);
                }
                snort_free(sm);
            }
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
    AppIdSession& asd)
{
    ServiceDiscovery& sd = asd.get_odp_ctxt().get_service_disco_mgr();

    if ( asd.is_decrypted() )
    {
        unsigned mapped_port = sslPortRemap(port);
        if (mapped_port)
        {
            if ( sd.tcp_services.find(mapped_port) != sd.tcp_services.end() )
                asd.service_candidates = sd.tcp_services[mapped_port];
        }
    }
    else if ( protocol == IpProtocol::TCP )
    {
        if ( sd.tcp_services.find(port) != sd.tcp_services.end() )
            asd.service_candidates = sd.tcp_services[port];
    }
    else
    {
        if ( sd.udp_services.find(port) != sd.udp_services.end() )
            asd.service_candidates = sd.udp_services[port];
    }
}

/* This function should be called to find the next service detector to try when
 * we have not yet found a valid detector in the host tracker.  It will try
 * both port and/or pattern (but not brute force - that should be done outside
 * of this function).  This includes UDP reversed services.  A valid sds
 * (even if just initialized to the NEW state) should exist before calling this
 * function.  The state coming out of this function will reflect the state in
 * which the next detector was found.  If nothing is found, it'll indicate that
 * brute force should be tried next as a state (and return nullptr).  This
 * function can be called once or multiple times (to run multiple detectors in
 * parallel) per flow.  Do not call this function if a detector has already
 * been specified (service_detector).  Basically, this function handles going
 * through the main port/pattern search (and returning which detector to add
 * next to the list of detectors to try (even if only 1)). */
void ServiceDiscovery::get_next_service(const Packet* p, const AppidSessionDirection dir, AppIdSession& asd)
{
    auto proto = asd.protocol;

    /* See if there are any port detectors to try.  If not, move onto patterns. */
    if ( asd.service_search_state == SESSION_SERVICE_SEARCH_STATE::PORT )
    {
        get_port_based_services(proto,
            (dir ==  APP_ID_FROM_RESPONDER) ? p->ptrs.sp : p->ptrs.dp, asd);
        asd.service_search_state = SESSION_SERVICE_SEARCH_STATE::PATTERN;
    }

    if ( asd.service_search_state == SESSION_SERVICE_SEARCH_STATE::PATTERN)
    {
        /* If we haven't found anything yet, try to see if we get any hits
         * first with UDP reversed services before moving onto pattern matches. */
        if (dir == APP_ID_FROM_INITIATOR)
        {
            if ( (proto == IpProtocol::UDP) and !asd.tried_reverse_service and
                 !asd.get_session_flags(APPID_SESSION_ADDITIONAL_PACKET) )
            {
                asd.tried_reverse_service = true;
                ServiceDiscoveryState* rsds = AppIdServiceState::get(p->ptrs.ip_api.get_src(),
                    proto, p->ptrs.sp, p->get_ingress_group(), p->pkth->address_space_id,
                    asd.is_decrypted());
                std::unordered_map<uint16_t, std::vector<ServiceDetector*>>::iterator urs_iterator;
                if ( rsds && rsds->get_service() )
                    asd.service_candidates.emplace_back(rsds->get_service());
                else if ( ( urs_iterator = udp_reversed_services.find(p->ptrs.sp) )
                          != udp_reversed_services.end() and !urs_iterator->second.empty() )
                {
                    asd.service_candidates.insert(asd.service_candidates.end(),
                        urs_iterator->second.begin(),
                        urs_iterator->second.end());
                }
                else if ( p->dsize )
                {
                    match_by_pattern(asd, p, proto);
                }
                return;
            }
        }
        else
        {
            match_by_pattern(asd, p, proto);
            asd.service_search_state = SESSION_SERVICE_SEARCH_STATE::PENDING;
            return;
        }
    }
}

int ServiceDiscovery::identify_service(AppIdSession& asd, Packet* p,
    AppidSessionDirection dir, AppidChangeBits& change_bits)
{
    ServiceDiscoveryState* sds = nullptr;
    bool got_brute_force = false;
    const SfIp* ip;
    uint16_t port;
    int16_t group;

    /* Get packet info. */
    auto proto = asd.protocol;
    if ( asd.is_service_ip_set() )
        std::tie(ip, port, group) = asd.get_server_info();
    else
    {
        if ( dir == APP_ID_FROM_RESPONDER )
        {
            ip   = p->ptrs.ip_api.get_src();
            port = p->ptrs.sp;
            group = p->get_ingress_group();
        }
        else
        {
            ip   = p->ptrs.ip_api.get_dst();
            port = p->ptrs.dp;
            group = p->get_egress_group();
        }
        asd.set_server_info(*ip, port, group);
    }

    if ( asd.service_search_state == SESSION_SERVICE_SEARCH_STATE::START )
    {
        asd.service_search_state = SESSION_SERVICE_SEARCH_STATE::PORT;
        sds = AppIdServiceState::add(ip, proto, port, group, asd.asid,
            asd.is_decrypted(), true);
        sds->set_reset_time(0);
        ServiceState sds_state = sds->get_state();

        if ( sds_state == ServiceState::FAILED )
        {
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s No service match, failed state\n", appidDebug->get_debug_session());
            fail_service(asd, p, dir, nullptr, sds);
            return APPID_NOMATCH;
        }

        if ( !asd.service_detector )
        {
            /* If a valid service already exists in host tracker, give it a try. */
            if ( sds_state == ServiceState::VALID )
                asd.service_detector = sds->get_service();
            /* If we've gotten to brute force, give next detector a try. */
            else if ( sds_state == ServiceState::SEARCHING_BRUTE_FORCE and
                asd.service_candidates.empty() )
            {
                asd.service_detector = sds->select_detector_by_brute_force(proto,
                    asd.get_odp_ctxt().get_service_disco_mgr());
                got_brute_force = true;
            }
        }
    }

    int ret = APPID_NOMATCH;
    bool got_incompatible_service = false;
    bool got_fail_service = false;
    AppIdDiscoveryArgs args(p->data, p->dsize, dir, asd, p, change_bits);
    /* If we already have a service to try, then try it out. */
    if ( asd.service_detector )
    {
        ret = asd.service_detector->validate(args);
        if (ret == APPID_NOMATCH)
            got_fail_service = true;
        else if (ret == APPID_NOT_COMPATIBLE)
            got_incompatible_service = true;
        asd.service_search_state = SESSION_SERVICE_SEARCH_STATE::PENDING;
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s %s service detector returned %s (%d)\n",
                appidDebug->get_debug_session(), asd.service_detector->get_log_name().c_str(),
                asd.service_detector->get_code_string((APPID_STATUS_CODE)ret), ret);
    }
    /* Try to find detectors based on ports and patterns. */
    else if (!got_brute_force)
    {
        /* See if we've got more detector(s) to add to the candidate list. */
        if ( ( asd.service_search_state == SESSION_SERVICE_SEARCH_STATE::PORT )
            || ( ( asd.service_search_state == SESSION_SERVICE_SEARCH_STATE::PATTERN )
            && (dir == APP_ID_FROM_RESPONDER ) ) )
        {
            get_next_service(p, dir, asd);
        }

        /* Run all of the detectors that we currently have. */
        ret = APPID_INPROCESS;
        auto it = asd.service_candidates.begin();
        while ( it != asd.service_candidates.end() )
        {
            ServiceDetector* service = (ServiceDetector*)*it;
            int result;

            result = service->validate(args);
            if ( appidDebug->is_active() )
                LogMessage("AppIdDbg %s %s service candidate returned %s (%d)\n",
                    appidDebug->get_debug_session(), service->get_log_name().c_str(),
                    service->get_code_string((APPID_STATUS_CODE)result), result);

            if ( result == APPID_SUCCESS )
            {
                ret = APPID_SUCCESS;
                asd.service_detector = service;
                asd.service_candidates.clear();
                break;    /* done */
            }
            else
            {
                if ( result == APPID_NOT_COMPATIBLE )
                    got_incompatible_service = true;
                if (result != APPID_INPROCESS)    /* fail */
                    it = asd.service_candidates.erase(it);
                else
                    ++it;
            }
        }

        /* If we tried everything and found nothing, then fail. */
        if ( asd.service_candidates.empty() and ret != APPID_SUCCESS and
             ( asd.service_search_state == SESSION_SERVICE_SEARCH_STATE::PENDING ) )
        {
            // FIXIT-E: For now, wait for snort service inspection only for TCP. In the future,
            // if AppId rolls any of its UDP detectors into service inspectors, the UDP condition
            // below needs to be removed.
            if (asd.has_no_service_inspector() or (proto == IpProtocol::UDP))
                got_fail_service = true;
            else if (appidDebug->is_active() and !asd.service_detector and !asd.has_no_service_candidate())
                LogMessage("AppIdDbg %s No service candidate, wait for snort service inspection\n",
                    appidDebug->get_debug_session());

            asd.set_no_service_candidate();
        }
    }

    /* Failed all candidates, or no detector identified after seeing bidirectional exchange */
    if ( got_fail_service or ( ( ret != APPID_INPROCESS ) and
         !asd.service_detector and ( dir == APP_ID_FROM_RESPONDER ) ) )
    {
        if (!sds)
            sds = AppIdServiceState::add(ip, proto, port, group, asd.asid,
                asd.is_decrypted(), true);
        // Don't log this if fail service is not due to empty list
        if (appidDebug->is_active() and !(got_fail_service and asd.service_detector))
            LogMessage("AppIdDbg %s No service %s\n", appidDebug->get_debug_session(),
                got_fail_service ? "candidate" : "detector");
        got_fail_service = true;
        fail_service(asd, p, dir, nullptr, sds);
        ret = APPID_NOMATCH;
    }

    /* Handle failure exception cases in states. */
    if ( ( ( got_fail_service and !got_brute_force ) or got_incompatible_service ) and
         ( ret != APPID_INPROCESS ) and ( ret != APPID_SUCCESS ) )
    {
        const SfIp* tmp_ip;
        if (dir == APP_ID_FROM_RESPONDER)
            tmp_ip = p->ptrs.ip_api.get_dst();
        else
            tmp_ip = p->ptrs.ip_api.get_src();

        if (!sds)
            sds = AppIdServiceState::add(ip, proto, port, group, asd.asid,
                asd.is_decrypted(), true);

        if (got_incompatible_service)
            sds->update_service_incompatible(tmp_ip);

        sds->set_service_id_failed(asd, tmp_ip);
    }

    return ret;
}

int ServiceDiscovery::add_ftp_service_state(AppIdSession& asd)
{
    if (!ftp_service)
        return -1;
    return asd.add_flow_data_id(21, ftp_service);
}

void ServiceDiscovery::clear_ftp_service_state()
{
    ftp_service = nullptr;
}

bool ServiceDiscovery::do_service_discovery(AppIdSession& asd, Packet* p,
    AppidSessionDirection direction, AppidChangeBits& change_bits)
{
    bool is_discovery_done = false;
    uint32_t prev_service_state = asd.service_disco_state;
    AppId tp_app_id = asd.get_tp_app_id();

    if (asd.service_disco_state == APPID_DISCO_STATE_NONE and p->dsize)
    {
        if (p->flow->get_session_flags() & SSNFLAG_MIDSTREAM)
        {
            // Unless it could be ftp control
            if ( asd.protocol == IpProtocol::TCP and ( p->ptrs.sp == 21 or p->ptrs.dp == 21 )
                and !( p->ptrs.tcph->is_fin() or p->ptrs.tcph->is_rst() ) )
            {
                asd.set_session_flags(APPID_SESSION_CLIENT_DETECTED |
                    APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_SERVICE_DETECTED);
                if ( !ServiceDiscovery::add_ftp_service_state(asd) )
                {
                    asd.set_session_flags(APPID_SESSION_CONTINUE);
                }
                asd.service_disco_state = APPID_DISCO_STATE_STATEFUL;
            }
            else
            {
                asd.set_session_flags(APPID_SESSION_SERVICE_DETECTED);
                asd.service_disco_state = APPID_DISCO_STATE_FINISHED;

                if (asd.get_payload_id() == APP_ID_NONE and
                    (asd.is_tp_appid_available() or asd.get_session_flags(APPID_SESSION_NO_TPI)))
                    asd.set_payload_id(APP_ID_UNKNOWN);
            }
        }
        else
        {
            asd.service_disco_state = APPID_DISCO_STATE_STATEFUL;
        }
    }

    //stop inspection as soon as tp has classified a valid AppId later in the session
    if ( tp_app_id > APP_ID_NONE and
         asd.service_disco_state == APPID_DISCO_STATE_STATEFUL and
         prev_service_state == APPID_DISCO_STATE_STATEFUL and
         !asd.get_session_flags(APPID_SESSION_NO_TPI) and
         asd.is_tp_appid_available() )
    {
        AppInfoTableEntry* entry = asd.get_odp_ctxt().get_app_info_mgr().get_app_info_entry(tp_app_id);
        if ( entry && entry->service_detector &&
            !(entry->flags & APPINFO_FLAG_SERVICE_ADDITIONAL) )
        {
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s Stop service detection\n", appidDebug->get_debug_session());
            asd.stop_service_inspection(p, direction);
        }
    }

    if (asd.service_disco_state != APPID_DISCO_STATE_FINISHED)
    {
        bool service_found = identify_service(asd, p, direction, change_bits) == APPID_SUCCESS;
        is_discovery_done = true;

        // Check to see if we want to stop any detectors for SIP/RTP.
        if (tp_app_id == APP_ID_SIP)
        {
            // TP needs to see its own future flows and does a better
            // job of it than we do, so stay out of its way, and don't
            // waste time (but we will still get the Snort callbacks
            // for any of our own future flows). Shut down our detectors.
            asd.set_service_id(APP_ID_SIP, asd.get_odp_ctxt());
            asd.stop_service_inspection(p, direction);
            asd.service_disco_state = APPID_DISCO_STATE_FINISHED;
        }
        else if ((tp_app_id == APP_ID_RTP) or (tp_app_id == APP_ID_RTP_AUDIO) or
            (tp_app_id == APP_ID_RTP_VIDEO))
        {
            // No need for anybody to keep wasting time once we've
            // found RTP - Shut down our detectors.
            asd.set_service_id(tp_app_id, asd.get_odp_ctxt());
            asd.stop_service_inspection(p, direction);
            asd.service_disco_state = APPID_DISCO_STATE_FINISHED;
            //  - Shut down TP.

            asd.tpsession->set_state(TP_STATE_TERMINATED);
            //  - Just ignore everything from now on.
            asd.set_session_flags(APPID_SESSION_FUTURE_FLOW);
        }

        if (!service_found and tp_app_id > APP_ID_NONE and asd.is_tp_appid_available() and
            asd.service_disco_state != APPID_DISCO_STATE_FINISHED)
        {
            // Third party has positively identified appId; Dig deeper only if our
            // detector identifies additional information or flow is UDP reversed.
            AppInfoTableEntry* entry = asd.get_odp_ctxt().get_app_info_mgr().get_app_info_entry(tp_app_id);
            if ( entry and entry->service_detector and
                ( ( entry->flags & APPINFO_FLAG_SERVICE_ADDITIONAL ) or
                ( ( entry->flags & APPINFO_FLAG_SERVICE_UDP_REVERSED ) and
                asd.protocol == IpProtocol::UDP and
                asd.get_session_flags(APPID_SESSION_INITIATOR_MONITORED |
                APPID_SESSION_RESPONDER_MONITORED) ) ) )
            {
                if (asd.service_candidates.empty() and !asd.service_detector)
                    asd.free_flow_data_by_mask(APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);
                asd.service_detector = entry->service_detector;
            }
            else if (prev_service_state == APPID_DISCO_STATE_NONE)
            {
                asd.stop_service_inspection(p, direction);
            }
        }
    }

    if (asd.service_disco_state == APPID_DISCO_STATE_STATEFUL)
    {
        //to stop executing validator after service has been detected
        if (asd.get_session_flags(APPID_SESSION_SERVICE_DETECTED |
            APPID_SESSION_CONTINUE) == APPID_SESSION_SERVICE_DETECTED)
        {
            asd.service_disco_state = APPID_DISCO_STATE_FINISHED;
            if ( asd.get_payload_id() == APP_ID_NONE and
                 ( asd.is_tp_appid_available() or
                   asd.get_session_flags(APPID_SESSION_NO_TPI) ) )
            {
                asd.set_payload_id(APP_ID_UNKNOWN);
            }
        }

        /* If the session appears to only have the client sending data then
           we must mark the service unknown to prevent pending forever. */
        if (asd.service_disco_state == APPID_DISCO_STATE_STATEFUL and
            asd.get_service_id() == APP_ID_NONE and asd.is_svc_taking_too_much_time())
        {
                asd.stop_service_inspection(p, direction);
                asd.set_service_id(APP_ID_UNKNOWN, asd.get_odp_ctxt());
                return is_discovery_done;
        }

        AppIdDnsSession* dsession = asd.get_dns_session();
        if (dsession and asd.get_service_id() == APP_ID_DNS
            and asd.get_odp_ctxt().dns_host_reporting and dsession->get_host())
        {
            AppId client_id = APP_ID_NONE;
            AppId payload_id = APP_ID_NONE;
            asd.get_odp_ctxt().get_dns_matchers().scan_hostname((const uint8_t*)(dsession->get_host()),
                dsession->get_host_len(), client_id, payload_id);
            asd.set_client_appid_data(client_id, change_bits);
            asd.set_payload_appid_data(payload_id);
        }
        else if (asd.get_service_id() == APP_ID_RTMP)
            asd.examine_rtmp_metadata(change_bits);
        else if (asd.get_session_flags(APPID_SESSION_SSL_SESSION) and asd.tsession)
            asd.examine_ssl_metadata(change_bits);

        if (tp_app_id <= APP_ID_NONE and asd.get_session_flags(
            APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_NOT_A_SERVICE |
            APPID_SESSION_IGNORE_HOST) == APPID_SESSION_SERVICE_DETECTED)
        {
            asd.sync_with_snort_protocol_id(asd.get_service_id(), p);
        }
    }

    return is_discovery_done;
}

/**Called when service can not be identified on a flow but the checks failed on client request
 * rather than server response. When client request fails a check, it may be specific to a client
 * therefore we should not fail the service right away. If the same behavior is seen from the same
 * client ultimately we will have to fail the service. If the same behavior is seen from different
 * clients going to same service then this most likely the service is something else.
 */
int ServiceDiscovery::incompatible_data(AppIdSession& asd, const Packet* pkt, AppidSessionDirection dir,
    ServiceDetector* service)
{
    if (service)
        asd.free_flow_data_by_id(service->get_flow_data_index());

    // ignore fails while searching with port/pattern selected detectors
    if ( !asd.service_detector && !asd.service_candidates.empty() )
        return APPID_SUCCESS;

    asd.set_service_detected();
    asd.clear_session_flags(APPID_SESSION_CONTINUE);
    asd.set_service_id(APP_ID_NONE, asd.get_odp_ctxt());

    if ( asd.get_session_flags(APPID_SESSION_IGNORE_HOST | APPID_SESSION_UDP_REVERSED) )
        return APPID_SUCCESS;

    if ( dir == APP_ID_FROM_INITIATOR )
    {
        asd.set_session_flags(APPID_SESSION_INCOMPATIBLE);
        return APPID_SUCCESS;
    }

    const SfIp* ip = pkt->ptrs.ip_api.get_src();
    int16_t group = pkt->get_ingress_group();
    uint16_t port = asd.get_service_port();
    if (!port)
        port = pkt->ptrs.sp;

    ServiceDiscoveryState* sds = AppIdServiceState::add(ip, asd.protocol, port,
        group, pkt->pkth->address_space_id, asd.is_decrypted());     // do not touch here
    sds->set_service(service);
    sds->set_reset_time(0);
    if ( !asd.is_service_ip_set() )
        asd.set_server_info(*ip, port, group);

    return APPID_SUCCESS;
}

int ServiceDiscovery::fail_service(AppIdSession& asd, const Packet* pkt, AppidSessionDirection dir,
    ServiceDetector* service, ServiceDiscoveryState* sds)
{
    if ( service )
        asd.free_flow_data_by_id(service->get_flow_data_index());

    /* If we're still working on a port/pattern list of detectors, then ignore
     * individual fails until we're done looking at everything. */
    if ((asd.get_odp_ctxt().first_pkt_service_id > APP_ID_NONE) or (!asd.service_detector && !asd.service_candidates.empty()))
        return APPID_SUCCESS;

    asd.set_service_id(APP_ID_NONE, asd.get_odp_ctxt());
    asd.set_service_detected();
    asd.clear_session_flags(APPID_SESSION_CONTINUE);

    /* Detectors should be careful in marking session UDP_REVERSED otherwise the same detector
     * gets all future flows. UDP_REVERSE should be marked only when detector positively
     * matches opposite direction patterns. */
    if ( asd.get_session_flags(APPID_SESSION_IGNORE_HOST | APPID_SESSION_UDP_REVERSED) )
        return APPID_SUCCESS;

    /* For subsequent packets, avoid marking service failed on client packet,
     * otherwise the service will show up on client side. */
    if (dir == APP_ID_FROM_INITIATOR)
    {
        asd.set_session_flags(APPID_SESSION_INCOMPATIBLE);
        return APPID_SUCCESS;
    }

    const SfIp* ip = pkt->ptrs.ip_api.get_src();
    uint16_t port = asd.get_service_port();
    int16_t group = pkt->get_ingress_group();

    if (!port)
        port = pkt->ptrs.sp;

    if (!asd.is_service_ip_set())
        asd.set_server_info(*ip, port, group);

    if ( !sds )
    {
        sds = AppIdServiceState::add(ip, asd.protocol, port, group,
            asd.asid, asd.is_decrypted());
        sds->set_service(service);
    }
    sds->set_reset_time(0);

    return APPID_SUCCESS;
}

