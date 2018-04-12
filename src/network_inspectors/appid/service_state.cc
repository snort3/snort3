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

// service_state.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_state.h"

#include <map>

#include "log/messages.h"
#include "sfip/sf_ip.h"
#include "time/packet_time.h"
#include "utils/util.h"

#include "appid_debug.h"
#include "service_plugins/service_detector.h"

using namespace snort;

ServiceDiscoveryState::ServiceDiscoveryState()
{
    state = SERVICE_ID_STATE::SEARCHING_PORT_PATTERN;
    last_detract.clear();
    last_invalid_client.clear();
    reset_time = 0;
}

ServiceDiscoveryState::~ServiceDiscoveryState()
{
    delete tcp_brute_force_mgr;
    delete udp_brute_force_mgr;
}

ServiceDetector* ServiceDiscoveryState::select_detector_by_brute_force(IpProtocol proto)
{
    if (proto == IpProtocol::TCP)
    {
        if ( !tcp_brute_force_mgr )
            tcp_brute_force_mgr = new AppIdDetectorList(IpProtocol::TCP);
        service = tcp_brute_force_mgr->next();
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Brute-force state %s\n", appidDebug->get_debug_session(),
                service? "" : "failed - no more TCP detectors");
    }
    else if (proto == IpProtocol::UDP)
    {
        if ( !udp_brute_force_mgr )
            udp_brute_force_mgr = new AppIdDetectorList(IpProtocol::UDP);
        service = udp_brute_force_mgr->next();
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Brute-force state %s\n", appidDebug->get_debug_session(),
                service? "" : "failed - no more UDP detectors");
    }
    else
        service = nullptr;

    if ( !service )
        state = SERVICE_ID_STATE::FAILED;

    return service;
}

void ServiceDiscoveryState::set_service_id_valid(ServiceDetector* sd)
{
    service = sd;
    reset_time = 0;
    if ( state != SERVICE_ID_STATE::VALID )
    {
        state = SERVICE_ID_STATE::VALID;
        valid_count = 0;
    }

    if ( !valid_count )
    {
        valid_count = 1;
        detract_count = 0;
        last_detract.clear();
        invalid_client_count = 0;
        last_invalid_client.clear();
    }
    else if ( valid_count < STATE_ID_MAX_VALID_COUNT)
        valid_count++;
}

/* Handle some exception cases on failure:
 *  - valid_count: If we have a detector that should be valid, but it keeps
 *    failing, consider restarting the detector search.
 *  - invalid_client_count: If our service detector search had trouble
 *    simply because of unrecognized client data, then consider retrying
 *    the search again. */
void ServiceDiscoveryState::set_service_id_failed(AppIdSession& asd, const SfIp* client_ip,
    unsigned invalid_delta)
{
    invalid_client_count += invalid_delta;

    /* If we had a valid detector, check for too many fails.  If so, start
     * search sequence again. */
    if ( state == SERVICE_ID_STATE::VALID )
    {
        /* Too many invalid clients?  If so, count it as an invalid detect. */
        if ( invalid_client_count >= STATE_ID_INVALID_CLIENT_THRESHOLD )
        {
            if ( valid_count <= 1 )
            {
                state = SERVICE_ID_STATE::SEARCHING_PORT_PATTERN;
                invalid_client_count = 0;
                last_invalid_client.clear();
                valid_count = 0;
                detract_count = 0;
                last_detract.clear();
            }
            else
            {
                valid_count--;
                last_invalid_client = *client_ip;
                invalid_client_count = 0;
            }
        }
        else if ( invalid_client_count == 0 )
        {
            // Just a plain old fail.  If too many of these happen, start search process over.
            if (last_detract.fast_eq6(*client_ip))
                detract_count++;
            else
                last_detract = *client_ip;

            if (detract_count >= STATE_ID_NEEDED_DUPE_DETRACT_COUNT)
            {
                if (valid_count <= 1)
                {
                    state = SERVICE_ID_STATE::SEARCHING_PORT_PATTERN;
                    invalid_client_count = 0;
                    last_invalid_client.clear();
                    valid_count = 0;
                    detract_count = 0;
                    last_detract.clear();
                }
                else
                    valid_count--;
            }
        }
    }
    else if ( ( state == SERVICE_ID_STATE::SEARCHING_PORT_PATTERN ) and
        ( asd.service_search_state == SESSION_SERVICE_SEARCH_STATE::PENDING ) and
        asd.service_candidates.empty() and
        !asd.get_session_flags(APPID_SESSION_MID | APPID_SESSION_OOO) )
    {
        if ( ( asd.protocol == IpProtocol::TCP ) or ( asd.protocol == IpProtocol::UDP ) )
            state = SEARCHING_BRUTE_FORCE;
        else
            state = FAILED;
    }
}

void ServiceDiscoveryState::update_service_incompatiable(const SfIp* ip)
{
    if ( invalid_client_count < STATE_ID_INVALID_CLIENT_THRESHOLD )
    {
        if ( last_invalid_client.fast_equals_raw(*ip) )
            invalid_client_count++;
        else
        {
            invalid_client_count += 3;
            last_invalid_client = *ip;
        }
    }
}

class AppIdServiceStateKey
{
public:
    AppIdServiceStateKey()
    {
        ip.clear();
        port = 0;
        level = 0;
        proto = IpProtocol::PROTO_NOT_SET;
        padding[0] = padding[1] = padding[2] = 0;
    }

    bool operator<(AppIdServiceStateKey right) const
    {
        if ( ip.less_than(right.ip) )
            return true;
        else if ( right.ip.less_than(ip) )
            return false;
        else
        {
            if ( port < right.port )
                return true;
            else if ( right.port < port )
                return false;
            else if ( proto < right.proto )
                return true;
            else if ( right.proto < proto )
                return false;
            else if ( level < right.level )
                return true;
            else
                return false;
        }
    }

    SfIp ip;
    uint16_t port;
    uint32_t level;
    IpProtocol proto;
    char padding[3];
};

static THREAD_LOCAL std::map<AppIdServiceStateKey, ServiceDiscoveryState*>* service_state_cache =
    nullptr;

void AppIdServiceState::initialize()
{
    service_state_cache = new std::map<AppIdServiceStateKey, ServiceDiscoveryState*>;
}

void AppIdServiceState::clean()
{
    if ( service_state_cache )
    {
        for ( auto& kv : *service_state_cache )
            delete kv.second;

        service_state_cache->clear();
        delete service_state_cache;
        service_state_cache = nullptr;
    }
}

ServiceDiscoveryState* AppIdServiceState::add(const SfIp* ip, IpProtocol proto, uint16_t port,
    bool decrypted)
{
    AppIdServiceStateKey ssk;
    ServiceDiscoveryState* ss = nullptr;

    ssk.ip.set(*ip);
    ssk.proto = proto;
    ssk.port = port;
    ssk.level = decrypted ? 1 : 0;

    std::map<AppIdServiceStateKey, ServiceDiscoveryState*>::iterator it;
    it = service_state_cache->find(ssk);
    if ( it == service_state_cache->end() )
    {
        ss = new ServiceDiscoveryState;
        (*service_state_cache)[ssk] = ss;
    }
    else
        ss = it->second;

    return ss;
}

ServiceDiscoveryState* AppIdServiceState::get(const SfIp* ip, IpProtocol proto, uint16_t port,
    bool decrypted)
{
    AppIdServiceStateKey ssk;
    ServiceDiscoveryState* ss = nullptr;

    ssk.ip.set(*ip);
    ssk.proto = proto;
    ssk.port = port;
    ssk.level = decrypted ? 1 : 0;

    std::map<AppIdServiceStateKey, ServiceDiscoveryState*>::iterator it;
    it = service_state_cache->find(ssk);
    if ( it != service_state_cache->end() )
        ss = it->second;

    return ss;
}

void AppIdServiceState::remove(const SfIp* ip, IpProtocol proto, uint16_t port, bool decrypted)
{
    AppIdServiceStateKey ssk;

    ssk.ip.set(*ip);
    ssk.proto = proto;
    ssk.port = port;
    ssk.level = decrypted ? 1 : 0;

    std::map<AppIdServiceStateKey, ServiceDiscoveryState*>::iterator it;
    it = service_state_cache->find(ssk);
    if ( it != service_state_cache->end() )
    {
        delete it->second;
        service_state_cache->erase(it);
    }
    else
    {
        char ipstr[INET6_ADDRSTRLEN];

        ipstr[0] = 0;
        sfip_ntop(ip, ipstr, sizeof(ipstr));
        ErrorMessage("Failed to remove from hash: %s:%u:%hu\n", ipstr, (unsigned)proto, port);
    }
}

void AppIdServiceState::check_reset(AppIdSession& asd, const SfIp* ip, uint16_t port)
{
    ServiceDiscoveryState* sds = AppIdServiceState::get(ip, IpProtocol::TCP, port,
        asd.is_decrypted());
    if ( sds )
    {
        if ( !sds->get_reset_time() )
            sds->set_reset_time(packet_time() );
        else if ( ( packet_time() - sds->get_reset_time() ) >= 60 )
        {
            AppIdServiceState::remove(ip, IpProtocol::TCP, port, asd.is_decrypted());
            // FIXIT-L - Remove if this flag not used anywhere
            asd.set_session_flags(APPID_SESSION_SERVICE_DELETED);
        }
    }
}

void AppIdServiceState::dump_stats()
{
    // FIXIT-L - do we need to keep ipv4 and ipv6 separate?
#if 0
    LogMessage("Service State:\n");
    if (serviceStateCache4)
    {
        LogMessage("           IPv4 Count: %u\n", xhash_count(serviceStateCache4));
        LogMessage("    IPv4 Memory Limit: %lu\n", serviceStateCache4->mc.memcap);
        LogMessage("     IPv4 Memory Used: %lu\n", serviceStateCache4->mc.memused);
    }
    if (serviceStateCache6)
    {
        LogMessage("           IPv6 Count: %u\n", xhash_count(serviceStateCache6));
        LogMessage("    IPv6 Memory Limit: %lu\n", serviceStateCache6->mc.memcap);
        LogMessage("     IPv6 Memory Used: %lu\n", serviceStateCache6->mc.memused);
    }
#endif
}

