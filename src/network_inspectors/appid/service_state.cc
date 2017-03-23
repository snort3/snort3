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

// service_state.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_state.h"

#include <map>

#include "service_plugins/service_detector.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"
#include "log/messages.h"

//#define DEBUG_SERVICE_STATE 1

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

// FIXIT-L - no memcap on size of this table, do we need that?
THREAD_LOCAL std::map<AppIdServiceStateKey, ServiceDiscoveryState*>* service_state_cache = nullptr;

void AppIdServiceState::initialize(unsigned long)
{
    service_state_cache = new std::map<AppIdServiceStateKey, ServiceDiscoveryState*>;
}

void AppIdServiceState::clean(void)
{
    if ( service_state_cache )
    {
        for ( auto& kv : *service_state_cache )
            delete kv.second;

        service_state_cache->empty();
        delete service_state_cache;
        service_state_cache = nullptr;
    }
}

ServiceDiscoveryState* AppIdServiceState::add(const SfIp* ip, IpProtocol proto, uint16_t port,
    uint32_t level)
{
    AppIdServiceStateKey ssk;
    ServiceDiscoveryState* ss = nullptr;

    ssk.ip.set(*ip);
    ssk.proto = proto;
    ssk.port = port;
    ssk.level = level;

    std::map<AppIdServiceStateKey, ServiceDiscoveryState*>::iterator it;
    it = service_state_cache->find(ssk);
    if ( it != service_state_cache->end())
    {
        ss = it->second;
    }
    else
    {
        ss = new ServiceDiscoveryState;
        (*service_state_cache)[ssk] = ss;
    }

#ifdef DEBUG_SERVICE_STATE
    char ipstr[INET6_ADDRSTRLEN];

    ipstr[0] = 0;
    sfip_ntop(ip, ipstr, sizeof(ipstr));
    DebugFormat(DEBUG_APPID, "ServiceState: Added to hash: %s:%u:%u:%u %p\n", ipstr,
        (unsigned)proto,
        (unsigned)port, level, (void*)ss);
#endif

    return ss;
}

ServiceDiscoveryState* AppIdServiceState::get(const SfIp* ip, IpProtocol proto, uint16_t port,
    uint32_t level)
{
    AppIdServiceStateKey ssk;
    ServiceDiscoveryState* ss = nullptr;
    char ipstr[INET6_ADDRSTRLEN];   // FIXIT-M ASAN reports mem leak on ServiceMatch* objects if
                                    // this is not defined
                                    //  which makes no sense, need to investigate further

    ssk.ip.set(*ip);
    ssk.proto = proto;
    ssk.port = port;
    ssk.level = level;

    std::map<AppIdServiceStateKey, ServiceDiscoveryState*>::iterator it;
    it = service_state_cache->find(ssk);
    if ( it != service_state_cache->end())
    {
        ss = it->second;
        if (ss->service && !ss->service->ref_count)
        {
            ss->service = nullptr;
            ss->state = SERVICE_ID_NEW;
        }
    }

#ifdef DEBUG_SERVICE_STATE
    ipstr[0] = 0;
    sfip_ntop(ip, ipstr, sizeof(ipstr));
    DebugFormat(DEBUG_APPID, "ServiceState: Read from hash: %s:%u:%u:%u %p %u %p\n", ipstr,
        (unsigned)proto,
        (unsigned)port, level, (void*)ss, ss ? ss->state : 0, ss ? (void*)ss->service : nullptr);
#else
    UNUSED(ipstr);
#endif

    return ss;
}

void AppIdServiceState::remove(const SfIp* ip, IpProtocol proto, uint16_t port, uint32_t level)
{
    AppIdServiceStateKey ssk;

    ssk.ip.set(*ip);
    ssk.proto = proto;
    ssk.port = port;
    ssk.level = level;

    std::map<AppIdServiceStateKey, ServiceDiscoveryState*>::iterator it;
    it = service_state_cache->find(ssk);
    if ( it != service_state_cache->end())
    {
        delete it->second;
        service_state_cache->erase(it);
    }
    else
    {
        char ipstr[INET6_ADDRSTRLEN];

        ipstr[0] = 0;
        sfip_ntop(ip, ipstr, sizeof(ipstr));
        ErrorMessage("Failed to remove from hash: %s:%u:%u\n", ipstr, (unsigned)proto, port);
    }
}

void AppIdServiceState::dump_stats(void)
{
    // FIXIT-L - do we need to keep ipv4 and ipv6 separate?
#if 0
    LogMessage("Service State:\n");
    if (serviceStateCache4)
    {
        LogMessage("           IPv4 Count: %u\n", sfxhash_count(serviceStateCache4));
        LogMessage("    IPv4 Memory Limit: %lu\n", serviceStateCache4->mc.memcap);
        LogMessage("     IPv4 Memory Used: %lu\n", serviceStateCache4->mc.memused);
    }
    if (serviceStateCache6)
    {
        LogMessage("           IPv6 Count: %u\n", sfxhash_count(serviceStateCache6));
        LogMessage("    IPv6 Memory Limit: %lu\n", serviceStateCache6->mc.memcap);
        LogMessage("     IPv6 Memory Used: %lu\n", serviceStateCache6->mc.memused);
    }
#endif
}

