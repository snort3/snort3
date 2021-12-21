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

// service_state.h author Sourcefire Inc.

#ifndef SERVICE_STATE_H
#define SERVICE_STATE_H

#include <list>
#include <map>

#include "protocols/protocol_ids.h"
#include "sfip/sf_ip.h"
#include "utils/cpp_macros.h"
#include "utils/util.h"

#include "appid_peg_counts.h"
#include "service_plugins/service_discovery.h"

class ServiceDetector;

struct AppIdServiceStateKey;
class ServiceDiscoveryState;

typedef std::map<AppIdServiceStateKey, ServiceDiscoveryState*> Map_t;
typedef std::list<Map_t::iterator> Queue_t;

enum ServiceState
{
    SEARCHING_PORT_PATTERN = 0,
    SEARCHING_BRUTE_FORCE,
    FAILED,
    VALID
};

class AppIdDetectorList
{
public:
    AppIdDetectorList(IpProtocol proto, ServiceDiscovery& sd)
    {
        if (proto == IpProtocol::TCP)
            detectors = sd.get_tcp_detectors();
        else
            detectors = sd.get_udp_detectors();
        dit = detectors->begin();
    }

    ServiceDetector* next()
    {
        ServiceDetector* detector = nullptr;

        if ( dit != detectors->end())
            detector = (ServiceDetector*)(dit++)->second;
        return detector;
    }

    void reset()
    {
        dit = detectors->begin();
    }

private:
    AppIdDetectors* detectors;
    AppIdDetectorsIterator dit;
};

class ServiceDiscoveryState
{
public:
    ServiceDiscoveryState();
    ~ServiceDiscoveryState();
    ServiceDetector* select_detector_by_brute_force(IpProtocol proto, ServiceDiscovery& sd);
    void set_service_id_valid(ServiceDetector* sd);
    void set_service_id_failed(AppIdSession& asd, const snort::SfIp* client_ip,
        unsigned invalid_delta = 0);
    void update_service_incompatible(const snort::SfIp* ip);

    ServiceState get_state() const
    {
        return state;
    }

    void set_state(ServiceState state)
    {
        this->state = state;
    }

    ServiceDetector* get_service() const
    {
        return service;
    }

    void set_service(ServiceDetector* service)
    {
        this->service = service;
    }

    time_t get_reset_time() const
    {
        return reset_time;
    }

    void set_reset_time(time_t resetTime)
    {
        reset_time = resetTime;
    }

    Queue_t::iterator qptr; // Our place in service_state_queue

private:
    ServiceState state;
    ServiceDetector* service = nullptr;
    AppIdDetectorList* tcp_brute_force_mgr = nullptr;
    AppIdDetectorList* udp_brute_force_mgr = nullptr;
    unsigned valid_count = 0;
    unsigned detract_count = 0;
    snort::SfIp last_detract;

    // consecutive incompatible flows - incompatible means client packet did not match.
    unsigned invalid_client_count = 0;

    /**IP address of client in last flow that was declared incompatible. If client IP address is
     * different every time, then consecutive incompatible status indicate that flow is not using
     * specific service.
     */
    snort::SfIp last_invalid_client;
    time_t reset_time;
};

class AppIdServiceState
{
public:
    static bool initialize(size_t memcap);
    static void clean();
    static ServiceDiscoveryState* add(const snort::SfIp*, IpProtocol, uint16_t port,
        int16_t group, uint16_t asid, bool decrypted, bool do_touch = false);
    static ServiceDiscoveryState* get(const snort::SfIp*, IpProtocol, uint16_t port,
        int16_t group, uint16_t asid, bool decrypted, bool do_touch = false);
    static void remove(const snort::SfIp*, IpProtocol, uint16_t port,
        int16_t group, uint16_t asid, bool decrypted);
    static void check_reset(AppIdSession& asd, const snort::SfIp* ip, uint16_t port,
        int16_t group, uint16_t asid);
    static bool prune(size_t max_memory = 0, size_t num_items = -1u);
};


PADDING_GUARD_BEGIN
struct AppIdServiceStateKey
{
    AppIdServiceStateKey(const snort::SfIp* ip,
        IpProtocol proto, uint16_t port, int16_t group, uint16_t asid, bool decrypted) :
        ip(*ip), port(port), group(group), asid(asid), decrypted(decrypted), proto(proto)
    { }

    bool operator<(const AppIdServiceStateKey& right) const
    {
        return memcmp((const uint8_t*) this, (const uint8_t*) &right, sizeof(*this)) < 0;
    }

    snort::SfIp ip;
    uint16_t port;
    int16_t group;
    uint16_t asid;
    bool decrypted;
    IpProtocol proto;
};
PADDING_GUARD_END


extern THREAD_LOCAL AppIdStats appid_stats;

class MapList
{
public:

    MapList(size_t cap) : memcap(cap), mem_used(0) {}

    ~MapList()
    {
        for ( auto& kv : m )
            delete kv.second;
    }

    ServiceDiscoveryState* add(const AppIdServiceStateKey& k, bool do_touch = false)
    {
        ServiceDiscoveryState* ss = nullptr;

        // Try to emplace k first, with a nullptr.
        std::pair<Map_t::iterator, bool> sit = m.emplace( std::make_pair(k, ss) );
        Map_t::iterator it = sit.first;

        if ( sit.second )
        {
            // emplace succeeded
            ss = it->second = new ServiceDiscoveryState;
            q.emplace_back(it);
            mem_used += sz;
            ss->qptr = --q.end(); // remember our place in the queue
            appid_stats.service_cache_adds++;

            if ( mem_used > memcap )
                remove( q.front() );
        }
        else
        {
            ss = it->second;
            if ( do_touch )
                touch( ss->qptr );
        }

        return ss;
    }

    ServiceDiscoveryState* get(const AppIdServiceStateKey& k, bool do_touch = false)
    {
        Map_t::const_iterator it = m.find(k);
        if ( it != m.end() ) {
            if ( do_touch )
                touch(it->second->qptr);
            return it->second;
        }
        return nullptr;
    }

    bool remove(Map_t::iterator it)
    {
        if ( it != m.end() && !m.empty() )
        {
            assert( mem_used >= sz );
            mem_used -= sz;
            q.erase(it->second->qptr);  // remove from queue
            delete it->second;
            m.erase(it);                // then from cache
            appid_stats.service_cache_removes++;

            return true;
        }
        return false;
    }

    bool prune(size_t max_memory = 0, size_t num_items = -1u)
    {
        if ( max_memory == 0 )
            max_memory = memcap;

        size_t i=0;
        while ( mem_used > max_memory && i++ < num_items )
            remove( q.front() );

        appid_stats.service_cache_prunes++;

        return mem_used <= max_memory;
    }

    Map_t::iterator find(const AppIdServiceStateKey& k)
    {
        return m.find(k);
    }

    void touch(Queue_t::iterator& qptr)
    {
        // If we don't already have the highest priority...
        if ( *qptr != q.back() )
        {
            q.emplace_back(*qptr);
            q.erase(qptr);
            qptr = --q.end();
        }
    }

    size_t size() const { return m.size(); }

    Queue_t::iterator newest() { return --q.end(); }
    Queue_t::iterator oldest() { return q.begin(); }
    Queue_t::iterator end() { return q.end(); }

    // how much memory we add when we put an SDS in the cache:
    static const size_t sz;

    friend class AppIdServiceState;

private:
    Map_t m;
    Queue_t q;
    size_t memcap;
    size_t mem_used;
};

#endif
