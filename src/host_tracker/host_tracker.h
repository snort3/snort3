//--------------------------------------------------------------------------
// Copyright (C) 2015-2019 Cisco and/or its affiliates. All rights reserved.
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

// host_tracker.h author Steve Chew <stechew@cisco.com>

#ifndef HOST_TRACKER_H
#define HOST_TRACKER_H

// The HostTracker class holds information known about a host (may be from
// configuration or dynamic discovery).  It provides a thread-safe API to
// set/get the host data.

#include <cstring>
#include <mutex>
#include <list>
#include <vector>

#include "framework/counts.h"
#include "host_cache_allocator.h"
#include "main/snort_types.h"
#include "main/thread.h"
#include "network_inspectors/appid/application_ids.h"
#include "protocols/protocol_ids.h"
#include "time/packet_time.h"

struct HostTrackerStats
{
    PegCount service_adds;
    PegCount service_finds;
};

extern THREAD_LOCAL struct HostTrackerStats host_tracker_stats;

namespace snort
{
#define MAC_SIZE 6
extern const uint8_t zero_mac[MAC_SIZE];

struct HostMac
{
    HostMac(u_int8_t p_ttl, const u_int8_t* p_mac, u_int8_t p_primary, uint32_t p_last_seen)
        : ttl(p_ttl), primary(p_primary), last_seen (p_last_seen) { memcpy(mac, p_mac, MAC_SIZE); }

    // the type and order below should match logger's serialization
    u_int8_t ttl;
    u_int8_t mac[MAC_SIZE];
    u_int8_t primary;
    uint32_t last_seen;
};

struct HostApplication
{
    Port port;
    IpProtocol proto;
    AppId appid;
    bool inferred_appid;
};

typedef HostCacheAllocIp<HostMac> HostMacAllocator;
typedef HostCacheAllocIp<HostApplication> HostAppAllocator;

class SO_PUBLIC HostTracker
{
public:
    HostTracker() : hops(-1)
    {
        last_seen = (uint32_t) packet_time();
        last_event = -1;
    }

    void update_last_seen();
    uint32_t get_last_seen() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return last_seen;
    }

    void update_last_event(uint32_t time = 0);
    uint32_t get_last_event() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return last_event;
    }

    // Returns true if a new mac entry is added, false otherwise
    bool add_mac(const u_int8_t* mac, u_int8_t ttl, u_int8_t primary);

    // The caller owns and deletes the copied list of mac addresses
    void copy_data(uint8_t& p_hops, uint32_t& p_last_seen, std::list<HostMac>*& p_macs);

    // Appid may not be identified always. Inferred means dynamic/runtime
    // appid detected from one flow to another flow such as BitTorrent.
    bool add_service(Port port, IpProtocol proto,
        AppId appid = APP_ID_NONE, bool inferred_appid = false, bool* added = nullptr);

    AppId get_appid(Port port, IpProtocol proto, bool inferred_only = false, bool allow_port_wildcard = false);

    //  This should be updated whenever HostTracker data members are changed
    void stringify(std::string& str);

private:
    mutable std::mutex host_tracker_lock; // ensure that updates to a shared object are safe
    uint8_t hops;                 // hops from the snort inspector, e.g., zero for ARP
    uint32_t last_seen;           // the last time this host was seen
    uint32_t last_event;          // the last time an event was generated
    std::list<HostMac, HostMacAllocator> macs;
    std::vector<HostApplication, HostAppAllocator> services;

    // Hide / delete the constructor from the outside world. We don't want to
    // have zombie host trackers, i.e. host tracker objects that live outside
    // the host cache.
    HostTracker( const HostTracker& ) = delete;
    HostTracker( const HostTracker&& ) = delete;

    HostTracker& operator=( const HostTracker& ) = delete;
    HostTracker& operator=( const HostTracker&& ) = delete;

    // Only the host cache can create them ...
    template<class Key, class Value, class Hash>
    friend class LruCacheShared;

    // ... and some unit tests. See Utest.h and UtestMacros.h in cpputest.
    friend class TEST_host_tracker_add_find_service_test_Test;
    friend class TEST_host_tracker_stringify_Test;
};
} // namespace snort
#endif
