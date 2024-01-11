//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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

// rna_mac_cache.h author Michael Matirko <mmatirko@cisco.com>

#ifndef RNA_MAC_CACHE
#define RNA_MAC_CACHE

#include "hash/hash_key_operations.h"
// Non-standard, required to include template definition across compiler translation units
#include "host_tracker/cache_allocator.cc"
#include "host_tracker/cache_allocator.h"

#define MAC_CACHE_INITIAL_SIZE 1024 * 1024 // Default to 1 MB

template <class T>
class HostCacheAllocMac : public CacheAlloc<T>
{
public:
    template <class U>
    struct rebind
    {
        typedef HostCacheAllocMac<U> other;
    };

    using CacheAlloc<T>::lru;

    HostCacheAllocMac();
};

class HostTrackerMac
{
public:
    HostTrackerMac()
    { last_seen = (uint32_t) snort::packet_time(); }

    bool add_network_proto(const uint16_t type);
    void update_last_seen(uint32_t p_last_seen);
    void update_vlan(uint16_t vth_pri_cfi_vlan, uint16_t vth_proto);
    bool has_vlan();
    bool has_same_vlan(uint16_t);
    void get_vlan_details(uint8_t& cfi, uint8_t& priority, uint16_t& vid);

    std::vector<uint16_t, HostCacheAllocMac<uint16_t>> get_network_protos()
    {
        std::lock_guard<std::mutex> lck(host_tracker_mac_lock);
        return network_protos;
    }

    uint16_t get_vlan();

    uint32_t get_last_seen()
    {
        std::lock_guard<std::mutex> lck(host_tracker_mac_lock);
        return last_seen;
    }

    uint32_t get_last_event()
    {
        std::lock_guard<std::mutex> lck(host_tracker_mac_lock);
        return last_event;
    }

    bool delete_proto(uint16_t proto)
    {
        std::lock_guard<std::mutex> lck(host_tracker_mac_lock);

        for (auto it = network_protos.begin(); it != network_protos.end(); ++it)
        {
            if (*it == proto)
            {
                network_protos.erase(it);
                return true;
            }
        }

        return false;
    }

    void update_last_seen()
    {
        std::lock_guard<std::mutex> lck(host_tracker_mac_lock);
        last_seen = (uint32_t) snort::packet_time();
    }

    void update_last_event(uint32_t event_time)
    {
        std::lock_guard<std::mutex> lck(host_tracker_mac_lock);
        last_event = event_time ? event_time : last_seen;
    }

    // This should be updated whenever HostTrackerMac data members are changed
    void stringify(std::string& str);

    snort::HostType host_type = snort::HostType::HOST_TYPE_HOST;

private:
    std::mutex host_tracker_mac_lock;
    uint32_t last_seen = 0;
    uint32_t last_event = 0;
    bool vlan_tag_present = false;
    snort::vlan::VlanTagHdr vlan_tag = { };
    std::vector<uint16_t, HostCacheAllocMac<uint16_t>> network_protos;
};

class MacKey
{
public:
    MacKey(const uint8_t *ma)
    { memcpy(mac_addr, ma, MAC_SIZE); }

    bool operator==(const MacKey& mk) const
    {
        return !(memcmp(mac_addr, mk.mac_addr, MAC_SIZE));
    }

    uint8_t mac_addr[MAC_SIZE];
};

struct HashMac
{
    uint64_t operator()(const MacKey& mk) const
    { return snort::hash_mac(mk.mac_addr); }
};

typedef LruCacheSharedMemcap<MacKey, HostTrackerMac, HashMac> HostCacheMac;

extern HostCacheMac* get_host_cache_mac();

template <class T>
HostCacheAllocMac<T>::HostCacheAllocMac()
{
    lru = get_host_cache_mac();
}
#endif
