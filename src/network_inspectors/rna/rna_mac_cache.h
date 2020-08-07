//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
#include "host_tracker/host_cache_allocator.cc"
#include "host_tracker/host_cache_allocator.h"
#include "host_tracker/host_cache.h"
#include "host_tracker/host_tracker.h"
#include "sfip/sf_ip.h"

using snort::SfIp;

#define MAC_CACHE_INITIAL_SIZE 1024 * 1024 // Default to 1 MB

class HostMacIp : public snort::HostMac
{
public:
    HostMacIp (const uint8_t* p_mac, uint8_t p_primary, uint32_t p_last_seen)
        : snort::HostMac(0, p_mac, p_primary, p_last_seen), src_ip(nullptr), dst_ip(nullptr)
    { }

    HostMacIp (const uint8_t* p_mac, uint8_t p_primary, uint32_t p_last_seen,
        SfIp* src, SfIp* dst) : snort::HostMac(0, p_mac, p_primary, p_last_seen),
        src_ip(src), dst_ip(dst)
    { }

    SfIp* src_ip;
    SfIp* dst_ip;

    snort::HostType host_type;

    void update_vlan(uint16_t vth_pri_cfi_vlan, uint16_t vth_proto);
    bool has_vlan();
    uint16_t get_vlan();
    void get_vlan_details(uint8_t& cfi, uint8_t& priority, uint16_t& vid);

private:
    bool vlan_tag_present = false;
    snort::vlan::VlanTagHdr vlan_tag;
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

template <class T>
class HostCacheAllocMac : public HostCacheAlloc<T>
{
public:
    template <class U>
    struct rebind
    {
        typedef HostCacheAllocMac<U> other;
    };

    using HostCacheAlloc<T>::lru;

    HostCacheAllocMac();
};

class LruMac
{
public:
    typedef HostMacIp ValueType;
    std::vector<ValueType, HostCacheAllocMac<ValueType>> data;

    bool isempty()
    { return data.size() == 0; }

    void insert(HostMacIp *hmi)
    { data.emplace_back(*hmi); }

};

typedef LruCacheSharedMemcap<MacKey, LruMac, HashMac> HostCacheMac;
extern HostCacheMac host_cache_mac;

template <class T>
HostCacheAllocMac<T>::HostCacheAllocMac()
{
    lru = &host_cache_mac;
}
#endif
