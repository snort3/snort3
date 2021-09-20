//--------------------------------------------------------------------------
// Copyright (C) 2020-2021 Cisco and/or its affiliates. All rights reserved.
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

// rna_mac_cache.cc author Michael Matirko <mmatirko@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "rna_mac_cache.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;
using namespace std;

bool HostTrackerMac::add_network_proto(const uint16_t type)
{
    lock_guard<mutex> lck(host_tracker_mac_lock);

    for ( const auto& proto : network_protos )
        if ( proto == type )
            return false;

    network_protos.emplace_back(type);
    return true;
}

void HostTrackerMac::update_last_seen(uint32_t p_last_seen)
{
    lock_guard<mutex> lck(host_tracker_mac_lock);
    last_seen = p_last_seen;
}

void HostTrackerMac::update_vlan(uint16_t vth_pri_cfi_vlan, uint16_t vth_proto)
{
    lock_guard<mutex> lck(host_tracker_mac_lock);

    vlan_tag_present = true;
    vlan_tag.vth_pri_cfi_vlan = vth_pri_cfi_vlan;
    vlan_tag.vth_proto = vth_proto;
}

bool HostTrackerMac::has_vlan()
{
    lock_guard<mutex> lck(host_tracker_mac_lock);
    return vlan_tag_present;
}

bool HostTrackerMac::has_same_vlan(uint16_t pvlan)
{
    lock_guard<mutex> lck(host_tracker_mac_lock);
    return vlan_tag_present and ( vlan_tag.vth_pri_cfi_vlan == pvlan );
}

uint16_t HostTrackerMac::get_vlan()
{
    lock_guard<mutex> lck(host_tracker_mac_lock);
    return vlan_tag.vth_pri_cfi_vlan;
}

void HostTrackerMac::get_vlan_details(uint8_t& cfi, uint8_t& priority, uint16_t& vid)
{
    lock_guard<mutex> lck(host_tracker_mac_lock);

    cfi = vlan_tag.cfi();
    priority = vlan_tag.priority();
    vid = vlan_tag.vid();
}

void HostTrackerMac::stringify(string& str)
{
    lock_guard<mutex> lck(host_tracker_mac_lock);

    auto total = network_protos.size();
    if ( total )
    {
        str += "\n Network proto: ";
        while ( total-- )
            str += to_string(network_protos[total]) + (total? ", " : "");
    }
}

#ifdef UNIT_TEST
TEST_CASE("RNA Mac Cache", "[rna_mac_cache]")
{
    uint8_t a_mac[6] = {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6};
    HostCacheMac mac_cache(MAC_CACHE_INITIAL_SIZE);

    SECTION("HostCacheMac: store, retrieve")
    {
        uint8_t b_mac[6] = {0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6};
        uint8_t c_mac[6] = {0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6};

        uint8_t test_mac[6] = {0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6};

        MacKey a(a_mac);
        MacKey b(b_mac);
        MacKey c(c_mac);
        MacKey test(test_mac);

        bool new_host_mac = false;

        auto a_ptr = mac_cache.find_else_create(a, &new_host_mac);
        CHECK(new_host_mac == true);
        CHECK(a_ptr != nullptr);

        new_host_mac = false;
        auto b_ptr = mac_cache.find_else_create(b, &new_host_mac);
        CHECK(new_host_mac == true);
        CHECK(b_ptr != nullptr);

        new_host_mac = false;
        auto c_ptr = mac_cache.find_else_create(c, &new_host_mac);
        CHECK(new_host_mac == true);
        CHECK(c_ptr != nullptr);

        // Try to add one of the previous macs again
        new_host_mac = false;
        auto test_ptr = mac_cache.find_else_create(test, &new_host_mac);
        CHECK(new_host_mac == false);
        CHECK(test_ptr != nullptr);

        // Verify macs in cache in LRU order, where test mac (i.e., b) is the most recent
        const auto&& lru_data = mac_cache.get_all_data();
        CHECK(lru_data.size() == 3);
        CHECK(lru_data[2].first == a);
        CHECK(lru_data[1].first == c);
        CHECK(lru_data[0].first == b);
    }

    SECTION("HostCacheMac: MAC Hashing")
    {
        uint64_t hash = hash_mac(a_mac);
        CHECK(hash == 0xA1A2A3A4A5A6);
    }

    SECTION("HostCacheMac: VLAN Tag Details")
    {
        MacKey a(a_mac);
        auto a_ptr = mac_cache.find_else_create(a, nullptr);

        a_ptr->update_vlan(12345, 54321);
        uint8_t cfi, priority;
        uint16_t vid;
        uint16_t vth_pri_cfi_vlan = a_ptr->get_vlan();

        a_ptr->get_vlan_details(cfi, priority, vid);

        CHECK(a_ptr->has_vlan());
        CHECK(cfi == (ntohs(vth_pri_cfi_vlan) & 0x1000) >> 12);
        CHECK(priority == (ntohs(vth_pri_cfi_vlan)) >> 13);
        CHECK(vid == (ntohs(vth_pri_cfi_vlan) & 0x0FFF));

    }
}
#endif

