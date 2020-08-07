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

// rna_mac_cache.cc author Michael Matirko <mmatirko@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "rna_mac_cache.h"

#include <cassert>
#include <vector>

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

HostCacheMac host_cache_mac(MAC_CACHE_INITIAL_SIZE);

void HostMacIp::update_vlan(uint16_t vth_pri_cfi_vlan, uint16_t vth_proto)
{
    vlan_tag_present = true;
    vlan_tag.vth_pri_cfi_vlan = vth_pri_cfi_vlan;
    vlan_tag.vth_proto = vth_proto;
}

bool HostMacIp::has_vlan()
{
    return vlan_tag_present;
}

uint16_t HostMacIp::get_vlan()
{
    return vlan_tag.vth_pri_cfi_vlan;
}

void HostMacIp::get_vlan_details(uint8_t& cfi, uint8_t& priority, uint16_t& vid)
{
    cfi = vlan_tag.cfi();
    priority = vlan_tag.priority();
    vid = vlan_tag.vid();
}

#ifdef UNIT_TEST
TEST_CASE("RNA Mac Cache", "[rna_mac_cache]")
{
    SECTION("HostCacheMac: store, retrieve")
    {
        uint8_t a_mac[6] = {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6};
        uint8_t b_mac[6] = {0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6};
        uint8_t c_mac[6] = {0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6};

        uint8_t test_mac[6] = {0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6};

        MacKey a(a_mac);
        MacKey b(b_mac);
        MacKey c(c_mac);
        MacKey test(test_mac);

        HostMacIp hm_b(b_mac, 1, 0);

        bool new_host = false;
        bool new_host_test = false;

        auto a_ptr = host_cache_mac.find_else_create(a, &new_host);
        assert(new_host);
        assert(a_ptr);

        auto b_ptr = host_cache_mac.find_else_create(b, &new_host);
        assert(new_host);
        b_ptr->insert(&hm_b);

        auto c_ptr = host_cache_mac.find_else_create(c, &new_host);
        assert(new_host);
        assert(c_ptr);

        // Try to add one of the previous macs again
        auto test_ptr = host_cache_mac.find_else_create(test, &new_host_test);
        assert(test_ptr);
        assert(!new_host_test);

        // Verify that test_ptr contains the host_mac we're looking for
        assert(!memcmp(test_ptr->data.front().mac, b_mac, MAC_SIZE));
    }

    SECTION("HostCacheMac: MAC Hashing")
    {
        uint8_t a_mac[6] = {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6};
        uint64_t hash = snort::hash_mac(a_mac);
        assert(hash == 0xA1A2A3A4A5A6);
    }
}
#endif
