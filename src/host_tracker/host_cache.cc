//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// host_cache.cc author Steve Chew <stechew@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_cache.h"

#include "main/snort_config.h"
#include "target_based/snort_protocols.h"

using namespace snort;

#define LRU_CACHE_INITIAL_SIZE 65535

LruCacheShared<HostIpKey, std::shared_ptr<HostTracker>, HashHostIpKey>
    host_cache(LRU_CACHE_INITIAL_SIZE);

void host_cache_add_host_tracker(HostTracker* ht)
{
    std::shared_ptr<HostTracker> sptr(ht);
    host_cache.insert((const uint8_t*) ht->get_ip_addr().get_ip6_ptr(), sptr);
}

namespace snort
{
bool host_cache_add_service(const SfIp& ipaddr, Protocol ipproto, Port port, const char* service)
{
    HostIpKey ipkey((const uint8_t*) ipaddr.get_ip6_ptr());
    SnortProtocolId proto_id = SnortConfig::get_conf()->proto_ref->find(service);
    HostApplicationEntry app_entry(ipproto, port, proto_id);
    std::shared_ptr<HostTracker> ht;

    if (!host_cache.find(ipkey, ht))
    {
        //  This host hasn't been seen.  Add it.
        ht = std::make_shared<HostTracker>();

        if (ht == nullptr)
        {
            //  FIXIT-L add error count
            return false;
        }
        host_cache.insert(ipkey, ht);
    }

    return ht->add_service(app_entry);
}
}

