//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
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
// dns_events.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dns_events.h"

#include <algorithm>

#include "service_inspectors/dns/dns.h"

using namespace snort;

void IPFqdnCacheItem::add_ip(const SfIp& ip)
{
    if (ip.is_set())
        ips.emplace_back(ip);
}

void IPFqdnCacheItem::add_fqdn(const FqdnTtl& fqdn_ttl)
{
    if (fqdn_ttl.fqdn.empty())
        return;

    if (std::find_if(fqdns.cbegin(), fqdns.cend(),
        [&fqdn_ttl](const FqdnTtl& i){ return i.fqdn == fqdn_ttl.fqdn; }) != fqdns.end())
            return;

    fqdns.emplace_back(fqdn_ttl);
}

void DnsResponseDataEvents::add_ip(const DnsResponseIp& ip)
{
    dns_ips.emplace_back(ip);
}

void DnsResponseDataEvents::add_fqdn(DnsResponseFqdn& fqdn, uint32_t ttl)
{
    fqdn.update_ttl(ttl);
    dns_fqdns.emplace_back(fqdn);
}

void DnsResponseDataEvents::get_dns_data(IPFqdnCacheItem& ip_fqdn_cache_item)
{
    for (auto& it: dns_ips)
        ip_fqdn_cache_item.add_ip(it.get_ip());

    // don't add fqdns without ips
    if (ip_fqdn_cache_item.ips.empty())
        return;

    for (auto& it: dns_fqdns)
        ip_fqdn_cache_item.add_fqdn(it.get_fqdn());
}

bool DnsResponseDataEvents::empty() const
{
    return (dns_ips.empty() or dns_fqdns.empty());
}
