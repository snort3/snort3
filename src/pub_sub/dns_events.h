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
// dns_events.h author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifndef DNS_EVENTS_H
#define DNS_EVENTS_H

// This event allows the dns service inspector to publish dns response
// for use by data bus subscribers

#include "framework/data_bus.h"
#include "sfip/sf_ip.h"

struct FqdnTtl
{
    FqdnTtl(const std::string& fqdn, uint32_t ttl) :
        fqdn(fqdn), ttl(ttl)
    {}

    std::string fqdn;
    uint32_t ttl;
};

struct IPFqdnCacheItem
{
    void add_ip(const snort::SfIp& ip);
    void add_fqdn(const FqdnTtl& fqdn_ttl);

    std::vector<snort::SfIp> ips;
    std::vector<FqdnTtl> fqdns;
};

struct DnsEventIds
{
    enum : unsigned
    {
        DNS_RESPONSE_DATA,
        num_ids
    };
};

const snort::PubKey dns_pub_key { "dns", DnsEventIds::num_ids };

class DnsResponseIp;
class DnsResponseFqdn;

namespace snort
{
class SO_PUBLIC DnsResponseDataEvents : public snort::DataEvent
{
public:
    void add_ip(const DnsResponseIp& event);
    void add_fqdn(DnsResponseFqdn& event, uint32_t ttl);
    void get_dns_data(IPFqdnCacheItem& ip_fqdn_cache_item);
    bool empty() const;

private:
    std::vector<DnsResponseIp> dns_ips;
    std::vector<DnsResponseFqdn> dns_fqdns;
};
}

#endif
