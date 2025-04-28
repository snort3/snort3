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
#include <map>
#include <string>

#include "service_inspectors/dns/dns.h"

using namespace snort;

static const std::string& class_name(uint16_t query_class)
{
    static const std::map<uint16_t, std::string> class_names =
    {
        {1,   "C_INTERNET"},   // RFC 1035
        {2,   "C_CSNET"},      // RFC 1035
        {3,   "C_CHAOS"},      // RFC 1035
        {4,   "C_HESIOD"},     // RFC 1035
        {254, "C_NONE"},       // RFC 2136
        {255, "ANY"}           // RFC 1035
        // Add more classes as needed
    };

    static const std::string unknown = "UNKNOWN";

    auto it = class_names.find(query_class);
    return it != class_names.end() ? it->second : unknown;
}

static const std::string& rcode_name(uint16_t rcode)
{
    static const std::map<uint16_t, std::string> rcode_names =
    {
        {0,  "NOERROR"},   // RFC 1035
        {1,  "FORMERR"},   // RFC 1035
        {2,  "SERVFAIL"},  // RFC 1035
        {3,  "NXDOMAIN"},  // RFC 1035, also referred as "Name Error"
        {4,  "NOTIMP"},    // RFC 1035
        {5,  "REFUSED"},   // RFC 1035
        {6,  "YXDOMAIN"},  // RFC 2136, RFC 6672
        {7,  "YXRRSET"},   // RFC 2136
        {8,  "NXRRSET"},   // RFC 2136
        {9,  "NOTAUTH"},   // RFC 2136, RFC 8945
        {10, "NOTZONE"},   // RFC 2136
        {11, "DSOTYPENI"}, // RFC 8490
        {12, "unassigned-12"},
        {13, "unassigned-13"},
        {14, "unassigned-14"},
        {15, "unassigned-15"},
        // extended RCODEs below, see
        // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
        {16, "BADVERS"},   // RFC 6891, also BADSIG RFC 8945
        {17, "BADKEY"},    // RFC 8945
        {18, "BADTIME"},   // RFC 8945
        {19, "BADMODE"},   // RFC 2930
        {20, "BADNAME"},   // RFC 2930
        {21, "BADALG"},    // RFC 2930
        {22, "BADTRUNC"},  // RFC 8945
        {23, "BADCOOKIE"}  // RFC 7873
        // Add more RCODEs as needed
    };

    static const std::string unknown = "UNKNOWN";

    auto it = rcode_names.find(rcode);
    return it != rcode_names.end() ? it->second : unknown;
}

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

uint16_t DnsResponseEvent::get_trans_id() const
{
    return session.hdr.id;
}

const std::string& DnsResponseEvent::get_query() const
{
    return session.resp_query;
}

uint16_t DnsResponseEvent::get_query_class() const
{
    return session.curr_q.dns_class;
}

const std::string& DnsResponseEvent::get_query_class_name() const
{
    static const std::string empty = "";
    if (session.hdr.questions == 0)
        return empty;
    return class_name(session.curr_q.dns_class);
}

uint16_t DnsResponseEvent::get_query_type() const
{
    return session.curr_q.type;
}

const std::string& DnsResponseEvent::get_query_type_name() const
{
    static const std::string empty = "";
    if (session.hdr.questions == 0)
        return empty;
    return DNSData::qtype_name(get_query_type());
}

uint8_t DnsResponseEvent::get_rcode() const
{
    return session.hdr.flags & DNS_HDR_FLAG_REPLY_CODE_MASK;
}

const std::string& DnsResponseEvent::get_rcode_name() const
{
    return rcode_name(get_rcode());
}

bool DnsResponseEvent::get_AA() const
{
    return session.hdr.flags & DNS_HDR_FLAG_AUTHORITATIVE;
}

bool DnsResponseEvent::get_TC() const
{
    return session.hdr.flags & DNS_HDR_FLAG_TRUNCATED;
}

bool DnsResponseEvent::get_RD() const
{
    return session.hdr.flags & DNS_HDR_FLAG_RECURSION_DESIRED;
}

bool DnsResponseEvent::get_RA() const
{
    return session.hdr.flags & DNS_HDR_FLAG_RECURSION_AVAIL;
}

uint8_t DnsResponseEvent::get_Z() const
{
    return (session.hdr.flags & DNS_HDR_FLAG_Z) >> DNS_HDR_FLAG_Z_SHIFT;
}

const std::string& DnsResponseEvent::get_answers() const
{
    if (!answers_set)
    {
        session.get_answers(packet, answers, ttls);
        answers_set = true;
    }
    return answers;
}

const std::string& DnsResponseEvent::get_TTLs() const
{
    if (!answers_set)
    {
        session.get_answers(packet, answers, ttls);
        answers_set = true;
    }
    return ttls;
}

bool DnsResponseEvent::get_rejected() const
{
    if (session.hdr.flags & DNS_HDR_FLAG_RESPONSE)
    {
        if (session.hdr.flags & DNS_HDR_FLAG_REPLY_CODE_MASK && !session.hdr.questions)
            return true;
        if (session.hdr.answers == 0 && session.hdr.authorities == 0 && session.hdr.additionals == 0)
            return true;
    }
    return false;
}

const std::string& DnsResponseEvent::get_auth() const
{
    if (!auth_set)
    {
        session.get_auth(packet, auth);
        auth_set = true;
    }
    return auth;
}

const std::string& DnsResponseEvent::get_addl() const
{
    if (!addl_set)
    {
        session.get_addl(packet, addl);
        addl_set = true;
    }
    return addl;
}
