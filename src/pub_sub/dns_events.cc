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

static const std::string& qtype_name(uint16_t query_type)
{
    static const std::map<uint16_t, std::string> qtype_names =
    {
        {1,     "A"},          // RFC 1035
        {2,     "NS"},         // RFC 1035
        {3,     "MD"},         // RFC 1035
        {4,     "MF"},         // RFC 1035
        {5,     "CNAME"},      // RFC 1035
        {6,     "SOA"},        // RFC 1035
        {7,     "MB"},         // RFC 1035
        {8,     "MG"},         // RFC 1035
        {9,     "MR"},         // RFC 1035
        {10,    "NULL"},       // RFC 1035
        {11,    "WKS"},        // RFC 1035
        {12,    "PTR"},        // RFC 1035
        {13,    "HINFO"},      // RFC 1035
        {14,    "MINFO"},      // RFC 1035
        {15,    "MX"},         // RFC 1035
        {16,    "TXT"},        // RFC 1035
        {17,    "RP"},         // RFC 1183
        {18,    "AFSDB"},      // RFC 1183
        {19,    "X25"},        // RFC 1183
        {20,    "ISDN"},       // RFC 1183
        {21,    "RT"},         // RFC 1183
        {22,    "NSAP"},       // RFC 1706
        {23,    "NSAP_PTR"},   // RFC 1348
        {24,    "SIG"},        // RFC 2536
        {25,    "KEY"},        // RFC 2536
        {26,    "PX"},         // RFC 2163
        {27,    "GPOS"},       // RFC 1712
        {28,    "AAAA"},       // RFC 3596
        {29,    "LOC"},        // RFC 1876
        {30,    "NXT"},        // RFC 2535
        {31,    "EID"},
        {32,    "NIMLOC"},
        {33,    "SRV"},        // RFC 2782
        {34,    "ATMA"},
        {35,    "NAPTR"},      // RFC 3403
        {36,    "KX"},         // RFC 2230
        {37,    "CERT"},       // RFC 4398
        {38,    "A6"},         // RFC 2874
        {39,    "DNAME"},      // RFC 6672
        {40,    "SINK"},
        {41,    "OPT"},        // RFC 6891
        {42,    "APL"},        // RFC 3123
        {43,    "DS"},         // RFC 4034
        {44,    "SSHFP"},      // RFC 4255
        {45,    "IPSECKEY"},   // RFC 4025
        {46,    "RRSIG"},      // RFC 4034
        {47,    "NSEC"},       // RFC 4034
        {48,    "DNSKEY"},     // RFC 4034
        {49,    "DHCID"},      // RFC 4701
        {50,    "NSEC3"},      // RFC 5155
        {51,    "NSEC3PARAM"}, // RFC 5155
        {52,    "TLSA"},       // RFC 6698
        {53,    "SMIMEA"},     // RFC 8162
        {55,    "HIP"},        // RFC 8005
        {56,    "NINFO"},
        {57,    "RKEY"},
        {58,    "TALINK"},
        {59,    "CDS"},        // RFC 7344
        {60,    "CDNSKEY"},    // RFC 7344
        {61,    "OPENPGPKEY"}, // RFC 7929
        {62,    "CSYNC"},      // RFC 7477
        {63,    "ZONEMD"},     // RFC 8976
        {64,    "SVCB"},       // RFC 9460
        {65,    "HTTPS"},      // RFC 9460
        {66,    "DSYNC"},
        {99,    "SPF"},        // RFC 7208
        {100,   "UINFO"},
        {101,   "UID"},
        {102,   "GID"},
        {103,   "UNSPEC"},
        {104,   "NID"},        // RFC 6742
        {105,   "L32"},        // RFC 6742
        {106,   "L64"},        // RFC 6742
        {107,   "LP"},         // RFC 6742
        {108,   "EUI48"},      // RFC 7043
        {109,   "EUI64"},      // RFC 7043
        {249,   "TKEY"},       // RFC 2930
        {250,   "TSIG"},       // RFC 8945
        {251,   "IXFR"},       // RFC 1995
        {252,   "AXFR"},       // RFC 1035
        {253,   "MAILB"},      // RFC 1035
        {254,   "MAILA"},      // RFC 1035
        {255,   "*"},          // RFC 1035, also known as ANY
        {256,   "URI"},        // RFC 7553
        {257,   "CAA"},        // RFC 8659
        {32768, "TA"},
        {32769, "DLV"},        // RFC 4431
        {65281, "WINS"},       // Microsoft
        {65282, "WINS-R"},     // Microsoft
        {65521, "INTEGRITY"}   // Chromium Design Doc: Querying HTTPSSVC
        // Add more QTYPEs as needed
    };

    static const std::string unknown = "UNKNOWN";

    auto it = qtype_names.find(query_type);
    return it != qtype_names.end() ? it->second : unknown;
}

static const std::string& rcode_name(uint16_t rcode)
{
    static const std::map<uint8_t, std::string> rcode_names =
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
    return qtype_name(get_query_type());
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
    return session.hdr.flags & DNS_HDR_FLAG_RESPONSE &&
        session.hdr.flags & DNS_HDR_FLAG_REPLY_CODE_MASK &&
        !session.hdr.questions;
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
