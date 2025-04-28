//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// dns.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dns.h"

#include <iomanip>
#include <sstream>
#include <string>
#include "sfip/sf_ip.h"

using namespace snort;

const std::string& DNSData::qtype_name(uint16_t query_type, bool* is_unknown)
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
        {65521, "INTEGRITY"},  // Chromium Design Doc: Querying HTTPSSVC
        {65534, "BIND9S"}      // BIND9 signing signal
        // Add more QTYPEs as needed
    };

    static const std::string unknown = "UNKNOWN";

    auto it = qtype_names.find(query_type);
    if (it == qtype_names.end())
    {
        if (is_unknown)
            *is_unknown = true;
        return unknown;
    }

    if (is_unknown)
        *is_unknown = false;
    return it->second;
}

static void decode_ip(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str, uint16_t type)
{
    int family = (type == DNS_RR_TYPE_A) ? AF_INET : AF_INET6;
    if (family == AF_INET && rdlength != 4)
        return;
    if (family == AF_INET6 && rdlength != 16)
        return;

    SfIpString ipbuf;
    SfIp rr_ip(rdata, family);
    rr_ip.ntop(ipbuf);

    rdata_str = ipbuf;
}

static const std::string part_sep = " ";    // separates between parts of an item in a list

static void decode_txt(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str)
{
    static const std::string txt_prefix = "TXT" + part_sep;

    while (rdlength)
    {
        if (!rdata_str.empty())
            rdata_str.append(part_sep);
        rdata_str.append(txt_prefix);

        uint8_t txt_len = *rdata;
        rdata_str.append(std::to_string(txt_len));
        rdata_str.append(part_sep);
        rdata++;
        rdlength--;

        uint8_t actual_len = rdlength > txt_len ? txt_len : rdlength;
        rdata_str.append((const char*)rdata, actual_len);
        rdata += actual_len;
        rdlength -= actual_len;
    }
}

static void decode_domain_name(const uint8_t* rdata, uint16_t rdlength,
    std::string& rdata_str, const Packet* p = nullptr)
{
    static const int MAX_LINKS = 10;
    int link_count = 0;

    bool first_label = true;
    while (rdlength)
    {
        uint8_t label_len = *rdata;
        rdata++;
        rdlength--;

        if (label_len == 0)
            break;

        if ((label_len & DNS_RR_PTR) == DNS_RR_PTR)
        {
            if (p == nullptr)
                break;  // compression not supported

            if (rdlength < 1)
                break;  // incomplete offset

            uint16_t offset = ((label_len & ~DNS_RR_PTR) << 8) | *rdata;
            if (offset >= p->dsize)
                break;  // invalid offset
            if (link_count++ > MAX_LINKS)
                break;  // too many links

            rdata = p->data + offset;
            rdlength = p->dsize - offset;
            continue;
        }

        if (label_len & DNS_RR_PTR)
            break;  // invalid label length

        uint8_t actual_len = rdlength > label_len ? label_len : rdlength;
        if (!first_label)
            rdata_str.append(".");
        first_label = false;
        rdata_str.append((const char*)rdata, actual_len);
        rdata += actual_len;
        rdlength -= actual_len;
    }
}

static void decode_bind9_signing(std::string& rdata_str)
{
    static const std::string bind9_signing = "BIND9" + part_sep + "signing" + part_sep + "signal";
    rdata_str.append(bind9_signing);
}

static void decode_dnskey(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str)
{
    static const std::string dnskey_prefix = "DNSKEY" + part_sep;
    static const unsigned ALGORITHM_OFFSET = 3; // size is one byte
    static const unsigned PUBLIC_KEY_OFFSET = 4;

    if (rdlength <= PUBLIC_KEY_OFFSET)
        return; // incomplete DNSKEY record

    rdata_str.append(dnskey_prefix);
    rdata_str.append(std::to_string(rdata[ALGORITHM_OFFSET]));
}

static void decode_ds(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str)
{
    static const std::string ds_prefix = "DS" + part_sep;
    static const unsigned ALGORITHM_OFFSET = 2; // size is one byte
    static const unsigned DIGEST_TYPE_OFFSET = 3; // size is one byte
    static const unsigned DIGEST_OFFSET = 4;

    if (rdlength <= DIGEST_OFFSET)
        return; // incomplete DS record

    rdata_str.append(ds_prefix);
    rdata_str.append(std::to_string(rdata[ALGORITHM_OFFSET]));
    rdata_str.append(part_sep);
    rdata_str.append(std::to_string(rdata[DIGEST_TYPE_OFFSET]));
}

static void decode_loc(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str)
{
    static const std::string loc_prefix = "LOC" + part_sep;
    static const unsigned SIZE_OFFSET = 1;  // size is one byte
    static const unsigned HORIZ_PRE_OFFSET = 2; // size is one byte
    static const unsigned VERT_PRE_OFFSET = 3; // size is one byte
    static const unsigned LATITUDE_OFFSET = 4;

    if (rdlength <= LATITUDE_OFFSET)
        return; // incomplete LOC record

    rdata_str.append(loc_prefix);
    rdata_str.append(std::to_string(rdata[SIZE_OFFSET]));
    rdata_str.append(part_sep);
    rdata_str.append(std::to_string(rdata[HORIZ_PRE_OFFSET]));
    rdata_str.append(part_sep);
    rdata_str.append(std::to_string(rdata[VERT_PRE_OFFSET]));
}

static void decode_mx(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str, const Packet* p)
{
    static const unsigned EXCHANGE_OFFSET = 2;
    if (rdlength <= EXCHANGE_OFFSET)
        return; // incomplete MX record

    rdata += EXCHANGE_OFFSET;
    rdlength -= EXCHANGE_OFFSET;
    decode_domain_name(rdata, rdlength, rdata_str, p);
}

static void decode_nsec(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str,
    const Packet* p, const uint8_t* rr_domain_name)
{
    static const std::string nsec_prefix = "NSEC" + part_sep;
    static const unsigned RDATA_OFFSET = 10;
    const uint8_t* rr_domain_name_end = rdata - RDATA_OFFSET;
    uint16_t rr_domain_name_len = rr_domain_name_end - rr_domain_name;

    rdata_str.append(nsec_prefix);
    decode_domain_name(rr_domain_name, rr_domain_name_len, rdata_str, p);
    rdata_str.append(part_sep);
    decode_domain_name(rdata, rdlength, rdata_str);
}

static void decode_opt(const uint8_t* rdata, std::string& rdata_str)
{
    static const std::string opt_prefix = "OPT" + part_sep;
    static const unsigned RDATA_OFFSET = 10;
    static const unsigned EXTENDED_RCODE_OFFSET = 4; // size is one byte
    static const unsigned DO_Z_OFFSET = 6; // size is two bytes
    static const unsigned DO_MASK = 0x8000;

    const uint8_t* rr_type = rdata - RDATA_OFFSET;
    auto do_z_flags = (uint16_t)rr_type[DO_Z_OFFSET] << 8 | rr_type[DO_Z_OFFSET + 1];

    rdata_str.append(opt_prefix);
    rdata_str.append(std::to_string(rr_type[EXTENDED_RCODE_OFFSET]));
    rdata_str.append(part_sep);
    rdata_str.append(std::to_string((do_z_flags & DO_MASK) >> 15));
}

static void decode_rrsig(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str)
{
    static const std::string rrsig_prefix = "RRSIG" + part_sep;
    static const unsigned SIGNER_NAME_OFFSET = 18;

    if (rdlength <= SIGNER_NAME_OFFSET)
        return; // incomplete RRSIG record

    auto type_covered = (uint16_t)rdata[0] << 8 | rdata[1];
    rdata_str.append(rrsig_prefix);
    rdata_str.append(std::to_string(type_covered));
    rdata_str.append(part_sep);

    rdata += SIGNER_NAME_OFFSET;
    rdlength -= SIGNER_NAME_OFFSET;
    decode_domain_name(rdata, rdlength, rdata_str);
}

static void decode_spf(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str)
{
    static const std::string spf_prefix = "SPF" + part_sep;

    if (rdlength <= 1)
        return; // incomplete SPF record

    rdata_str.append(spf_prefix);

    uint8_t txt_len = *rdata;
    rdata_str.append(std::to_string(txt_len));
    rdata_str.append(part_sep);
    rdata++;
    rdlength--;

    uint8_t actual_len = rdlength > txt_len ? txt_len : rdlength;
    rdata_str.append((const char*)rdata, actual_len);
}

static void decode_srv(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str, const Packet* p)
{
    static const unsigned TARGET_OFFSET = 6;

    if (rdlength <= TARGET_OFFSET)
        return; // incomplete SRV record

    rdata += TARGET_OFFSET;
    rdlength -= TARGET_OFFSET;
    decode_domain_name(rdata, rdlength, rdata_str, p);
}

static void decode_sshfp(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str)
{
    static const std::string sshfp_prefix = "SSHFP" + part_sep;
    static const unsigned FINGERPRINT_OFFSET = 2;

    if (rdlength <= FINGERPRINT_OFFSET)
        return; // incomplete SSHFP record

    const uint8_t* rdata_end = rdata + rdlength;
    rdata += FINGERPRINT_OFFSET;
    std::ostringstream oss;
    while (rdata < rdata_end)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*rdata);
        rdata++;
    }

    rdata_str.append(sshfp_prefix);
    rdata_str.append(oss.str());
}

static void decode_default_rr(std::string& rdata_str, uint16_t type)
{
    bool is_unknown = false;
    rdata_str.append(DNSData::qtype_name(type, &is_unknown));
    if (is_unknown)
    {
        rdata_str.append("-");
        rdata_str.append(std::to_string(type));
    }
}

void DNSData::decode_rdata(const Packet* p, const uint8_t* rr_domain_name, const uint8_t* rdata,
    uint16_t rdlength, uint16_t type, std::string& rdata_str) const
{
    assert(rdata <= p->data + p->dsize);

    if (rdata + rdlength > p->data + p->dsize)
        rdlength = p->dsize - (rdata - p->data);

    switch (type)
    {
    case DNS_RR_TYPE_A:
    case DNS_RR_TYPE_AAAA:
        decode_ip(rdata, rdlength, rdata_str, type);
        break;

    case DNS_RR_TYPE_BIND9_SIGNING:
        decode_bind9_signing(rdata_str);
        break;

    case DNS_RR_TYPE_CNAME:
    case DNS_RR_TYPE_MB:
    case DNS_RR_TYPE_MD:
    case DNS_RR_TYPE_MF:
    case DNS_RR_TYPE_MG:
    case DNS_RR_TYPE_MR:
    case DNS_RR_TYPE_NS:
    case DNS_RR_TYPE_PTR:
    case DNS_RR_TYPE_SOA:
        decode_domain_name(rdata, rdlength, rdata_str, p);
        break;

    case DNS_RR_TYPE_DNSKEY:
        decode_dnskey(rdata, rdlength, rdata_str);
        break;

    case DNS_RR_TYPE_DS:
        decode_ds(rdata, rdlength, rdata_str);
        break;

    case DNS_RR_TYPE_LOC:
        decode_loc(rdata, rdlength, rdata_str);
        break;

    case DNS_RR_TYPE_MX:
        decode_mx(rdata, rdlength, rdata_str, p);
        break;

    case DNS_RR_TYPE_NSEC:
        decode_nsec(rdata, rdlength, rdata_str, p, rr_domain_name);
        break;

    case DNS_RR_TYPE_OPT:
        decode_opt(rdata, rdata_str);
        break;

    case DNS_RR_TYPE_RRSIG:
        decode_rrsig(rdata, rdlength, rdata_str);
        break;

    case DNS_RR_TYPE_SPF:
        decode_spf(rdata, rdlength, rdata_str);
        break;

    case DNS_RR_TYPE_SRV:
        decode_srv(rdata, rdlength, rdata_str, p);
        break;

    case DNS_RR_TYPE_SSHFP:
        decode_sshfp(rdata, rdlength, rdata_str);
        break;

    case DNS_RR_TYPE_TXT:
        decode_txt(rdata, rdlength, rdata_str);
        break;

    case DNS_RR_TYPE_CAA:
    case DNS_RR_TYPE_HINFO:
    case DNS_RR_TYPE_HTTPS:
    case DNS_RR_TYPE_NSEC3:
    case DNS_RR_TYPE_NSEC3PARAM:
    case DNS_RR_TYPE_SVCB:
    case DNS_RR_TYPE_TKEY:
    case DNS_RR_TYPE_TSIG:
    default:
        decode_default_rr(rdata_str, type);
        break;
    }
}

void DNSData::get_rr_data(const Packet *p, const std::vector<uint16_t>& tabs,
    std::string& rrs, std::string* ttls) const
{
    assert(p != nullptr);
    assert(p->data != nullptr);

    static const std::string item_sep = " ";    // list item separator
    static const unsigned RDATA_OFFSET = 10;
    const uint8_t* rr_domain_name = nullptr;

    for (auto tab : tabs)
    {
        if (tab + RDATA_OFFSET > p->dsize)
            continue;

        auto rr_type = p->data + tab;
        if (rr_domain_name == nullptr)
        {
            rr_domain_name = rr_type;
            continue;
        }

        uint16_t type = (rr_type[0] << 8) | rr_type[1];
        uint32_t ttl = (rr_type[4] << 24) | (rr_type[5] << 16) | (rr_type[6] << 8) | rr_type[7];
        uint16_t rdlength = (rr_type[8] << 8) | rr_type[9];

        auto rdata = rr_type + RDATA_OFFSET;
        std::string rdata_str;
        decode_rdata(p, rr_domain_name, rdata, rdlength, type, rdata_str);
        rr_domain_name = rdata + rdlength;

        if (rdata_str.empty())
            continue;

        if (!rrs.empty())
        {
            rrs.append(item_sep);
            if (ttls)
                ttls->append(item_sep);
        }
        rrs.append(rdata_str);
        if (ttls)
            ttls->append(std::to_string(ttl));
    }
}
