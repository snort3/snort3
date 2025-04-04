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

#include <string>
#include "sfip/sf_ip.h"

using namespace snort;

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

static void decode_mx(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str, const Packet* p)
{
    static const unsigned EXCHANGE_OFFSET = 2;
    if (rdlength <= EXCHANGE_OFFSET)
        return; // incomplete MX record

    rdata += EXCHANGE_OFFSET;
    rdlength -= EXCHANGE_OFFSET;
    decode_domain_name(rdata, rdlength, rdata_str, p);
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

static void decode_nsec(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str,
    const std::string& resp_query)
{
    static const std::string nsec_prefix = "NSEC" + part_sep;

    rdata_str.append(nsec_prefix);
    rdata_str.append(resp_query);
    rdata_str.append(part_sep);
    decode_domain_name(rdata, rdlength, rdata_str);
}

static void decode_ds(const uint8_t* rdata, uint16_t rdlength, std::string& rdata_str)
{
    static const std::string ds_prefix = "DS" + part_sep;
    static const unsigned DIGEST_OFFSET = 4;

    if (rdlength <= DIGEST_OFFSET)
        return; // incomplete DS record

    rdata_str.append(ds_prefix);
    rdata_str.append(std::to_string(rdata[2])); // algorithm
    rdata_str.append(part_sep);
    rdata_str.append(std::to_string(rdata[3])); // digest type
}

void DNSData::decode_rdata(const Packet* p, const uint8_t* rdata, uint16_t rdlength, uint16_t type,
    std::string& rdata_str) const
{
    assert(rdata < p->data + p->dsize);

    if (rdata + rdlength > p->data + p->dsize)
        rdlength = p->dsize - (rdata - p->data);

    switch (type)
    {
    case DNS_RR_TYPE_A:
    case DNS_RR_TYPE_AAAA:
        decode_ip(rdata, rdlength, rdata_str, type);
        break;

    case DNS_RR_TYPE_TXT:
        decode_txt(rdata, rdlength, rdata_str);
        break;

    case DNS_RR_TYPE_CNAME:
    case DNS_RR_TYPE_MD:
    case DNS_RR_TYPE_MF:
    case DNS_RR_TYPE_MB:
    case DNS_RR_TYPE_MG:
    case DNS_RR_TYPE_MR:
    case DNS_RR_TYPE_NS:
    case DNS_RR_TYPE_PTR:
    case DNS_RR_TYPE_SOA:
        decode_domain_name(rdata, rdlength, rdata_str, p);
        break;

    case DNS_RR_TYPE_MX:
        decode_mx(rdata, rdlength, rdata_str, p);
        break;

    case DNS_RR_TYPE_RRSIG:
        decode_rrsig(rdata, rdlength, rdata_str);
        break;

    case DNS_RR_TYPE_NSEC:
        decode_nsec(rdata, rdlength, rdata_str, resp_query);
        break;

    case DNS_RR_TYPE_DS:
        decode_ds(rdata, rdlength, rdata_str);
        break;

    default:
        break;
    }
}

void DNSData::get_rr_data(const Packet *p, const std::vector<uint16_t>& tabs,
    std::string& rrs, std::string* ttls) const
{
    static const std::string item_sep = " ";    // list item separator
    static const unsigned RDATA_OFFSET = 10;
    for (auto tab : tabs)
    {
        if (tab + RDATA_OFFSET >= p->dsize)
            continue;

        auto rdata = p->data + tab;

        uint16_t type = (rdata[0] << 8) | rdata[1];
        uint32_t ttl = (rdata[4] << 24) | (rdata[5] << 16) | (rdata[6] << 8) | rdata[7];

        uint16_t rdlength = (rdata[8] << 8) | rdata[9];

        std::string rdata_str;
        decode_rdata(p, rdata + RDATA_OFFSET, rdlength, type, rdata_str);

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
