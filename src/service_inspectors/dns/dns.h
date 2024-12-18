//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

// dns.h author Steven Sturges

#ifndef DNS_H
#define DNS_H

#include "flow/flow.h"

#include "protocols/packet.h"
#include "pub_sub/dns_events.h"

// Implementation header with definitions, datatypes and flowdata class for
// DNS service inspector.

// Directional defines
#define DNS_DIR_FROM_SERVER 1
#define DNS_DIR_FROM_CLIENT 2

struct DNSHdr
{
    uint16_t id = 0;
    uint16_t flags = 0;
    uint16_t questions = 0;
    uint16_t answers = 0;
    uint16_t authorities = 0;
    uint16_t additionals = 0;
};

#define DNS_HDR_FLAG_REPLY_CODE_MASK        0x000F
#define DNS_HDR_FLAG_NON_AUTHENTICATED_OK   0x0010
#define DNS_HDR_FLAG_ANS_AUTHENTICATED      0x0020
#define DNS_HDR_FLAG_RESERVED               0x0040
#define DNS_HDR_FLAG_RECURSION_AVAIL        0x0080
#define DNS_HDR_FLAG_RECURSION_DESIRED      0x0100
#define DNS_HDR_FLAG_TRUNCATED              0x0200
#define DNS_HDR_FLAG_AUTHORITATIVE          0x0400
#define DNS_HDR_FLAG_OPCODE_MASK            0x7800
#define DNS_HDR_FLAG_RESPONSE               0x8000

struct DNSQuestion
{
    uint16_t type = 0;
    uint16_t dns_class = 0;
};

struct DNSRR
{
    uint16_t type = 0;
    uint16_t dns_class = 0;
    uint32_t ttl = 0;
    uint16_t length = 0;
};

// FIXIT-L replace alerted/relative to bool?
struct DNSNameState
{
    uint32_t txt_count = 0;
    uint32_t total_txt_len = 0;
    uint8_t txt_len = 0;
    uint8_t txt_bytes_seen = 0;
    uint8_t name_state = 0;
    uint8_t alerted = 0;
    uint16_t offset = 0;
    uint8_t relative = 0;
    std::string dns_name;

    void get_dns_name(std::string& name) const
    {
        if (dns_name.size())
            name = dns_name;
    }
};

// FIXIT-L  remove obsolete flags?
#define DNS_RR_TYPE_A                       0x0001
#define DNS_RR_TYPE_NS                      0x0002
#define DNS_RR_TYPE_MD                      0x0003 // obsolete
#define DNS_RR_TYPE_MF                      0x0004 // obsolete
#define DNS_RR_TYPE_CNAME                   0x0005
#define DNS_RR_TYPE_SOA                     0x0006
#define DNS_RR_TYPE_MB                      0x0007 // experimental
#define DNS_RR_TYPE_MG                      0x0008 // experimental
#define DNS_RR_TYPE_MR                      0x0009 // experimental
#define DNS_RR_TYPE_NULL                    0x000a // experimental
#define DNS_RR_TYPE_WKS                     0x000b
#define DNS_RR_TYPE_PTR                     0x000c
#define DNS_RR_TYPE_HINFO                   0x000d
#define DNS_RR_TYPE_MINFO                   0x000e // experimental
#define DNS_RR_TYPE_MX                      0x000f
#define DNS_RR_TYPE_TXT                     0x0010
#define DNS_RR_TYPE_AAAA                    0x001c

#define DNS_FLAG_NOT_DNS                0x01

// DNSSessionData States
#define DNS_RESP_STATE_LENGTH           0x00 // 2 bytes - TCP only
#define DNS_RESP_STATE_LENGTH_PART      0x01 // Partial length

#define DNS_RESP_STATE_HDR              0x10 // 12 bytes
#define DNS_RESP_STATE_HDR_ID           0x11 //  (2 bytes)
#define DNS_RESP_STATE_HDR_ID_PART      0x12 //  (2 bytes)
#define DNS_RESP_STATE_HDR_FLAGS        0x13 //  (2 bytes)
#define DNS_RESP_STATE_HDR_FLAGS_PART   0x14 //  (2 bytes)
#define DNS_RESP_STATE_HDR_QS           0x15 //  (2 bytes)
#define DNS_RESP_STATE_HDR_QS_PART      0x16 //  (2 bytes)
#define DNS_RESP_STATE_HDR_ANSS         0x17 //  (2 bytes)
#define DNS_RESP_STATE_HDR_ANSS_PART    0x18 //  (2 bytes)
#define DNS_RESP_STATE_HDR_AUTHS        0x19 //  (2 bytes)
#define DNS_RESP_STATE_HDR_AUTHS_PART   0x1a //  (2 bytes)
#define DNS_RESP_STATE_HDR_ADDS         0x1b //  (2 bytes)
#define DNS_RESP_STATE_HDR_ADDS_PART    0x1c //  (2 bytes)

#define DNS_RESP_STATE_QUESTION         0x20 // 4 bytes
#define DNS_RESP_STATE_Q_NAME           0x21 // (size depends on data)
#define DNS_RESP_STATE_Q_NAME_COMPLETE  0x22 // (size depends on data)
#define DNS_RESP_STATE_Q_TYPE           0x23 //  (2 bytes)
#define DNS_RESP_STATE_Q_TYPE_PART      0x24 //  (2 bytes)
#define DNS_RESP_STATE_Q_CLASS          0x25 //  (2 bytes)
#define DNS_RESP_STATE_Q_CLASS_PART     0x26 //  (2 bytes)
#define DNS_RESP_STATE_Q_COMPLETE       0x27

#define DNS_RESP_STATE_NAME_SIZE        0x31 // (1 byte)
#define DNS_RESP_STATE_NAME             0x32 // (size depends on field)
#define DNS_RESP_STATE_NAME_COMPLETE    0x33

#define DNS_RESP_STATE_ANS_RR           0x40 // (size depends on field)
#define DNS_RESP_STATE_RR_NAME_SIZE     0x41 // (1 byte)
#define DNS_RESP_STATE_RR_NAME          0x42 // (size depends on field)
#define DNS_RESP_STATE_RR_NAME_COMPLETE 0x43
#define DNS_RESP_STATE_RR_TYPE          0x44 //  (2 bytes)
#define DNS_RESP_STATE_RR_TYPE_PART     0x45 //  (2 bytes)
#define DNS_RESP_STATE_RR_CLASS         0x46 //  (2 bytes)
#define DNS_RESP_STATE_RR_CLASS_PART    0x47 //  (2 bytes)
#define DNS_RESP_STATE_RR_TTL           0x48 //  (4 bytes)
#define DNS_RESP_STATE_RR_TTL_PART      0x49 //  (4 bytes)
#define DNS_RESP_STATE_RR_RDLENGTH      0x4a //  (2 bytes)
#define DNS_RESP_STATE_RR_RDLENGTH_PART 0x4b //  (2 bytes)
#define DNS_RESP_STATE_RR_RDATA_START   0x4c // (size depends on RDLENGTH)
#define DNS_RESP_STATE_RR_RDATA_MID     0x4d // (size depends on RDLENGTH)
#define DNS_RESP_STATE_RR_COMPLETE      0x4e

#define DNS_RESP_STATE_AUTH_RR          0x50
#define DNS_RESP_STATE_ADD_RR           0x60

class DnsConfig;
struct DNSData;

class DnsResponseFqdn
{
public:
    DnsResponseFqdn()
    {}

    DnsResponseFqdn(const unsigned char* data, uint16_t bytes_unused, DNSData* dnsSessionData) :
        data(data), bytes_unused(bytes_unused), dnsSessionData(std::make_shared<DNSData>(*dnsSessionData))
    {}

    FqdnTtl get_fqdn();
    void update_ttl(uint32_t ttl);

private:
    const unsigned char* data = nullptr;
    uint16_t bytes_unused = 0;
    std::shared_ptr<DNSData> dnsSessionData;
};

// Per-session data block containing current state
// of the DNS inspector for the session.
struct DNSData
{
    uint32_t state = 0;               // The current state of the session.
    uint16_t curr_rec = 0;            // Record number for the current record
    uint16_t curr_rec_length = 0;
    uint16_t bytes_seen_curr_rec = 0;
    uint16_t length = 0;
    uint16_t bytes_unused = 0;
    uint8_t curr_rec_state = 0;
    DNSHdr hdr;                   // Copy of the data from the DNS Header
    DNSQuestion curr_q;
    DNSRR curr_rr;
    DNSNameState curr_txt;
    uint8_t flags = 0;
    std::vector<unsigned char> data;
    const DnsConfig* dns_config = nullptr;
    snort::DnsResponseDataEvents dns_events;
    DnsResponseFqdn cur_fqdn_event;

    bool publish_response() const;
    bool has_events() const;
    bool valid_dns(const DNSHdr&) const;
};

DNSData* get_dns_session_data(snort::Packet* p, bool from_server, DNSData& udpSessionData);

class DnsResponseIp
{
public:
    DnsResponseIp()
    {}

    DnsResponseIp(const unsigned char* data, uint16_t type) :
        data(data), type(type)
    {}

    snort::SfIp get_ip();

private:
    const unsigned char* data = nullptr;
    uint16_t type = 0;
};

class DnsFlowData : public snort::FlowData
{
public:
    DnsFlowData();
    ~DnsFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    DNSData session;
};

#endif

