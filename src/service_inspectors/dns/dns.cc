//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// dns.cc author Steven Sturges
// Alert for DNS client rdata buffer overflow.
// Alert for Obsolete or Experimental RData types (per RFC 1035)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dns.h"

#include "detection/detection_engine.h"
#include "dns_config.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "stream/stream.h"

#include "dns_module.h"
#include "dns_splitter.h"
#include "pub_sub/dns_events.h"

using namespace snort;

#define MAX_UDP_PAYLOAD 0x1FFF

THREAD_LOCAL ProfileStats dnsPerfStats;
THREAD_LOCAL DnsStats dnsstats;

const PegInfo dns_peg_names[] =
{
    { CountType::SUM, "packets", "total packets processed" },
    { CountType::SUM, "requests", "total dns requests" },
    { CountType::SUM, "responses", "total dns responses" },
    { CountType::NOW, "concurrent_sessions", "total concurrent dns sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent dns sessions" },
    { CountType::SUM, "aborted_sessions", "total dns sessions aborted" },

    { CountType::END, nullptr, nullptr }
};

/*
 * Function prototype(s)
 */
static void snort_dns(Packet* p, const DnsConfig* dns_config);

unsigned DnsFlowData::inspector_id = 0;

DnsFlowData::DnsFlowData() : FlowData(inspector_id)
{
    dnsstats.concurrent_sessions++;
    if(dnsstats.max_concurrent_sessions < dnsstats.concurrent_sessions)
        dnsstats.max_concurrent_sessions = dnsstats.concurrent_sessions;
}

DnsFlowData::~DnsFlowData()
{
    assert(dnsstats.concurrent_sessions > 0);
    dnsstats.concurrent_sessions--;
}

unsigned DnsUdpFlowData::inspector_id = 0;

DnsUdpFlowData::DnsUdpFlowData() : FlowData(inspector_id) {}

bool DNSData::publish_response() const
{
    return (dns_config->publish_response and state == DNS_RESP_STATE_ANS_RR);
}

bool DNSData::has_events() const
{
    return !dns_events.empty();
}

static DNSData* SetNewDNSData(Packet* p)
{
    DnsFlowData* fd;

    if (p->is_udp())
        return nullptr;

    fd = new DnsFlowData;
    fd->session.dns_events.set_packet(p);
    p->flow->set_flow_data(fd);

    return &fd->session;
}

bool DNSData::valid_dns(const DNSHdr& dns_header) const
{
    // Check QR bit (Query/Response)
    bool is_query = ((dns_header.flags & 0x8000) == 0);

    // Check Opcode (should be 0 for standard queries)
    uint16_t opcode = (dns_header.flags & 0x7800) >> 11;
    if (opcode > 2) 
        return false;

    // Check for reserved bits and RCODE
    if (dns_header.flags & 0x7800)
        return false;

    // Validate Recursion bits (RA should not be set in a query)
    bool ra_bit = (dns_header.flags & 0x0080) != 0;
    if (is_query && ra_bit) 
        return false;

    return true;
}

DNSData* get_dns_session_data(Packet* p, bool from_server, DNSData& udpSessionData)
{
    DnsFlowData* fd;
    if (p->is_udp())
    {
        if(p->dsize > MAX_UDP_PAYLOAD)
            return nullptr;

        if(!from_server)
        {
            if (p->dsize < (sizeof(DNSHdr) + sizeof(DNSQuestion) + 2))
                return nullptr;
        }
        else
        {
            if (p->dsize < (sizeof(DNSHdr)))
                return nullptr;
        }
        udpSessionData.dns_events.set_packet(p);
        return &udpSessionData;
    }

    fd = (DnsFlowData*)((p->flow)->get_flow_data(DnsFlowData::inspector_id));
    if (fd)
    {
        fd->session.dns_events.set_packet(p);
        return &fd->session;
    }
    return nullptr;
}

static uint16_t ParseDNSHeader(
    const unsigned char* data, uint16_t bytes_unused, DNSData* dnsSessionData)
{
    if ( !bytes_unused )
        return 0;

    switch (dnsSessionData->state)
    {
    case DNS_RESP_STATE_LENGTH:
        /* First two bytes are length in TCP */
        dnsSessionData->length = ((uint8_t)*data) << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_LENGTH_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_LENGTH_PART:
        dnsSessionData->length |= ((uint8_t)*data);
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_ID;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_ID:
        dnsSessionData->hdr.id = (uint8_t)*data << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_ID_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_ID_PART:
        dnsSessionData->hdr.id |= (uint8_t)*data;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_FLAGS;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_FLAGS:
        dnsSessionData->hdr.flags = (uint8_t)*data << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_FLAGS_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_FLAGS_PART:
        dnsSessionData->hdr.flags |= (uint8_t)*data;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_QS;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_QS:
        dnsSessionData->hdr.questions = (uint8_t)*data << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_QS_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_QS_PART:
        dnsSessionData->hdr.questions |= (uint8_t)*data;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_ANSS;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_ANSS:
        dnsSessionData->hdr.answers = (uint8_t)*data << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_ANSS_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_ANSS_PART:
        dnsSessionData->hdr.answers |= (uint8_t)*data;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_AUTHS;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_AUTHS:
        dnsSessionData->hdr.authorities = (uint8_t)*data << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_AUTHS_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_AUTHS_PART:
        dnsSessionData->hdr.authorities |= (uint8_t)*data;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_ADDS;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_ADDS:
        dnsSessionData->hdr.additionals = (uint8_t)*data << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->state = DNS_RESP_STATE_HDR_ADDS_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_HDR_ADDS_PART:
        dnsSessionData->hdr.additionals |= (uint8_t)*data;
        dnsSessionData->state = DNS_RESP_STATE_QUESTION;
        bytes_unused--;
        break;
    }

    return bytes_unused;
}

static uint16_t ParseDNSName(
    const unsigned char* data, uint16_t bytes_unused, DNSData* dnsSessionData, bool parse_dns_name = false)
{
    uint16_t bytes_required = dnsSessionData->curr_txt.txt_len -
        dnsSessionData->curr_txt.txt_bytes_seen;

    while (dnsSessionData->curr_txt.name_state != DNS_RESP_STATE_NAME_COMPLETE)
    {
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }

        switch (dnsSessionData->curr_txt.name_state)
        {
        case DNS_RESP_STATE_NAME_SIZE:
            dnsSessionData->curr_txt.txt_len = (uint8_t)*data;
            data++;
            bytes_unused--;
            dnsSessionData->bytes_seen_curr_rec++;
            if (dnsSessionData->curr_txt.txt_len == 0)
            {
                dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_NAME_COMPLETE;
                return bytes_unused;
            }

            dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_NAME;
            dnsSessionData->curr_txt.txt_bytes_seen = 0;

            if ((dnsSessionData->curr_txt.txt_len & DNS_RR_PTR) == DNS_RR_PTR)
            {
                /* A reference to another location...
                   This is an offset */
                dnsSessionData->curr_txt.offset = (dnsSessionData->curr_txt.txt_len & ~0xC0) << 8;
                bytes_required = dnsSessionData->curr_txt.txt_len = 1;
                dnsSessionData->curr_txt.relative = 1;
                /* Setup to read 2nd Byte of Location */
            }
            else
            {
                bytes_required = dnsSessionData->curr_txt.txt_len;
                dnsSessionData->curr_txt.offset = 0;
                dnsSessionData->curr_txt.relative = 0;
            }

            if (bytes_unused == 0)
            {
                return bytes_unused;
            }

        /* Fall through */
        case DNS_RESP_STATE_NAME:
            if (bytes_required <= bytes_unused)
            {
                bytes_unused -= bytes_required;
                if (dnsSessionData->curr_txt.relative)
                {
                    /* If this one is a relative offset, read that extra byte */
                    dnsSessionData->curr_txt.offset |= *data;
                    if (dnsSessionData->length > 0)
                        dnsSessionData->curr_txt.offset += 2; // first two bytes are length in TCP

                    if (parse_dns_name && dnsSessionData->data.size() > dnsSessionData->curr_txt.offset)
                    {
                        // If the name field is a pointer, then parse the name field at that offset only if
                        // the offset is within the bounds of the data buffer.
                        dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_NAME_SIZE;
                        return ParseDNSName(&dnsSessionData->data[0] + dnsSessionData->curr_txt.offset,
                            dnsSessionData->bytes_unused, dnsSessionData, parse_dns_name);
                    }
                }

                if (parse_dns_name)
                {
                    if (!dnsSessionData->curr_txt.dns_name.empty())
                        dnsSessionData->curr_txt.dns_name += ".";

                    dnsSessionData->curr_txt.dns_name.append((const char*)data, bytes_required);
                }

                data += bytes_required;
                dnsSessionData->bytes_seen_curr_rec += bytes_required;
                dnsSessionData->curr_txt.txt_bytes_seen += bytes_required;

                if (bytes_unused == 0)
                {
                    return bytes_unused;
                }
            }
            else
            {
                dnsSessionData->bytes_seen_curr_rec+= bytes_unused;
                dnsSessionData->curr_txt.txt_bytes_seen += bytes_unused;
                return 0;
            }
            if (dnsSessionData->curr_txt.relative)
            {
                /* And since its relative, we're done */
                dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_NAME_COMPLETE;
                return bytes_unused;
            }
            break;
        }

        /* Go to the next portion of the name */
        dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_NAME_SIZE;
    }

    return bytes_unused;
}

static uint16_t ParseDNSQuestion(
    const unsigned char* data, uint16_t bytes_unused, DNSData* dnsSessionData)
{
    if ( !bytes_unused )
        return 0;

    if (dnsSessionData->curr_rec_state < DNS_RESP_STATE_Q_NAME_COMPLETE)
    {
        uint16_t new_bytes_unused = ParseDNSName(data, bytes_unused, dnsSessionData, true);
        uint16_t bytes_used = bytes_unused - new_bytes_unused;

        if (dnsSessionData->curr_txt.name_state == DNS_RESP_STATE_NAME_COMPLETE)
        {
            dnsSessionData->resp_query = dnsSessionData->curr_txt.dns_name;
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_TYPE;
            dnsSessionData->curr_txt = DNSNameState();
            data = data + bytes_used;
            bytes_unused = new_bytes_unused;

            if ( !bytes_unused )
                return 0;  /* ran out of data */
        }
        else
        {
            /* Should be 0 -- ran out of data */
            return new_bytes_unused;
        }
    }

    switch (dnsSessionData->curr_rec_state)
    {
    case DNS_RESP_STATE_Q_TYPE:
        dnsSessionData->curr_q.type = (uint8_t)*data << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_TYPE_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_Q_TYPE_PART:
        dnsSessionData->curr_q.type |= (uint8_t)*data;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_CLASS;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_Q_CLASS:
        dnsSessionData->curr_q.dns_class = (uint8_t)*data << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_CLASS_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_Q_CLASS_PART:
        dnsSessionData->curr_q.dns_class |= (uint8_t)*data;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_COMPLETE;
        bytes_unused--;
        break;
    }

    return bytes_unused;
}

static uint16_t ParseDNSAnswer(
    const unsigned char* data, uint16_t bytes_unused, DNSData* dnsSessionData,
    const Packet* p, std::vector<uint16_t>& tabs)
{
    if ( !bytes_unused )
        return 0;

    if (dnsSessionData->curr_rec_state < DNS_RESP_STATE_RR_NAME_COMPLETE)
    {
        if (dnsSessionData->publish_response())
            dnsSessionData->cur_fqdn_event = DnsResponseFqdn(data, bytes_unused, dnsSessionData);

        uint16_t new_bytes_unused = ParseDNSName(data, bytes_unused, dnsSessionData);
        uint16_t bytes_used = bytes_unused - new_bytes_unused;

        if (dnsSessionData->curr_txt.name_state == DNS_RESP_STATE_NAME_COMPLETE)
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_TYPE;
            dnsSessionData->curr_txt = DNSNameState();
            data = data + bytes_used;
        }
        bytes_unused = new_bytes_unused;

        if ( !bytes_unused )
            return 0;  /* ran out of data */
    }

    switch (dnsSessionData->curr_rec_state)
    {
    case DNS_RESP_STATE_RR_TYPE:
        tabs.emplace_back(data - p->data);
        dnsSessionData->curr_rr.type = (uint8_t)*data << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_TYPE_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_RR_TYPE_PART:
        dnsSessionData->curr_rr.type |= (uint8_t)*data;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_CLASS;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_RR_CLASS:
        dnsSessionData->curr_rr.dns_class = (uint8_t)*data << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_CLASS_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_RR_CLASS_PART:
        dnsSessionData->curr_rr.dns_class |= (uint8_t)*data;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_TTL;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_RR_TTL:
        dnsSessionData->curr_rr.ttl = (uint8_t)*data << 24;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_TTL_PART;
        dnsSessionData->bytes_seen_curr_rec = 1;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_RR_TTL_PART:
        while (dnsSessionData->bytes_seen_curr_rec < 4)
        {
            dnsSessionData->bytes_seen_curr_rec++;
            dnsSessionData->curr_rr.ttl |=
                (uint8_t)*data << (4-dnsSessionData->bytes_seen_curr_rec)*8;
            data++;

            if ( !--bytes_unused )
                return 0;
        }
        // Fall through

    case DNS_RESP_STATE_RR_RDLENGTH:
        dnsSessionData->curr_rr.length = (uint8_t)*data << 8;
        data++;

        if ( !--bytes_unused )
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDLENGTH_PART;
            return 0;
        }
        // Fall through

    case DNS_RESP_STATE_RR_RDLENGTH_PART:
        dnsSessionData->curr_rr.length |= (uint8_t)*data;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDATA_START;
        bytes_unused--;
        break;
    }

    return bytes_unused;
}

/* The following check is to look for an attempt to exploit
 * a vulnerability in the DNS client, per MS 06-041.
 *
 * For details, see:
 * http://www.microsoft.com/technet/security/bulletin/ms06-007.mspx
 * http://cve.mitre.org/cgi-bin/cvename.cgi?name=2006-3441
 *
 * Vulnerability Research by Lurene Grenier, Judy Novak,
 * and Brian Caswell.
 */
static uint16_t CheckRRTypeTXTVuln(
    const unsigned char* data,
    uint16_t bytes_unused,
    DNSData* dnsSessionData)
{
    uint16_t bytes_required = dnsSessionData->curr_txt.txt_len -
        dnsSessionData->curr_txt.txt_bytes_seen;

    while (dnsSessionData->curr_txt.name_state != DNS_RESP_STATE_RR_NAME_COMPLETE)
    {
        if (dnsSessionData->bytes_seen_curr_rec == dnsSessionData->curr_rr.length)
        {
            /* Done with the name */
            dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_RR_NAME_COMPLETE;
            /* Got to the end of the rdata in this packet! */
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_COMPLETE;
            return bytes_unused;
        }

        if (bytes_unused == 0)
        {
            return bytes_unused;
        }

        switch (dnsSessionData->curr_txt.name_state)
        {
        case DNS_RESP_STATE_RR_NAME_SIZE:
            dnsSessionData->curr_txt.txt_len = (uint8_t)*data;
            dnsSessionData->curr_txt.txt_count++;

            /* include the null */
            dnsSessionData->curr_txt.total_txt_len += dnsSessionData->curr_txt.txt_len + 1;

            if (!dnsSessionData->curr_txt.alerted)
            {
                uint32_t overflow_check = (dnsSessionData->curr_txt.txt_count * 4) +
                    (dnsSessionData->curr_txt.total_txt_len * 2) + 4;
                /* if txt_count * 4 + total_txt_len * 2 + 4 > FFFF, vulnerability! */
                if (overflow_check > 0xFFFF)
                {
                    /* Alert on obsolete DNS RR types */
                    DetectionEngine::queue_event(GID_DNS, DNS_EVENT_RDATA_OVERFLOW);

                    dnsSessionData->curr_txt.alerted = 1;
                }
            }

            data++;
            bytes_unused--;
            dnsSessionData->bytes_seen_curr_rec++;
            if (dnsSessionData->curr_txt.txt_len > 0)
            {
                dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_RR_NAME;
                dnsSessionData->curr_txt.txt_bytes_seen = 0;
                bytes_required = dnsSessionData->curr_txt.txt_len;
            }
            else
            {
                continue;
            }
            if (bytes_unused == 0)
            {
                return bytes_unused;
            }
        /* Fall through */
        case DNS_RESP_STATE_RR_NAME:
            if (bytes_required <= bytes_unused)
            {
                bytes_unused -= bytes_required;
                dnsSessionData->bytes_seen_curr_rec += bytes_required;
                data += bytes_required;
                dnsSessionData->curr_txt.txt_bytes_seen += bytes_required;
                if (bytes_unused == 0)
                {
                    return bytes_unused;
                }
            }
            else
            {
                dnsSessionData->curr_txt.txt_bytes_seen += bytes_unused;
                dnsSessionData->bytes_seen_curr_rec += bytes_unused;
                return 0;
            }
            break;
        }

        /* Go to the next portion of the name */
        dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_RR_NAME_SIZE;
    }

    return bytes_unused;
}

static uint16_t SkipDNSRData(
    const unsigned char*,
    uint16_t bytes_unused,
    DNSData* dnsSessionData)
{
    uint16_t bytes_required = dnsSessionData->curr_rr.length - dnsSessionData->bytes_seen_curr_rec;

    if (bytes_required <= bytes_unused)
    {
        bytes_unused -= bytes_required;
        dnsSessionData->bytes_seen_curr_rec += bytes_required;
    }
    else
    {
        dnsSessionData->bytes_seen_curr_rec += bytes_unused;
        return 0;
    }

    /* Got to the end of the rdata in this packet! */
    dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_COMPLETE;
    return bytes_unused;
}

static uint16_t ParseDNSRData(
    const unsigned char* data,
    uint16_t bytes_unused,
    DNSData* dnsSessionData)
{
    if (bytes_unused == 0)
    {
        return bytes_unused;
    }

    switch (dnsSessionData->curr_rr.type)
    {
    case DNS_RR_TYPE_TXT:
        /* Check for RData Overflow */
        bytes_unused = CheckRRTypeTXTVuln(data, bytes_unused, dnsSessionData);
        break;

    case DNS_RR_TYPE_MD:
    case DNS_RR_TYPE_MF:
        /* Alert on obsolete DNS RR types */
        DetectionEngine::queue_event(GID_DNS, DNS_EVENT_OBSOLETE_TYPES);
        bytes_unused = SkipDNSRData(data, bytes_unused, dnsSessionData);
        break;

    case DNS_RR_TYPE_MB:
    case DNS_RR_TYPE_MG:
    case DNS_RR_TYPE_MR:
    case DNS_RR_TYPE_NULL:
    case DNS_RR_TYPE_MINFO:
        /* Alert on experimental DNS RR types */
        DetectionEngine::queue_event(GID_DNS, DNS_EVENT_EXPERIMENTAL_TYPES);
        bytes_unused = SkipDNSRData(data, bytes_unused, dnsSessionData);
        break;
    case DNS_RR_TYPE_A:
    case DNS_RR_TYPE_AAAA:
        if (dnsSessionData->publish_response())
        {
            dnsSessionData->dns_events.add_fqdn(dnsSessionData->cur_fqdn_event, dnsSessionData->curr_rr.ttl);
            dnsSessionData->dns_events.add_ip(DnsResponseIp(data, dnsSessionData->curr_rr.type));
        }

        bytes_unused = SkipDNSRData(data, bytes_unused, dnsSessionData);
        break;
    case DNS_RR_TYPE_CNAME:
        if (dnsSessionData->publish_response())
            dnsSessionData->dns_events.add_fqdn(dnsSessionData->cur_fqdn_event, dnsSessionData->curr_rr.ttl);

        bytes_unused = SkipDNSRData(data, bytes_unused, dnsSessionData);
        break;
    default:
        /* An unknown RR type or one w/o special handling, skip */
        bytes_unused = SkipDNSRData(data, bytes_unused, dnsSessionData);
        break;
    }

    return bytes_unused;
}

static void ParseDNSResponseMessage(Packet* p, DNSData* dnsSessionData, bool& needNextPacket)
{
    uint16_t bytes_unused = p->dsize;
    int i;
    const unsigned char* data = p->data;

    // For DNS over TCP, it's possible that multiple DNS transactions may be processed in a single TCP connection.
    // When a new transaction's DNS response message arrives, the reused DNS session's data field may not be empty,
    // so we must use the field "state" to determine if we are processing a new DNS response message.
    // For DNS over UDP, a new session data object is created for each DNS response message, so the following condition
    // is always met as the data field is always empty.
    if (dnsSessionData->dns_config->publish_response and (dnsSessionData->data.empty() or
        dnsSessionData->state == DNS_RESP_STATE_LENGTH))
    {
        // We are at the beginning of a new DNS response message, so we need to clear the data field
        // and the event object, which are reused by multiple DNS transactions in a single TCP connection.
        dnsSessionData->data.resize(bytes_unused);
        memcpy((void*)&dnsSessionData->data[0], data, bytes_unused);
        dnsSessionData->bytes_unused = bytes_unused;
        // For DNS over TCP, the reused event object may hold domain names and IP addresses extracted
        // from previous DNS response message which must be cleared before processing a new DNS message.
        dnsSessionData->dns_events.clear_data();
    }

    while (bytes_unused)
    {
        /* Parse through the DNS Header */
        if (dnsSessionData->state < DNS_RESP_STATE_QUESTION)
        {
            /* Length only applies on a TCP packet, skip to header ID
             * if at beginning of a UDP Response.
             */
            if ((dnsSessionData->state == DNS_RESP_STATE_LENGTH) &&
                p->is_udp())
            {
                dnsSessionData->state = DNS_RESP_STATE_HDR_ID;
            }

            bytes_unused = ParseDNSHeader(data, bytes_unused, dnsSessionData);

            if (dnsSessionData->hdr.flags & DNS_HDR_FLAG_RESPONSE)
                dnsstats.responses++;

            if (bytes_unused > 0)
            {
                data = p->data + (p->dsize - bytes_unused);
            }
            else
            {
                needNextPacket = true;
                return;
            }

            dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_NAME;
            dnsSessionData->curr_rec = 0;
        }

        if (!(dnsSessionData->hdr.flags & DNS_HDR_FLAG_RESPONSE))
        {
            /* Not a response */
            return;
        }

        /* Handle the DNS Queries */
        if (dnsSessionData->state == DNS_RESP_STATE_QUESTION)
        {
            /* Skip over the 4 byte question records... */
            for (i=dnsSessionData->curr_rec; i< dnsSessionData->hdr.questions; i++)
            {
                bytes_unused = ParseDNSQuestion(data, bytes_unused, dnsSessionData);

                if (dnsSessionData->curr_rec_state == DNS_RESP_STATE_Q_COMPLETE)
                {
                    dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_NAME;
                    dnsSessionData->curr_rec++;
                }
                if (bytes_unused > 0)
                {
                    data = p->data + (p->dsize - bytes_unused);
                }
                else
                {
                    needNextPacket = true;
                    return;
                }
            }
            dnsSessionData->state = DNS_RESP_STATE_ANS_RR;
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
            dnsSessionData->curr_rec = 0;
        }

        /* Handle the RRs */
        switch (dnsSessionData->state)
        {
        case DNS_RESP_STATE_ANS_RR: /* ANSWERS section */
            dnsSessionData->answer_tabs.emplace_back(data - p->data);
            for (i=dnsSessionData->curr_rec; i<dnsSessionData->hdr.answers; i++)
            {
                bytes_unused = ParseDNSAnswer(data, bytes_unused, dnsSessionData, p, dnsSessionData->answer_tabs);

                if (bytes_unused == 0)
                {
                    needNextPacket = true;
                    return;
                }

                switch (dnsSessionData->curr_rec_state)
                {
                case DNS_RESP_STATE_RR_RDATA_START:
                    dnsSessionData->bytes_seen_curr_rec = 0;
                    dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDATA_MID;
                /* Fall through */
                case DNS_RESP_STATE_RR_RDATA_MID:
                    /* Data now points to the beginning of the RDATA */
                    data = p->data + (p->dsize - bytes_unused);
                    bytes_unused = ParseDNSRData(data, bytes_unused, dnsSessionData);
                    if (dnsSessionData->curr_rec_state != DNS_RESP_STATE_RR_COMPLETE)
                    {
                        needNextPacket = true;
                        return;
                    }
                    else
                    {
                        /* Go to the next record */
                        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
                        dnsSessionData->curr_rec++;

                        if (dnsSessionData->curr_rr.type == DNS_RR_TYPE_TXT)
                        {
                            /* Reset the state tracking for this record */
                            dnsSessionData->curr_txt = DNSNameState();
                        }
                        data = p->data + (p->dsize - bytes_unused);
                    }
                }
            }
            dnsSessionData->state = DNS_RESP_STATE_AUTH_RR;
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
            dnsSessionData->curr_rec = 0;
        /* Fall through */
        case DNS_RESP_STATE_AUTH_RR: /* AUTHORITIES section */
            dnsSessionData->auth_tabs.emplace_back(data - p->data);
            for (i=dnsSessionData->curr_rec; i<dnsSessionData->hdr.authorities; i++)
            {
                bytes_unused = ParseDNSAnswer(data, bytes_unused, dnsSessionData, p, dnsSessionData->auth_tabs);

                if (bytes_unused == 0)
                {
                    /* No more data */
                    return;
                }

                switch (dnsSessionData->curr_rec_state)
                {
                case DNS_RESP_STATE_RR_RDATA_START:
                    dnsSessionData->bytes_seen_curr_rec = 0;
                    dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDATA_MID;
                /* Fall through */
                case DNS_RESP_STATE_RR_RDATA_MID:
                    /* Data now points to the beginning of the RDATA */
                    data = p->data + (p->dsize - bytes_unused);
                    bytes_unused = ParseDNSRData(data, bytes_unused, dnsSessionData);
                    if (dnsSessionData->curr_rec_state != DNS_RESP_STATE_RR_COMPLETE)
                    {
                        /* Out of data, pick up on the next packet */
                        return;
                    }
                    else
                    {
                        /* Go to the next record */
                        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
                        dnsSessionData->curr_rec++;

                        if (dnsSessionData->curr_rr.type == DNS_RR_TYPE_TXT)
                        {
                            /* Reset the state tracking for this record */
                            dnsSessionData->curr_txt = DNSNameState();
                        }
                        data = p->data + (p->dsize - bytes_unused);
                    }
                }
            }
            dnsSessionData->state = DNS_RESP_STATE_ADD_RR;
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
            dnsSessionData->curr_rec = 0;
        /* Fall through */
        case DNS_RESP_STATE_ADD_RR: /* ADDITIONALS section */
            dnsSessionData->addl_tabs.emplace_back(data - p->data);
            for (i=dnsSessionData->curr_rec; i<dnsSessionData->hdr.additionals; i++)
            {
                bytes_unused = ParseDNSAnswer(data, bytes_unused, dnsSessionData, p, dnsSessionData->addl_tabs);

                if (bytes_unused == 0)
                {
                    /* No more data */
                    return;
                }

                switch (dnsSessionData->curr_rec_state)
                {
                case DNS_RESP_STATE_RR_RDATA_START:
                    dnsSessionData->bytes_seen_curr_rec = 0;
                    dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDATA_MID;
                /* Fall through */
                case DNS_RESP_STATE_RR_RDATA_MID:
                    /* Data now points to the beginning of the RDATA */
                    data = p->data + (p->dsize - bytes_unused);
                    bytes_unused = ParseDNSRData(data, bytes_unused, dnsSessionData);
                    if (dnsSessionData->curr_rec_state != DNS_RESP_STATE_RR_COMPLETE)
                    {
                        /* Out of data, pick up on the next packet */
                        return;
                    }
                    else
                    {
                        /* Go to the next record */
                        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
                        dnsSessionData->curr_rec++;

                        if (dnsSessionData->curr_rr.type == DNS_RR_TYPE_TXT)
                        {
                            /* Reset the state tracking for this record */
                            dnsSessionData->curr_txt = DNSNameState();
                        }
                        data = p->data + (p->dsize - bytes_unused);
                    }
                }
            }
            /* Done with this one, onto the next -- may also be in this packet */
            dnsSessionData->state = DNS_RESP_STATE_LENGTH;
            dnsSessionData->curr_rec_state = 0;
            dnsSessionData->curr_rec = 0;
        }
    }
}

SfIp DnsResponseIp::get_ip()
{
    SfIp ip = {};
    int family = 0;
    switch (type)
    {
        case DNS_RR_TYPE_A:
            family = AF_INET;
            break;
        case DNS_RR_TYPE_AAAA:
            family = AF_INET6;
            break;
    }

    if (family and strlen((const char*)data))
        ip.set(data, family);

    return ip;
}

FqdnTtl DnsResponseFqdn::get_fqdn()
{
    std::string dns_name;
    ParseDNSName(data, bytes_unused, dnsSessionData.get(), true);

    if (dnsSessionData->curr_txt.name_state == DNS_RESP_STATE_NAME_COMPLETE)
        dnsSessionData->curr_txt.get_dns_name(dns_name);

    return FqdnTtl(dns_name, dnsSessionData->curr_rr.ttl);
}

void DnsResponseFqdn::update_ttl(uint32_t ttl)
{
    dnsSessionData->curr_rr.ttl = ttl;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Dns : public Inspector
{
public:
    Dns(DnsModule*);
    ~Dns() override;

    void eval(Packet*) override;
    StreamSplitter* get_splitter(bool) override;
    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    static unsigned get_pub_id() { return pub_id; }

    bool supports_no_ips() const override
    { return true; }

private:
    const DnsConfig* config = nullptr;
    static unsigned pub_id;
};

unsigned Dns::pub_id = 0;

Dns::Dns(DnsModule* m)
{
    config = m->get_config();
    assert(config);
}

Dns::~Dns()
{
    delete config;
}

void Dns::show(const SnortConfig*) const
{
    config->show();
}

void Dns::eval(Packet* p)
{
    // precondition - what we registered for
    assert((p->is_udp() and p->dsize and p->data) or p->has_tcp_data() or p->has_udp_quic_data());
    assert(p->flow);

    ++dnsstats.packets;
    snort_dns(p, config);
}

bool Dns::configure(snort::SnortConfig*)
{
    if ( !pub_id )
        pub_id = DataBus::get_id(dns_pub_key);

    return true;
}

StreamSplitter* Dns::get_splitter(bool c2s)
{
    return new DnsSplitter(c2s);
}

// Get the DNS transaction ID from a UDP packet's data field
static inline uint16_t get_udp_trans_id(Packet* p)
{
    // The length of packet's data field should have already been validated
    return (static_cast<uint16_t>(p->data[0]) << 8) | static_cast<uint16_t>(p->data[1]);
}

// Add DNS transaction ID to the UDP packet's flow data object
static void add_to_udp_flow(Packet* p, uint16_t trans_id)
{
    DnsUdpFlowData* udp_flow_data = (DnsUdpFlowData*)((p->flow)->get_flow_data(DnsUdpFlowData::inspector_id));
    if (!udp_flow_data)
    {
        udp_flow_data = new DnsUdpFlowData();
        p->flow->set_flow_data(udp_flow_data);
    }
    udp_flow_data->trans_ids.emplace(trans_id);
}

// Check if the DNS transaction ID is found in the UDP packet's flow data object
static bool is_in_udp_flow(Packet* p, uint16_t trans_id)
{
    bool found = false;
    DnsUdpFlowData* udp_flow_data = (DnsUdpFlowData*)((p->flow)->get_flow_data(DnsUdpFlowData::inspector_id));
    if (udp_flow_data)
        found = udp_flow_data->trans_ids.find(trans_id) != udp_flow_data->trans_ids.end();
    return found;
}

// Remove DNS transaction ID from the UDP packet's flow data object
static void rm_from_udp_flow(Packet* p, uint16_t trans_id)
{
    DnsUdpFlowData* udp_flow_data = (DnsUdpFlowData*)((p->flow)->get_flow_data(DnsUdpFlowData::inspector_id));
    bool should_close = true;
    if (udp_flow_data)
    {
        udp_flow_data->trans_ids.erase(trans_id);
        should_close = udp_flow_data->trans_ids.empty();
    }
    if (should_close)
    {
        // Mark the UDP flow as "closed" only when all trans_ids are matched
        // and removed by DNS-reply packets, or if the flow data object is not found
        p->flow->session_state |= STREAM_STATE_CLOSED;
    }
}

static void snort_dns(Packet* p, const DnsConfig* dns_config)
{
    // cppcheck-suppress unreadVariable
    Profile profile(dnsPerfStats);

    // For TCP, do a few extra checks...
    if ( p->has_tcp_data() )
    {
        // If session picked up mid-stream, do not process further.
        // Would be almost impossible to tell where we are in the
        // data stream.
        if ( p->test_session_flags(SSNFLAG_MIDSTREAM) )
            return;

        if ( !Stream::is_stream_sequenced(p->flow, SSN_DIR_FROM_CLIENT) )
            return;
    }

    // Get the direction of the packet.
    bool from_server = ( (p->is_from_server() ) ? true : false );

    DNSData udp_session_data;
    // Attempt to get a previously allocated DNS block.
    DNSData* dnsSessionData = get_dns_session_data(p, from_server, udp_session_data);

    if (dnsSessionData == nullptr)
    {
        // Check the stream session. If it does not currently
        // have our DNS data-block attached, create one.
        dnsSessionData = SetNewDNSData(p);

        if ( !dnsSessionData )
            // Could not get/create the session data for this packet.
            return;
    }

    if (dnsSessionData->flags & DNS_FLAG_NOT_DNS)
        return;

    dnsSessionData->dns_config = dns_config;
    if ( from_server )
    {
        uint16_t trans_id = 0;
        // Always parse the response packet for TCP flows
        bool should_parse_response = true;
        if (p->is_udp())
        {
            // If this is a DNS-over-UDP flow then parse the response packet and publish events
            // only when the response packet's DNS transaction-ID is found in the flow data object
            trans_id = get_udp_trans_id(p);
            should_parse_response = is_in_udp_flow(p, trans_id);
        }

        if (should_parse_response)
        {
            bool needNextPacket = false;
            ParseDNSResponseMessage(p, dnsSessionData, needNextPacket);
            trans_id = dnsSessionData->hdr.id;

            if (!dnsSessionData->valid_dns(dnsSessionData->hdr))
            {
                dnsSessionData->flags |= DNS_FLAG_NOT_DNS;
                return;
            }

            if (!needNextPacket and dnsSessionData->has_events())
                DataBus::publish(Dns::get_pub_id(), DnsEventIds::DNS_RESPONSE_DATA, dnsSessionData->dns_events);

            DnsResponseEvent dns_response_event(*dnsSessionData, p);
            DataBus::publish(Dns::get_pub_id(), DnsEventIds::DNS_RESPONSE, dns_response_event, p->flow);
        }

        if (p->is_udp())
            rm_from_udp_flow(p, trans_id);
    }
    else
    {
        dnsstats.requests++;
        if (p->is_udp())
            add_to_udp_flow(p, get_udp_trans_id(p));
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new DnsModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void dns_init()
{
    DnsFlowData::init();
    DnsUdpFlowData::init();
}

static Inspector* dns_ctor(Module* m)
{
    DnsModule* mod = (DnsModule*)m;
    return new Dns(mod);
}

static void dns_dtor(Inspector* p)
{
    delete p;
}

const InspectApi dns_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        DNS_NAME,
        DNS_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__ANY_PDU,
    nullptr, // buffers
    "dns",
    dns_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dns_ctor,
    dns_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &dns_api.base,
    nullptr
};
#else
const BaseApi* sin_dns[] =
{
    &dns_api.base,
    nullptr
};
#endif

