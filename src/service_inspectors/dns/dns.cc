//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "stream/stream.h"

#include "dns_module.h"

using namespace snort;

#define MAX_UDP_PAYLOAD 0x1FFF
#define DNS_RR_PTR 0xC0

THREAD_LOCAL ProfileStats dnsPerfStats;
THREAD_LOCAL DnsStats dnsstats;

const PegInfo dns_peg_names[] =
{
    { CountType::SUM, "packets", "total packets processed" },
    { CountType::SUM, "requests", "total dns requests" },
    { CountType::SUM, "responses", "total dns responses" },
    { CountType::NOW, "concurrent_sessions", "total concurrent dns sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent dns sessions" },

    { CountType::END, nullptr, nullptr }
};

/*
 * Function prototype(s)
 */
static void snort_dns(Packet* p);

unsigned DnsFlowData::inspector_id = 0;

DNSData udpSessionData;

DnsFlowData::DnsFlowData() : FlowData(inspector_id)
{
    memset(&session, 0, sizeof(session));
    dnsstats.concurrent_sessions++;
    if(dnsstats.max_concurrent_sessions < dnsstats.concurrent_sessions)
        dnsstats.max_concurrent_sessions = dnsstats.concurrent_sessions;
}

DnsFlowData::~DnsFlowData()
{
    assert(dnsstats.concurrent_sessions > 0);
    dnsstats.concurrent_sessions--;
}

static DNSData* SetNewDNSData(Packet* p)
{
    DnsFlowData* fd;

    if (p->is_udp())
        return nullptr;

    fd = new DnsFlowData;

    p->flow->set_flow_data(fd);
    return &fd->session;
}

static DNSData* get_dns_session_data(Packet* p, bool from_server)
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

        memset(&udpSessionData, 0, sizeof(udpSessionData));
        return &udpSessionData;
    }

    fd = (DnsFlowData*)((p->flow)->get_flow_data(DnsFlowData::inspector_id));
    return fd ? &fd->session : nullptr;
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
        dnsSessionData->state = DNS_RESP_STATE_LENGTH_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_LENGTH_PART:
        dnsSessionData->length |= ((uint8_t)*data);
        dnsSessionData->state = DNS_RESP_STATE_HDR_ID;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_HDR_ID:
        dnsSessionData->hdr.id = (uint8_t)*data << 8;
        dnsSessionData->state = DNS_RESP_STATE_HDR_ID_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_HDR_ID_PART:
        dnsSessionData->hdr.id |= (uint8_t)*data;
        dnsSessionData->state = DNS_RESP_STATE_HDR_FLAGS;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_HDR_FLAGS:
        dnsSessionData->hdr.flags = (uint8_t)*data << 8;
        dnsSessionData->state = DNS_RESP_STATE_HDR_FLAGS_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_HDR_FLAGS_PART:
        dnsSessionData->hdr.flags |= (uint8_t)*data;
        dnsSessionData->state = DNS_RESP_STATE_HDR_QS;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_HDR_QS:
        dnsSessionData->hdr.questions = (uint8_t)*data << 8;
        dnsSessionData->state = DNS_RESP_STATE_HDR_QS_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_HDR_QS_PART:
        dnsSessionData->hdr.questions |= (uint8_t)*data;
        dnsSessionData->state = DNS_RESP_STATE_HDR_ANSS;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_HDR_ANSS:
        dnsSessionData->hdr.answers = (uint8_t)*data << 8;
        dnsSessionData->state = DNS_RESP_STATE_HDR_ANSS_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_HDR_ANSS_PART:
        dnsSessionData->hdr.answers |= (uint8_t)*data;
        dnsSessionData->state = DNS_RESP_STATE_HDR_AUTHS;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_HDR_AUTHS:
        dnsSessionData->hdr.authorities = (uint8_t)*data << 8;
        dnsSessionData->state = DNS_RESP_STATE_HDR_AUTHS_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_HDR_AUTHS_PART:
        dnsSessionData->hdr.authorities |= (uint8_t)*data;
        dnsSessionData->state = DNS_RESP_STATE_HDR_ADDS;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_HDR_ADDS:
        dnsSessionData->hdr.additionals = (uint8_t)*data << 8;
        dnsSessionData->state = DNS_RESP_STATE_HDR_ADDS_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
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
    const unsigned char* data, uint16_t bytes_unused, DNSData* dnsSessionData)
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
        uint16_t new_bytes_unused = ParseDNSName(data, bytes_unused, dnsSessionData);
        uint16_t bytes_used = bytes_unused - new_bytes_unused;

        if (dnsSessionData->curr_txt.name_state == DNS_RESP_STATE_NAME_COMPLETE)
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_TYPE;
            memset(&dnsSessionData->curr_txt, 0, sizeof(DNSNameState));
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
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_TYPE_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_Q_TYPE_PART:
        dnsSessionData->curr_q.type |= (uint8_t)*data;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_CLASS;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_Q_CLASS:
        dnsSessionData->curr_q.dns_class = (uint8_t)*data << 8;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_CLASS_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
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
    const unsigned char* data, uint16_t bytes_unused, DNSData* dnsSessionData)
{
    if ( !bytes_unused )
        return 0;

    if (dnsSessionData->curr_rec_state < DNS_RESP_STATE_RR_NAME_COMPLETE)
    {
        uint16_t new_bytes_unused = ParseDNSName(data, bytes_unused, dnsSessionData);
        uint16_t bytes_used = bytes_unused - new_bytes_unused;

        if (dnsSessionData->curr_txt.name_state == DNS_RESP_STATE_NAME_COMPLETE)
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_TYPE;
            memset(&dnsSessionData->curr_txt, 0, sizeof(DNSNameState));
            data = data + bytes_used;
        }
        bytes_unused = new_bytes_unused;

        if ( !bytes_unused )
            return 0;  /* ran out of data */
    }

    switch (dnsSessionData->curr_rec_state)
    {
    case DNS_RESP_STATE_RR_TYPE:
        dnsSessionData->curr_rr.type = (uint8_t)*data << 8;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_TYPE_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_RR_TYPE_PART:
        dnsSessionData->curr_rr.type |= (uint8_t)*data;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_CLASS;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_RR_CLASS:
        dnsSessionData->curr_rr.dns_class = (uint8_t)*data << 8;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_CLASS_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
        // Fall through

    case DNS_RESP_STATE_RR_CLASS_PART:
        dnsSessionData->curr_rr.dns_class |= (uint8_t)*data;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_TTL;
        data++;

        if ( !--bytes_unused )
            return 0;
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
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDLENGTH;
        // Fall through

    case DNS_RESP_STATE_RR_RDLENGTH:
        dnsSessionData->curr_rr.length = (uint8_t)*data << 8;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDLENGTH_PART;
        data++;

        if ( !--bytes_unused )
            return 0;
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

            /* include the NULL */
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
    case DNS_RR_TYPE_NS:
    case DNS_RR_TYPE_CNAME:
    case DNS_RR_TYPE_SOA:
    case DNS_RR_TYPE_WKS:
    case DNS_RR_TYPE_PTR:
    case DNS_RR_TYPE_HINFO:
    case DNS_RR_TYPE_MX:
        bytes_unused = SkipDNSRData(data, bytes_unused, dnsSessionData);
        break;
    default:
        /* Not one of the known types.  Stop looking at this session
         * as DNS. */
        dnsSessionData->flags |= DNS_FLAG_NOT_DNS;
        break;
    }

    return bytes_unused;
}

static void ParseDNSResponseMessage(Packet* p, DNSData* dnsSessionData)
{
    uint16_t bytes_unused = p->dsize;
    int i;
    const unsigned char* data = p->data;

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
                /* No more data */
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
                    /* No more data */
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
            for (i=dnsSessionData->curr_rec; i<dnsSessionData->hdr.answers; i++)
            {
                bytes_unused = ParseDNSAnswer(data, bytes_unused, dnsSessionData);

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
                            memset(&dnsSessionData->curr_txt, 0, sizeof(DNSNameState));
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
            for (i=dnsSessionData->curr_rec; i<dnsSessionData->hdr.authorities; i++)
            {
                bytes_unused = ParseDNSAnswer(data, bytes_unused, dnsSessionData);

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
                            memset(&dnsSessionData->curr_txt, 0, sizeof(DNSNameState));
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
            for (i=dnsSessionData->curr_rec; i<dnsSessionData->hdr.authorities; i++)
            {
                bytes_unused = ParseDNSAnswer(data, bytes_unused, dnsSessionData);

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
                            memset(&dnsSessionData->curr_txt, 0, sizeof(DNSNameState));
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

static void snort_dns(Packet* p)
{
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

        // If we're waiting on stream reassembly, don't process this packet.
        if ( p->packet_flags & PKT_STREAM_INSERT )
            return;
    }

    // Get the direction of the packet.
    bool from_server = ( (p->is_from_server() ) ? true : false );


    // Attempt to get a previously allocated DNS block.
    DNSData* dnsSessionData = get_dns_session_data(p, from_server);

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

    if ( from_server )
    {
        ParseDNSResponseMessage(p, dnsSessionData);
    }
    else
    {
        dnsstats.requests++;
    }
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Dns : public Inspector
{
public:
    Dns(DnsModule*);

    void show(SnortConfig*) override;
    void eval(Packet*) override;
};

Dns::Dns(DnsModule*)
{ }

void Dns::show(SnortConfig*)
{
    LogMessage("DNS\n");
}

void Dns::eval(Packet* p)
{
    // precondition - what we registered for
    assert((p->is_udp() and p->dsize and p->data) or p->has_tcp_data());
    assert(p->flow);

    ++dnsstats.packets;
    snort_dns(p);
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
const BaseApi* sin_dns = &dns_api.base;
#endif

