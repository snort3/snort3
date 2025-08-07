//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// detector_dns.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detector_dns.h"

#include "appid_config.h"
#include "appid_dns_session.h"
#include "app_info_table.h"
#include "application_ids.h"

using namespace snort;

#define MAX_DNS_HOST_NAME_LEN 253

#define MAX_OPCODE     5
#define INVALID_OPCODE 3

#define MAX_RCODE 10

#define RCODE_NXDOMAIN 3

#define DNS_LENGTH_FLAGS 0xC0

#define PATTERN_A_REC      1
#define PATTERN_AAAA_REC  28
#define PATTERN_CNAME_REC  5
#define PATTERN_SRV_REC   33
#define PATTERN_TXT_REC   16
#define PATTERN_MX_REC    15
#define PATTERN_SOA_REC    6
#define PATTERN_NS_REC     2
#define PATTERN_ANY_REC  255
#define PATTERN_PTR_REC   12

#pragma pack(1)

struct DNSHeader
{
    uint16_t id;
#if defined(SF_BIGENDIAN)
    uint8_t QR : 1,
        Opcode : 4,
        AA : 1,
        TC : 1,
        RD : 1;
    uint8_t RA : 1,
        Z : 1,
        AD : 1,
        CD : 1,
        RCODE : 4;
#else
    uint8_t RD : 1,
        TC : 1,
        AA : 1,
        Opcode : 4,
        QR : 1;
    uint8_t RCODE : 4,
        CD : 1,
        AD : 1,
        Z : 1,
        RA : 1;
#endif
    uint16_t QDCount;
    uint16_t ANCount;
    uint16_t NSCount;
    uint16_t ARCount;
};

struct DNSTCPHeader
{
    uint16_t length;
};

struct DNSLabel
{
    uint8_t len;
    uint8_t name;
};

struct DNSLabelPtr
{
    uint16_t position;
    uint8_t data;
};

struct DNSLabelBitfield
{
    uint8_t id;
    uint8_t len;
    uint8_t data;
};

struct DNSQueryFixed
{
    uint16_t QType;
    uint16_t QClass;
};

struct DNSAnswerData
{
    uint16_t type;
    uint16_t klass;
    uint32_t ttl;
    uint16_t r_len;
};

#pragma pack()

enum DNSState
{
    DNS_STATE_QUERY,
    DNS_STATE_RESPONSE,
    DNS_STATE_MULTI_QUERY
};

class ServiceDNSData : public AppIdFlowData
{
public:
    ServiceDNSData() = default;
    ~ServiceDNSData() override;
    void save_dns_cache(uint16_t size, const uint8_t* data);
    void free_dns_cache();

    DNSState state = DNS_STATE_QUERY;
    uint8_t* cached_data = nullptr;
    uint16_t cached_len = 0;
    uint16_t id = 0;
};

void ServiceDNSData::save_dns_cache(uint16_t size, const uint8_t* data)
{
    if(size > 0)
    {
        cached_data = (uint8_t*)snort_calloc(size, sizeof(uint8_t));
        if(cached_data)
        {
            memcpy(cached_data, data, size);
        }
        cached_len = size;
    }
}

void ServiceDNSData::free_dns_cache()
{
    if(cached_data)
    {
        snort_free(cached_data);
        cached_data = nullptr;
    }

    cached_len = 0;
}

ServiceDNSData::~ServiceDNSData()
{
    free_dns_cache();
}

DnsTcpServiceDetector::DnsTcpServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "DNS-TCP";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_DNS, APPINFO_FLAG_SERVICE_UDP_REVERSED | APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { 53, IpProtocol::TCP, false },
        { 5300, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


DnsUdpServiceDetector::DnsUdpServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "DNS-UDP";
    proto = IpProtocol::UDP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_DNS, APPINFO_FLAG_SERVICE_UDP_REVERSED | APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { 53, IpProtocol::UDP, false },
        { 53, IpProtocol::UDP, true },
        { 5300, IpProtocol::UDP, false }
    };

    handler->register_detector(name, this, proto);
}


APPID_STATUS_CODE DnsValidator::add_dns_query_info(AppIdSession& asd, uint16_t id,
    const uint8_t* host, uint8_t host_len, uint16_t host_offset, uint16_t record_type,
    uint16_t options_offset, AppidChangeBits& change_bits)
{
    AppIdDnsSession* dsession = asd.get_dns_session();
    if (!dsession)
        dsession = asd.create_dns_session();
    if ( ( dsession->get_state() != 0 ) && ( dsession->get_id() != id ) )
        dsession->reset();

    if (dsession->get_state() & DNS_GOT_QUERY)
        return APPID_SUCCESS;
    dsession->set_state(dsession->get_state() | DNS_GOT_QUERY);

    dsession->set_id(id);
    dsession->set_record_type(record_type);

    if (!dsession->get_host_len())
    {
        if ((host != nullptr) && (host_len > 0) && (host_offset > 0))
        {
            char* new_host = dns_parse_host(host, host_len);
            if (!new_host)
                return APPID_NOMATCH;
            dsession->set_host(new_host, change_bits, true);
            dsession->set_host_offset(host_offset);
            dsession->set_options_offset(options_offset);
            snort_free(new_host);
       }
    }

    return APPID_SUCCESS;
}

APPID_STATUS_CODE DnsValidator::add_dns_response_info(AppIdSession& asd, uint16_t id,
    const uint8_t* host, uint8_t host_len, uint16_t host_offset, uint8_t response_type, uint32_t ttl,
    AppidChangeBits& change_bits)
{
    AppIdDnsSession* dsession = asd.get_dns_session();
    if (!dsession)
        dsession = asd.create_dns_session();
    if ( ( dsession->get_state() != 0 ) && ( dsession->get_id() != id ) )
        dsession->reset();

    if (dsession->get_state() & DNS_GOT_RESPONSE)
        return APPID_SUCCESS;
    dsession->set_state(dsession->get_state() | DNS_GOT_RESPONSE);

    dsession->set_id(id);
    dsession->set_ttl(ttl);
    dsession->set_response_type(response_type);

    if (!dsession->get_host_len())
    {
        if ((host != nullptr) && (host_len > 0) && (host_offset > 0))
        {
            char* new_host = dns_parse_host(host, host_len);
            if (!new_host)
                return APPID_NOMATCH;
            dsession->set_host(new_host, change_bits, false);
            dsession->set_host_offset(host_offset);
            snort_free(new_host);
        }
    }

    return APPID_SUCCESS;
}

APPID_STATUS_CODE DnsValidator::dns_validate_label(const uint8_t* data, uint16_t& offset, uint16_t size,
    uint8_t& len, bool& len_valid)
{
    const DNSLabelPtr* lbl_ptr;
    const DNSLabelBitfield* lbl_bit;
    uint16_t tmp;

    len = 0;
    len_valid = true;

    while ((size > offset) and (size - offset) >= (int)offsetof(DNSLabel, name))
    {
        const DNSLabel* lbl = (const DNSLabel*)(data + offset);

        switch (lbl->len & DNS_LENGTH_FLAGS)
        {
        case 0xC0:
            len_valid = false;
            lbl_ptr = (const DNSLabelPtr*)lbl;
            offset += offsetof(DNSLabelPtr, data);
            if (offset > size)
                return APPID_NOMATCH;
            tmp = (uint16_t)(ntohs(lbl_ptr->position) & 0x3FFF);
            if (tmp > size - offsetof(DNSLabel, name))
                return APPID_NOMATCH;
            return APPID_SUCCESS;
        case 0x00:
            offset += offsetof(DNSLabel, name);
            if (!lbl->len)
            {
                len--;    // take off the extra '.' at the end
                return APPID_SUCCESS;
            }
            offset += lbl->len;
            if ((len + lbl->len + 1) > MAX_DNS_HOST_NAME_LEN)
            {
                len_valid = false;
                return APPID_NOMATCH;
            }
            len += lbl->len + 1;    // add 1 for '.'
            break;
        case 0x40:
            len_valid = false;
            if (lbl->len != 0x41)
                return APPID_NOMATCH;
            offset += offsetof(DNSLabelBitfield, data);
            if (offset >= size)
                return APPID_NOMATCH;
            lbl_bit = (const DNSLabelBitfield*)lbl;
            if (lbl_bit->len)
            {
                offset += ((lbl_bit->len - 1) / 8) + 1;
            }
            else
            {
                offset += 32;
            }
            break;
        default:
            len_valid = false;
            return APPID_NOMATCH;
        }
    }
    return APPID_NOMATCH;
}

int DnsValidator::dns_validate_query(const uint8_t* data, uint16_t* offset, uint16_t size,
    uint16_t id, bool host_reporting, AppIdSession& asd, AppidChangeBits& change_bits)
{
    int ret;
    const uint8_t* host = data + *offset;
    uint8_t host_len = 0;
    bool host_len_valid = false;
    uint16_t host_offset = *offset;

    ret = dns_validate_label(data, *offset, size, host_len, host_len_valid);

    if ((ret == APPID_SUCCESS) and (host_reporting))
    {
        if ((*offset > size) || ((size - *offset) < (uint16_t)sizeof(DNSQueryFixed)))
            return APPID_NOMATCH;

        const DNSQueryFixed* query = (const DNSQueryFixed*)(data + *offset);

        *offset += sizeof(DNSQueryFixed);

        uint16_t record_type = ntohs(query->QType);

        if ((host_len == 0) || (!host_len_valid))
        {
            host        = nullptr;
            host_len    = 0;
            host_offset = 0;
        }
        switch (record_type)
        {
        case PATTERN_A_REC:
        case PATTERN_AAAA_REC:
        case PATTERN_CNAME_REC:
        case PATTERN_SRV_REC:
        case PATTERN_TXT_REC:
        case PATTERN_MX_REC:
        case PATTERN_SOA_REC:
        case PATTERN_NS_REC:
        case PATTERN_ANY_REC:
            ret = add_dns_query_info(asd, id, host, host_len, host_offset, record_type, *offset, change_bits);
            break;
        case PATTERN_PTR_REC:
            ret = add_dns_query_info(asd, id, nullptr, 0, 0, record_type, *offset, change_bits);
            break;
        default:
            break;
        }
    
    }
    return ret;
}

int DnsValidator::dns_validate_answer(const uint8_t* data, uint16_t* offset, uint16_t size,
    uint16_t id, uint8_t rcode, bool host_reporting, AppIdSession& asd, AppidChangeBits& change_bits)
{
    int ret;
    uint8_t host_len;
    bool host_len_valid;

    ret = dns_validate_label(data, *offset, size, host_len, host_len_valid);
    if (ret == APPID_SUCCESS)
    {
        const DNSAnswerData* ad = (const DNSAnswerData*)(data + (*offset));
        *offset += sizeof(DNSAnswerData);
        if (*offset > size)
            return APPID_NOMATCH;
        uint16_t r_data_offset = *offset;
        *offset += ntohs(ad->r_len);
        if (*offset > size)
            return APPID_NOMATCH;
        if (host_reporting)
        {
            uint16_t record_type = ntohs(ad->type);
            uint32_t ttl = ntohl(ad->ttl);

            switch (record_type)
            {
            case PATTERN_A_REC:
            case PATTERN_AAAA_REC:
            case PATTERN_CNAME_REC:
            case PATTERN_SRV_REC:
            case PATTERN_TXT_REC:
            case PATTERN_MX_REC:
            case PATTERN_SOA_REC:
            case PATTERN_NS_REC:
                ret = add_dns_response_info(asd, id, nullptr, 0, 0, rcode, ttl, change_bits);
                break;
            case PATTERN_PTR_REC:
                {
                    const uint8_t* host = data + r_data_offset;
                    uint16_t host_offset = r_data_offset;

                    ret = dns_validate_label(
                        data, r_data_offset, size, host_len, host_len_valid);

                    if (ret != APPID_SUCCESS)
                        return ret;

                    if ((host_len == 0) || (!host_len_valid))
                    {
                        host = nullptr;
                        host_len = 0;
                        host_offset = 0;
                    }
                    ret = add_dns_response_info(
                        asd, id, host, host_len, host_offset, rcode, ttl, change_bits);
                }
                break;
            default:
                break;
            }
        }
    }
    return ret;
}

int DnsValidator::dns_validate_header(AppidSessionDirection dir, const DNSHeader* hdr,
    bool host_reporting, const AppIdSession& asd)
{
    if (hdr->Opcode > MAX_OPCODE || hdr->Opcode == INVALID_OPCODE)
        return APPID_NOMATCH;
    else if (hdr->Z)
        return APPID_NOMATCH;
    else if (hdr->RCODE > MAX_RCODE)
        return APPID_NOMATCH;
    else if (!hdr->QR)        // Query.
    {
        if (host_reporting)
        {
            AppIdDnsSession* dsession = asd.get_dns_session();
            if (dsession)
                dsession->reset();
        }
        return dir == APP_ID_FROM_INITIATOR ? APPID_SUCCESS : APPID_REVERSED;
    }
    else     // Response.
        return dir == APP_ID_FROM_INITIATOR ? APPID_REVERSED : APPID_SUCCESS;
}

int DnsValidator::validate_packet(const uint8_t* data, uint16_t size, const int,
    bool host_reporting, AppIdSession& asd, AppidChangeBits& change_bits)
{
    uint16_t i;
    uint16_t count;
    const DNSHeader* hdr = (const DNSHeader*)data;
    uint16_t offset;

    if (hdr->TC && size == 512)
        return APPID_SUCCESS;

    offset = sizeof(DNSHeader);

    if (hdr->QDCount)
    {
        count = ntohs(hdr->QDCount);
        for (i=0; i<count; i++)
        {
            if (dns_validate_query(data, &offset, size, ntohs(hdr->id), host_reporting, asd, change_bits) !=
                APPID_SUCCESS)
            {
                return APPID_NOMATCH;
            }
        }
    }

    if (hdr->ANCount)
    {
        count = ntohs(hdr->ANCount);
        for (i=0; i<count; i++)
        {
            if (dns_validate_answer(data, &offset, size, ntohs(hdr->id), hdr->RCODE,
                host_reporting, asd, change_bits) != APPID_SUCCESS)
            {
                return APPID_NOMATCH;
            }
        }
    }

    if (hdr->NSCount)
    {
        count = ntohs(hdr->NSCount);
        for (i=0; i<count; i++)
        {
            if (dns_validate_answer(data, &offset, size, ntohs(hdr->id), hdr->RCODE,
                host_reporting, asd, change_bits) != APPID_SUCCESS)
            {
                return APPID_NOMATCH;
            }
        }
    }

    if (hdr->ARCount)
    {
        count = ntohs(hdr->ARCount);
        for (i=0; i<count; i++)
        {
            if (dns_validate_answer(data, &offset, size, ntohs(hdr->id), hdr->RCODE,
                host_reporting, asd, change_bits) != APPID_SUCCESS)
            {
                return APPID_NOMATCH;
            }
        }
    }

    if (hdr->QR && (hdr->RCODE != 0))    // error response
        return add_dns_response_info(asd, ntohs(hdr->id), nullptr, 0, 0, hdr->RCODE, 0, change_bits);

    return APPID_SUCCESS;
}

int DnsUdpServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    int rval;

    if (!args.size)
        return APPID_INPROCESS;

    if (args.size < sizeof(DNSHeader))
    {
        rval = (args.dir == APP_ID_FROM_INITIATOR) ? APPID_INVALID_CLIENT : APPID_NOMATCH;
        goto udp_done;
    }
    if ((rval = dns_validate_header(args.dir, (const DNSHeader*)args.data,
        args.asd.get_odp_ctxt().dns_host_reporting, args.asd)) != APPID_SUCCESS)
    {
        if (rval == APPID_REVERSED)
        {
            if (args.dir == APP_ID_FROM_RESPONDER)
            {
                if (args.asd.get_session_flags(APPID_SESSION_UDP_REVERSED))
                {
                    // To get here, we missed the initial query, got a
                    // response, and now we've got another query.
                    rval = validate_packet(args.data, args.size, args.dir,
                        args.asd.get_odp_ctxt().dns_host_reporting, args.asd, args.change_bits);
                    if (rval == APPID_SUCCESS)
                        goto inprocess;
                }
                goto invalid;
            }
            else
            {
                // To get here, we missed the initial query, but now we've got
                // a response.
                // Coverity doesn't realize that validate_packet() checks the packet data for valid values
                // coverity[tainted_scalar]
                rval = validate_packet(args.data, args.size, args.dir,
                    args.asd.get_odp_ctxt().dns_host_reporting, args.asd, args.change_bits);
                if (rval == APPID_SUCCESS)
                {
                    args.asd.set_session_flags(APPID_SESSION_UDP_REVERSED);
                    goto success;
                }
                goto nomatch;
            }
        }
        rval = (args.dir == APP_ID_FROM_INITIATOR) ? APPID_INVALID_CLIENT : APPID_NOMATCH;
        goto udp_done;
    }

    // Coverity doesn't realize that validate_packet() checks the packet data for valid values
    // coverity[tainted_scalar]
    rval = validate_packet(args.data, args.size, args.dir,
        args.asd.get_odp_ctxt().dns_host_reporting, args.asd, args.change_bits);
    if ((rval == APPID_SUCCESS) && (args.dir == APP_ID_FROM_INITIATOR))
        goto inprocess;

udp_done:
    switch (rval)
    {
    case APPID_SUCCESS:
success:
        args.asd.set_session_flags(APPID_SESSION_CONTINUE);
        return add_service(args.change_bits, args.asd, args.pkt, args.dir, APP_ID_DNS);

    case APPID_INVALID_CLIENT:
invalid:
        incompatible_data(args.asd, args.pkt, args.dir);
        return APPID_NOT_COMPATIBLE;

    case APPID_NOMATCH:
nomatch:
        fail_service(args.asd, args.pkt, args.dir);
        return APPID_NOMATCH;

    case APPID_INPROCESS:
inprocess:
        add_app(args.asd, APP_ID_NONE, APP_ID_DNS, nullptr, args.change_bits);
        service_inprocess(args.asd, args.pkt, args.dir);
        return APPID_INPROCESS;

    default:
        return rval;
    }
}

int DnsTcpServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    int rval;
    uint8_t* reallocated_data = nullptr;
    const uint8_t* data = args.data;
    uint16_t size = args.size;
    ServiceDNSData* dd = static_cast<ServiceDNSData*>(data_get(args.asd));

    {
        if (!args.size)
            goto inprocess;

        if (args.size < sizeof(DNSTCPHeader))
        {
            if (args.dir == APP_ID_FROM_INITIATOR)
                goto not_compatible;
            else
                goto fail;
        }

        if (!dd)
        {
            dd = new ServiceDNSData;
            data_add(args.asd, dd);
        }

        if (dd->cached_data and dd->cached_len and args.dir == APP_ID_FROM_INITIATOR)
        {
            reallocated_data = static_cast<uint8_t*>(snort_calloc(dd->cached_len + args.size, sizeof(uint8_t)));
            memcpy(reallocated_data, dd->cached_data, dd->cached_len);
            memcpy(reallocated_data + dd->cached_len, args.data, args.size);
            size = dd->cached_len + args.size;
            dd->free_dns_cache();
            data = reallocated_data;
        }

        const DNSTCPHeader* hdr = (const DNSTCPHeader*)data;
        data = data + sizeof(DNSTCPHeader);
        size = size - sizeof(DNSTCPHeader);
        uint16_t tmp = ntohs(hdr->length);

        if (tmp > size and args.dir == APP_ID_FROM_INITIATOR)
        {
            dd->save_dns_cache(args.size, args.data);
            goto inprocess;
        } else if (tmp > size and args.dir == APP_ID_FROM_RESPONDER) {
            goto not_compatible;
        }

        if (tmp < sizeof(DNSHeader) || dns_validate_header(args.dir, (const DNSHeader*)data,
            args.asd.get_odp_ctxt().dns_host_reporting, args.asd))
        {
            if (args.dir == APP_ID_FROM_INITIATOR)
                goto not_compatible;
            else
                goto fail;
        }

        // Coverity doesn't realize that validate_packet() checks the packet data for valid values
        // coverity[tainted_scalar]
        rval = validate_packet(data, size, args.dir,
            args.asd.get_odp_ctxt().dns_host_reporting, args.asd, args.change_bits);
        if (rval != APPID_SUCCESS)
            goto tcp_done;

        if (dd->state == DNS_STATE_QUERY || dd->state == DNS_STATE_MULTI_QUERY)
        {
            if (args.dir != APP_ID_FROM_INITIATOR)
                goto fail;
            dd->id = ((const DNSHeader*)data)->id;
            DNSState current_state = dd->state;
            dd->state = DNS_STATE_RESPONSE;
            if (current_state == DNS_STATE_QUERY)
                goto inprocess;
            goto success;
        }
        else if (args.dir == APP_ID_FROM_RESPONDER && dd->id == ((const DNSHeader*)data)->id)
            dd->state = DNS_STATE_MULTI_QUERY;
        else
            goto fail;
    }
tcp_done:
    switch (rval)
    {
    case APPID_SUCCESS:
        goto success;
    case APPID_INVALID_CLIENT:
        goto not_compatible;
    case APPID_NOMATCH:
        goto fail;
    case APPID_INPROCESS:
        goto inprocess;
    default:
        dd->free_dns_cache();
        return rval;
    }

success:
    if (reallocated_data)
        snort_free(reallocated_data);
    args.asd.set_session_flags(APPID_SESSION_CONTINUE);
    return add_service(args.change_bits, args.asd, args.pkt, args.dir, APP_ID_DNS);

not_compatible:
    if (reallocated_data)
        snort_free(reallocated_data);
    incompatible_data(args.asd, args.pkt, args.dir);
    return APPID_NOT_COMPATIBLE;

fail:
    if (reallocated_data)
        snort_free(reallocated_data);
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;

inprocess:
    if (reallocated_data)
        snort_free(reallocated_data);
    add_app(args.asd, APP_ID_NONE, APP_ID_DNS, nullptr, args.change_bits);
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;
}

char* dns_parse_host(const uint8_t* host, uint8_t host_len)
{
    char* str = static_cast<char*>(snort_calloc(host_len + 1));    // plus '\0' at end
    const uint8_t* src = host;
    char* dst = str;

    uint32_t dstLen = 0;

    while (*src != 0)
    {
        uint8_t len = *src;
        src++;

        if ((dstLen + len) <= host_len)
            memcpy(dst, src, len);
        else
        {
            // Malformed DNS host, return
            snort_free(str);
            return nullptr;
        }
        src += len;
        dst += len;
        *dst = '.';
        dstLen += len + 1;
        dst++;
    }
    str[host_len] = '\0';    // nullptr term
    return str;
}
