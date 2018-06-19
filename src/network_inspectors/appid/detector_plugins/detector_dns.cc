//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
    DNS_STATE_RESPONSE
};

struct ServiceDNSData
{
    DNSState state;
    uint16_t id;
};

// DNS host pattern structure
struct DNSHostPattern
{
    uint8_t type;
    AppId appId;
    uint8_t* pattern;
    int pattern_size;
};

struct DetectorDNSHostPattern
{
    DNSHostPattern* dpattern;
    DetectorDNSHostPattern* next;
};

struct MatchedDNSPatterns
{
    DNSHostPattern* mpattern;
    MatchedDNSPatterns* next;
};

struct ServiceDnsConfig
{
    DetectorDNSHostPattern* DetectorDNSHostPatternList;
    snort::SearchTool* dns_host_host_matcher;
};
static ServiceDnsConfig serviceDnsConfig;      // DNS service configuration

static int dns_host_pattern_match(void* id, void*, int, void* data, void*)
{
    MatchedDNSPatterns* cm;
    MatchedDNSPatterns** matches = (MatchedDNSPatterns**)data;
    DNSHostPattern* target = (DNSHostPattern*)id;

    cm = (MatchedDNSPatterns*)snort_calloc(sizeof(MatchedDNSPatterns));
    cm->mpattern = target;
    cm->next = *matches;
    *matches = cm;

    return 0;
}

static int dns_host_detector_create_matcher(DetectorDNSHostPattern* list)
{
    DetectorDNSHostPattern* element = nullptr;

    if (serviceDnsConfig.dns_host_host_matcher)
        delete serviceDnsConfig.dns_host_host_matcher;

    serviceDnsConfig.dns_host_host_matcher = new snort::SearchTool("ac_full", true);
    if (!serviceDnsConfig.dns_host_host_matcher)
        return 0;

    /* Add patterns from Lua API */
    for (element = list; element; element = element->next)
    {
        serviceDnsConfig.dns_host_host_matcher->add((char*)element->dpattern->pattern,
            element->dpattern->pattern_size, element->dpattern, true);
    }

    serviceDnsConfig.dns_host_host_matcher->prep();

    return 1;
}

int dns_host_detector_process_patterns()
{
    int retVal = 1;
    if (!dns_host_detector_create_matcher(serviceDnsConfig.DetectorDNSHostPatternList))
        retVal = 0;
    return retVal;
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


void DnsValidator::add_dns_query_info(AppIdSession& asd, uint16_t id, const uint8_t* host, uint8_t
    host_len, uint16_t host_offset, uint16_t record_type)
{
    AppIdDnsSession* dsession = asd.get_dns_session();
    if ( ( dsession->get_state() != 0 ) && ( dsession->get_id() != id ) )
        dsession->reset();

    if (dsession->get_state() & DNS_GOT_QUERY)
        return;
    dsession->set_state(dsession->get_state() | DNS_GOT_QUERY);

    dsession->set_id(id);
    dsession->set_record_type(record_type);

    if (!dsession->get_host())
    {
        if ((host != nullptr) && (host_len > 0) && (host_offset > 0))
        {
            char* new_host = dns_parse_host(host, host_len);
            dsession->set_host(new_host);
            dsession->set_host_offset(host_offset);
       }
    }
}

void DnsValidator::add_dns_response_info(AppIdSession& asd, uint16_t id, const uint8_t* host,
    uint8_t host_len, uint16_t host_offset, uint8_t response_type, uint32_t ttl)
{
    AppIdDnsSession* dsession = asd.get_dns_session();
        if ( ( dsession->get_state() != 0 ) && ( dsession->get_id() != id ) )
            dsession->reset();

    if (dsession->get_state() & DNS_GOT_RESPONSE)
        return;
    dsession->set_state(dsession->get_state() | DNS_GOT_RESPONSE);

    dsession->set_id(id);
    dsession->set_ttl(ttl);
    dsession->set_response_type(response_type);

    if (!dsession->get_host())
    {
        if ((host != nullptr) && (host_len > 0) && (host_offset > 0))
        {
            char* new_host = dns_parse_host(host, host_len);
            dsession->set_host(new_host);
            dsession->set_host_offset(host_offset);
        }
    }
}

int DnsValidator::dns_validate_label(const uint8_t* data, uint16_t* offset, uint16_t size,
    uint8_t* len, unsigned* len_valid)
{
    const DNSLabelPtr* lbl_ptr;
    const DNSLabelBitfield* lbl_bit;
    uint16_t tmp;

    *len = 0;
    *len_valid = 1;

    while ((size > *offset) && (size-(*offset)) >= (int)offsetof(DNSLabel, name))
    {
        const DNSLabel* lbl = (const DNSLabel*)(data + (*offset));

        switch (lbl->len & DNS_LENGTH_FLAGS)
        {
        case 0xC0:
            *len_valid = 0;
            lbl_ptr = (const DNSLabelPtr*)lbl;
            *offset += offsetof(DNSLabelPtr, data);
            if (*offset >= size)
                return APPID_NOMATCH;
            tmp = (uint16_t)(ntohs(lbl_ptr->position) & 0x3FFF);
            if (tmp > size - offsetof(DNSLabel, name))
                return APPID_NOMATCH;
            return APPID_SUCCESS;
        case 0x00:
            *offset += offsetof(DNSLabel, name);
            if (!lbl->len)
            {
                (*len)--;    // take off the extra '.' at the end
                return APPID_SUCCESS;
            }
            *offset += lbl->len;
            *len += lbl->len + 1;    // add 1 for '.'
            break;
        case 0x40:
            *len_valid = 0;
            if (lbl->len != 0x41)
                return APPID_NOMATCH;
            *offset += offsetof(DNSLabelBitfield, data);
            if (*offset >= size)
                return APPID_NOMATCH;
            lbl_bit = (const DNSLabelBitfield*)lbl;
            if (lbl_bit->len)
            {
                *offset += ((lbl_bit->len - 1) / 8) + 1;
            }
            else
            {
                *offset += 32;
            }
            break;
        default:
            *len_valid = 0;
            return APPID_NOMATCH;
        }
    }
    return APPID_NOMATCH;
}

int DnsValidator::dns_validate_query(const uint8_t* data, uint16_t* offset, uint16_t size,
    uint16_t id, bool host_reporting, AppIdSession& asd)
{
    int ret;
    const uint8_t* host;
    uint8_t host_len;
    unsigned host_len_valid;
    uint16_t host_offset;

    host = data + *offset;
    host_offset = *offset;
    ret = dns_validate_label(data, offset, size, &host_len, &host_len_valid);

    if (ret == APPID_SUCCESS)
    {
        const DNSQueryFixed* query = (const DNSQueryFixed*)(data + *offset);
        *offset += sizeof(DNSQueryFixed);

        if (host_reporting)
        {
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
                add_dns_query_info(asd, id, host, host_len, host_offset, record_type);
                break;
            case PATTERN_PTR_REC:
                add_dns_query_info(asd, id, nullptr, 0, 0, record_type);
                break;
            default:
                break;
            }
        }
    }
    return ret;
}

int DnsValidator::dns_validate_answer(const uint8_t* data, uint16_t* offset, uint16_t size,
    uint16_t id, uint8_t rcode, bool host_reporting, AppIdSession& asd)
{
    int ret;
    uint8_t host_len;
    unsigned host_len_valid;
    uint16_t r_data_offset;

    ret = dns_validate_label(data, offset, size, &host_len, &host_len_valid);
    if (ret == APPID_SUCCESS)
    {
        const DNSAnswerData* ad = (const DNSAnswerData*)(data + (*offset));
        *offset += sizeof(DNSAnswerData);
        if (*offset > size)
            return APPID_NOMATCH;
        r_data_offset = *offset;
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
                add_dns_response_info(asd, id, nullptr, 0, 0, rcode, ttl);
                break;
            case PATTERN_PTR_REC:
                {
                    const uint8_t* host = data + r_data_offset;
                    uint16_t host_offset = r_data_offset;

                    ret = dns_validate_label(
                        data, &r_data_offset, size, &host_len, &host_len_valid);

                    if ((host_len == 0) || (!host_len_valid))
                    {
                        host = nullptr;
                        host_len = 0;
                        host_offset = 0;
                    }
                    add_dns_response_info(
                        asd, id, host, host_len, host_offset, rcode, ttl);
                }
                break;
            default:
                break;
            }
        }
    }
    return ret;
}

int DnsValidator::dns_validate_header(const AppidSessionDirection dir, const DNSHeader* hdr,
    bool host_reporting, AppIdSession& asd)
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
            asd.get_dns_session()->reset();
        return dir == APP_ID_FROM_INITIATOR ? APPID_SUCCESS : APPID_REVERSED;
    }
    else     // Response.
        return dir == APP_ID_FROM_INITIATOR ? APPID_REVERSED : APPID_SUCCESS;
}

int DnsValidator::validate_packet(const uint8_t* data, uint16_t size, const int,
    bool host_reporting, AppIdSession& asd)
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
            if (dns_validate_query(data, &offset, size, ntohs(hdr->id), host_reporting, asd) !=
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
                host_reporting, asd) != APPID_SUCCESS)
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
                host_reporting, asd) != APPID_SUCCESS)
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
                host_reporting, asd) != APPID_SUCCESS)
            {
                return APPID_NOMATCH;
            }
        }
    }

    if (hdr->QR && (hdr->RCODE != 0))    // error response
        add_dns_response_info(asd, ntohs(hdr->id), nullptr, 0, 0, hdr->RCODE, 0);

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
        args.config->mod_config->dns_host_reporting, args.asd)) != APPID_SUCCESS)
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
                        args.config->mod_config->dns_host_reporting, args.asd);
                    if (rval == APPID_SUCCESS)
                        goto inprocess;
                }
                goto invalid;
            }
            else
            {
                // To get here, we missed the initial query, but now we've got
                // a response.
                rval = validate_packet(args.data, args.size, args.dir,
                    args.config->mod_config->dns_host_reporting, args.asd);
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

    rval = validate_packet(args.data, args.size, args.dir,
        args.config->mod_config->dns_host_reporting, args.asd);
    if ((rval == APPID_SUCCESS) && (args.dir == APP_ID_FROM_INITIATOR))
        goto inprocess;

udp_done:
    switch (rval)
    {
    case APPID_SUCCESS:
success:
        args.asd.set_session_flags(APPID_SESSION_CONTINUE);
        return add_service(args.asd, args.pkt, args.dir, APP_ID_DNS);

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
        add_app(args.asd, APP_ID_NONE, APP_ID_DNS, nullptr);
        service_inprocess(args.asd, args.pkt, args.dir);
        return APPID_INPROCESS;

    default:
        return rval;
    }
}

int DnsTcpServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    int rval;

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
        const DNSTCPHeader* hdr = (const DNSTCPHeader*)args.data;
        const uint8_t* data = args.data + sizeof(DNSTCPHeader);
        uint16_t size = args.size - sizeof(DNSTCPHeader);
        uint16_t tmp = ntohs(hdr->length);
        if (tmp < sizeof(DNSHeader) || dns_validate_header(args.dir, (const DNSHeader*)data,
            args.config->mod_config->dns_host_reporting, args.asd))
        {
            if (args.dir == APP_ID_FROM_INITIATOR)
                goto not_compatible;
            else
                goto fail;
        }

        if (tmp > size)
            goto not_compatible;
        rval = validate_packet(data, size, args.dir,
            args.config->mod_config->dns_host_reporting, args.asd);
        if (rval != APPID_SUCCESS)
            goto tcp_done;

        ServiceDNSData* dd = static_cast<ServiceDNSData*>(data_get(args.asd));
        if (!dd)
        {
            dd = static_cast<ServiceDNSData*>(snort_calloc(sizeof(ServiceDNSData)));
            if (data_add(args.asd, dd, &snort_free))
                dd->state = DNS_STATE_QUERY;
        }

        if (dd->state == DNS_STATE_QUERY)
        {
            if (args.dir != APP_ID_FROM_INITIATOR)
                goto fail;
            dd->id = ((const DNSHeader*)data)->id;
            dd->state = DNS_STATE_RESPONSE;
            goto inprocess;
        }
        else
        {
            if (args.dir != APP_ID_FROM_RESPONDER || dd->id != ((const DNSHeader*)data)->id)
                goto fail;
        }
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
        return rval;
    }

success:
    args.asd.set_session_flags(APPID_SESSION_CONTINUE);
    return add_service(args.asd, args.pkt, args.dir, APP_ID_DNS);

not_compatible:
    incompatible_data(args.asd, args.pkt, args.dir);
    return APPID_NOT_COMPATIBLE;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;

inprocess:
    add_app(args.asd, APP_ID_NONE, APP_ID_DNS, nullptr);
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;
}

static int dns_host_scan_patterns(snort::SearchTool* matcher, const uint8_t* pattern, size_t size,
    AppId* ClientAppId, AppId* payloadId)
{
    MatchedDNSPatterns* mp = nullptr;
    MatchedDNSPatterns* tmpMp;
    DNSHostPattern* best_match;

    if (!matcher)
        return 0;

    matcher->find_all((const char*)pattern, size, dns_host_pattern_match, false, &mp);

    if (!mp)
        return 0;

    best_match = mp->mpattern;
    tmpMp = mp->next;
    snort_free(mp);

    while ((mp = tmpMp))
    {
        tmpMp = mp->next;
        if (mp->mpattern->pattern_size > best_match->pattern_size)
        {
            best_match = mp->mpattern;
        }
        snort_free(mp);
    }

    switch (best_match->type)
    {
    // type 0 means WEB APP
    case 0:
        *ClientAppId = APP_ID_DNS;
        *payloadId = best_match->appId;
        break;
    // type 1 means CLIENT
    case 1:
        *ClientAppId = best_match->appId;
        *payloadId = 0;
        break;
    default:
        return 0;
    }

    return 1;
}

int dns_host_scan_hostname(const uint8_t* pattern, size_t size, AppId* ClientAppId,
    AppId* payloadId)
{
    return dns_host_scan_patterns(serviceDnsConfig.dns_host_host_matcher, pattern, size,
        ClientAppId, payloadId);
}

void service_dns_host_clean()
{
    dns_detector_free_patterns();

    if (serviceDnsConfig.dns_host_host_matcher )
    {
        delete serviceDnsConfig.dns_host_host_matcher;
        serviceDnsConfig.dns_host_host_matcher = nullptr;
    }
}

static int dns_add_pattern(DetectorDNSHostPattern** list, uint8_t* pattern_str, size_t
    pattern_size, uint8_t type, AppId app_id)
{
    DetectorDNSHostPattern* new_dns_host_pattern;

    new_dns_host_pattern = static_cast<DetectorDNSHostPattern*>(snort_calloc(
        sizeof(DetectorDNSHostPattern)));
    new_dns_host_pattern->dpattern = static_cast<DNSHostPattern*>(snort_calloc(
        sizeof(DNSHostPattern)));

    new_dns_host_pattern->dpattern->type = type;
    new_dns_host_pattern->dpattern->appId = app_id;
    new_dns_host_pattern->dpattern->pattern = pattern_str;
    new_dns_host_pattern->dpattern->pattern_size = pattern_size;

    new_dns_host_pattern->next = *list;
    *list = new_dns_host_pattern;

    return 1;
}

int dns_add_host_pattern(uint8_t* pattern_str, size_t pattern_size, uint8_t type, AppId app_id)
{
    return dns_add_pattern(&serviceDnsConfig.DetectorDNSHostPatternList, pattern_str, pattern_size,
        type, app_id);
}

static void dns_patterns_free(DetectorDNSHostPattern** list)
{
    DetectorDNSHostPattern* tmp_pattern;

    while ((tmp_pattern = *list))
    {
        *list = tmp_pattern->next;
        if (tmp_pattern->dpattern)
        {
            if (tmp_pattern->dpattern->pattern)
                snort_free(tmp_pattern->dpattern->pattern);
            snort_free (tmp_pattern->dpattern);
        }
        snort_free(tmp_pattern);
    }
}

void dns_detector_free_patterns()
{
    dns_patterns_free(&serviceDnsConfig.DetectorDNSHostPatternList);
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

