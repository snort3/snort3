//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "detector_dns.h"

#include "main/snort_debug.h"
#include "utils/util.h"

#include "appid_module.h"
#include "app_info_table.h"
#include "application_ids.h"
#include "dns_defs.h"

#include "client_plugins/client_app_api.h"
#include "service_plugins/service_api.h"
#include "service_plugins/service_config.h"

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

struct MatchedDNSPatterns
{
    DNSHostPattern* mpattern;
    int index;
    MatchedDNSPatterns* next;
};

static int dns_service_init(const IniServiceAPI* const);
static int dns_udp_validate(ServiceValidationArgs*);
static int dns_tcp_validate(ServiceValidationArgs*);

static RNAServiceElement udp_svc_element =
{
    nullptr,                            // next
    &dns_udp_validate,                  // validate
    nullptr,                            // userdata
    DETECTOR_TYPE_DECODER,              // detectorType
    1,                                  // ref_count
    1,                                  // current_ref_count
    0,                                  // provides_user
    "dns"                               // name
};

static RNAServiceElement tcp_svc_element =
{
    nullptr,                            // next
    &dns_tcp_validate,                  // validate
    nullptr,                            // userdata
    DETECTOR_TYPE_DECODER,              // detectorType
    1,                                  // ref_count
    1,                                  // current_ref_count
    0,                                  // provides_user
    "tcp dns"                               // name
};

static RNAServiceValidationPort pp[] =
{
    { &dns_tcp_validate, 53, IpProtocol::TCP, 0 },
    { &dns_udp_validate, 53, IpProtocol::UDP, 0 },
    { &dns_udp_validate, 53, IpProtocol::UDP, 1 },
    { &dns_tcp_validate, 5300, IpProtocol::TCP, 0 },
    { &dns_udp_validate, 5300, IpProtocol::UDP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule dns_service_mod =
{
    "DNS",              // name
    &dns_service_init,  // init
    pp,                 // pp
    nullptr,            // api
    nullptr,            // next
    0,                  // provides_user
    nullptr,            // clean
    0                   // flow_data_index
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_DNS, APPINFO_FLAG_SERVICE_UDP_REVERSED | APPINFO_FLAG_SERVICE_ADDITIONAL }
};

static CLIENT_APP_RETCODE dns_udp_client_init(const IniClientAppAPI* const, SF_LIST*);
static CLIENT_APP_RETCODE dns_tcp_client_init(const IniClientAppAPI* const, SF_LIST*);
static CLIENT_APP_RETCODE dns_udp_client_validate(
    const uint8_t*, uint16_t, const int, AppIdData*, Packet*, Detector*, const AppIdConfig*);

static CLIENT_APP_RETCODE dns_tcp_client_validate(
    const uint8_t*, uint16_t, const int, AppIdData*, Packet*, Detector*, const AppIdConfig*);

SO_PUBLIC RNAClientAppModule dns_udp_client_mod =
{
    "DNS",                      // name
    IpProtocol::UDP,                // proto
    &dns_udp_client_init,       // init
    nullptr,                    // clean
    &dns_udp_client_validate,   // validate
    1,                          // minimum_matches
    nullptr,                    // api
    nullptr,                    // userData
    0,                          // precedence
    nullptr,                    // finalize
    0,                          // provides_user
    0,                          // flow_data_index
};

SO_PUBLIC RNAClientAppModule dns_tcp_client_mod =
{
    "DNS",                      // name
    IpProtocol::TCP,                // proto
    &dns_tcp_client_init,       // init
    nullptr,                    // clean
    &dns_tcp_client_validate,   // validate
    1,                          // minimum_matches
    nullptr,                    // api
    nullptr,                    // userData
    0,                          // precedence
    nullptr,                    // finalize
    0,                          // provides_user
    0,                          // flow_data_index
};

static CLIENT_APP_RETCODE dns_udp_client_init(const IniClientAppAPI* const, SF_LIST*)
{ return CLIENT_APP_SUCCESS; }

static CLIENT_APP_RETCODE dns_tcp_client_init(const IniClientAppAPI* const, SF_LIST*)
{ return CLIENT_APP_SUCCESS; }

static CLIENT_APP_RETCODE dns_udp_client_validate(
    const uint8_t*, uint16_t, const int, AppIdData*, Packet*, Detector*, const AppIdConfig*)
{ return CLIENT_APP_INPROCESS; }

static CLIENT_APP_RETCODE dns_tcp_client_validate(
    const uint8_t*, uint16_t, const int, AppIdData*, Packet*, Detector*, const AppIdConfig*)
{ return CLIENT_APP_INPROCESS; }

static int dns_host_pattern_match(void* id, void*, int index, void* data, void*)
{
    MatchedDNSPatterns* cm;
    MatchedDNSPatterns** matches = (MatchedDNSPatterns**)data;
    DNSHostPattern* target = (DNSHostPattern*)id;

    cm = (MatchedDNSPatterns*)snort_calloc(sizeof(MatchedDNSPatterns));
    cm->mpattern = target;
    cm->index = index;
    cm->next = *matches;
    *matches = cm;

    return 0;
}

static int dns_host_detector_create_matcher(ServiceDnsConfig* pDnsConfig,
    DetectorDNSHostPattern* list)
{
    DetectorDNSHostPattern* element = nullptr;

    if (pDnsConfig->dns_host_host_matcher)
        delete pDnsConfig->dns_host_host_matcher;

    pDnsConfig->dns_host_host_matcher = new SearchTool("ac_full");
    if (!pDnsConfig->dns_host_host_matcher)
        return 0;

    /* Add patterns from Lua API */
    for (element = list; element; element = element->next)
    {
        pDnsConfig->dns_host_host_matcher->add((char*)element->dpattern->pattern,
            element->dpattern->pattern_size, element->dpattern, true);
    }

    pDnsConfig->dns_host_host_matcher->prep();

    return 1;
}

int dns_host_detector_process_patterns(ServiceDnsConfig* pDnsConfig)
{
    int retVal = 1;
    if (!dns_host_detector_create_matcher(pDnsConfig, pDnsConfig->DetectorDNSHostPatternList))
        retVal = 0;
    return retVal;
}

static int dns_service_init(const IniServiceAPI* const init_api)
{
    unsigned i;
    for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
    {
        DebugFormat(DEBUG_INSPECTOR, "registering appId: %d\n", appIdRegistry[i].appId);
        init_api->RegisterAppId(&dns_udp_validate, appIdRegistry[i].appId,
            appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

static int dns_validate_label(const uint8_t* data, uint16_t* offset, uint16_t size, uint8_t* len,
    unsigned* len_valid)
{
    const DNSLabel* lbl;
    const DNSLabelPtr* lbl_ptr;
    const DNSLabelBitfield* lbl_bit;
    uint16_t tmp;

    *len = 0;
    *len_valid = 1;
    for (;; )
    {
        if ((size <= *offset) || (size-(*offset)) < (int)offsetof(DNSLabel, name))
            return SERVICE_NOMATCH;
        lbl = (DNSLabel*)(data + (*offset));
        switch (lbl->len & DNS_LENGTH_FLAGS)
        {
        case 0xC0:
            *len_valid = 0;
            lbl_ptr = (DNSLabelPtr*)lbl;
            *offset += offsetof(DNSLabelPtr, data);
            if (*offset >= size)
                return SERVICE_NOMATCH;
            tmp = (uint16_t)(ntohs(lbl_ptr->position) & 0x3FFF);
            if (tmp > size - offsetof(DNSLabel, name))
                return SERVICE_NOMATCH;
            return SERVICE_SUCCESS;
        case 0x00:
            *offset += offsetof(DNSLabel, name);
            if (!lbl->len)
            {
                (*len)--;    // take off the extra '.' at the end
                return SERVICE_SUCCESS;
            }
            *offset += lbl->len;
            *len += lbl->len + 1;    // add 1 for '.'
            break;
        case 0x40:
            *len_valid = 0;
            if (lbl->len != 0x41)
                return SERVICE_NOMATCH;
            *offset += offsetof(DNSLabelBitfield, data);
            if (*offset >= size)
                return SERVICE_NOMATCH;
            lbl_bit = (DNSLabelBitfield*)lbl;
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
            return SERVICE_NOMATCH;
        }
    }
    return SERVICE_NOMATCH;
}

static int dns_validate_query(const uint8_t* data, uint16_t* offset, uint16_t size,
    uint16_t id, unsigned host_reporting, AppIdData* flowp)
{
    int ret;
    const uint8_t* host;
    uint8_t host_len;
    unsigned host_len_valid;
    uint16_t host_offset;
    DNSQueryFixed* query;
    uint16_t record_type;

    host = data + *offset;
    host_offset = *offset;
    ret = dns_validate_label(data, offset, size, &host_len, &host_len_valid);
    if (ret == SERVICE_SUCCESS)
    {
        query = (DNSQueryFixed*)(data + *offset);
        *offset += sizeof(DNSQueryFixed);
        if (host_reporting)
        {
            record_type = ntohs(query->QType);
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
                dns_service_mod.api->add_dns_query_info(flowp, id, host, host_len, host_offset,
                    record_type);
                break;
            case PATTERN_PTR_REC:
                dns_service_mod.api->add_dns_query_info(flowp, id, nullptr, 0, 0, record_type);
                break;
            default:
                break;
            }
        }
    }
    return ret;
}

static int dns_validate_answer(const uint8_t* data, uint16_t* offset, uint16_t size,
    uint16_t id, uint8_t rcode, unsigned host_reporting, AppIdData* flowp)
{
    int ret;
    const uint8_t* host;
    uint8_t host_len;
    unsigned host_len_valid;
    uint16_t host_offset;
    uint16_t record_type;
    uint32_t ttl;
    uint16_t r_data_offset;

    ret = dns_validate_label(data, offset, size, &host_len, &host_len_valid);
    if (ret == SERVICE_SUCCESS)
    {
        DNSAnswerData* ad = (DNSAnswerData*)(data + (*offset));
        *offset += sizeof(DNSAnswerData);
        if (*offset > size)
            return SERVICE_NOMATCH;
        r_data_offset = *offset;
        *offset += ntohs(ad->r_len);
        if (*offset > size)
            return SERVICE_NOMATCH;
        if (host_reporting)
        {
            record_type = ntohs(ad->type);
            ttl         = ntohl(ad->ttl);
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
                dns_service_mod.api->add_dns_response_info(flowp, id, nullptr, 0, 0, rcode, ttl);
                break;
            case PATTERN_PTR_REC:
                host = data + r_data_offset;
                host_offset = r_data_offset;
                ret = dns_validate_label(data, &r_data_offset, size, &host_len, &host_len_valid);
                if ((host_len == 0) || (!host_len_valid))
                {
                    host        = nullptr;
                    host_len    = 0;
                    host_offset = 0;
                }
                dns_service_mod.api->add_dns_response_info(flowp, id, host, host_len, host_offset,
                    rcode, ttl);
                break;
            default:
                break;
            }
        }
    }
    return ret;
}

static int dns_validate_header(const int dir, DNSHeader* hdr,
    unsigned host_reporting, AppIdData* flowp)
{
    if (hdr->Opcode > MAX_OPCODE || hdr->Opcode == INVALID_OPCODE)
    {
        return SERVICE_NOMATCH;
    }
    if (hdr->Z)
    {
        return SERVICE_NOMATCH;
    }
    if (hdr->RCODE > MAX_RCODE)
    {
        return SERVICE_NOMATCH;
    }
    if (!hdr->QR)
    {
        // Query.
        if (host_reporting)
            dns_service_mod.api->reset_dns_info(flowp);
        return dir == APP_ID_FROM_INITIATOR ? SERVICE_SUCCESS : SERVICE_REVERSED;
    }

    // Response.
    return dir == APP_ID_FROM_INITIATOR ? SERVICE_REVERSED : SERVICE_SUCCESS;
}

static int validate_packet(const uint8_t* data, uint16_t size, const int,
    unsigned host_reporting, AppIdData* flowp)
{
    uint16_t i;
    uint16_t count;
    const DNSHeader* hdr = (const DNSHeader*)data;
    uint16_t offset;

    if (hdr->TC && size == 512)
        return SERVICE_SUCCESS;

    offset = sizeof(DNSHeader);

    if (hdr->QDCount)
    {
        count = ntohs(hdr->QDCount);
        for (i=0; i<count; i++)
        {
            if (dns_validate_query(data, &offset, size, ntohs(hdr->id), host_reporting, flowp) !=
                SERVICE_SUCCESS)
            {
                return SERVICE_NOMATCH;
            }
        }
    }

    if (hdr->ANCount)
    {
        count = ntohs(hdr->ANCount);
        for (i=0; i<count; i++)
        {
            if (dns_validate_answer(data, &offset, size, ntohs(hdr->id), hdr->RCODE,
                host_reporting, flowp) != SERVICE_SUCCESS)
            {
                return SERVICE_NOMATCH;
            }
        }
    }

    if (hdr->NSCount)
    {
        count = ntohs(hdr->NSCount);
        for (i=0; i<count; i++)
        {
            if (dns_validate_answer(data, &offset, size, ntohs(hdr->id), hdr->RCODE,
                host_reporting, flowp) != SERVICE_SUCCESS)
            {
                return SERVICE_NOMATCH;
            }
        }
    }

    if (hdr->ARCount)
    {
        count = ntohs(hdr->ARCount);
        for (i=0; i<count; i++)
        {
            if (dns_validate_answer(data, &offset, size, ntohs(hdr->id), hdr->RCODE,
                host_reporting, flowp) != SERVICE_SUCCESS)
            {
                return SERVICE_NOMATCH;
            }
        }
    }

    if (hdr->QR && (hdr->RCODE != 0))    // error response
        dns_service_mod.api->add_dns_response_info(flowp, ntohs(hdr->id), nullptr, 0, 0,
            hdr->RCODE,
            0);

    return SERVICE_SUCCESS;
}

static int dns_udp_validate(ServiceValidationArgs* args)
{
    int rval;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (!size)
        return SERVICE_INPROCESS;

    if (size < sizeof(DNSHeader))
    {
        rval = (dir == APP_ID_FROM_INITIATOR) ? SERVICE_INVALID_CLIENT : SERVICE_NOMATCH;
        goto udp_done;
    }
    if ((rval = dns_validate_header(dir, (DNSHeader*)data,
            pAppidActiveConfig->mod_config->dns_host_reporting, flowp)) != SERVICE_SUCCESS)
    {
        if (rval == SERVICE_REVERSED)
        {
            if (dir == APP_ID_FROM_RESPONDER)
            {
                if (getAppIdFlag(flowp, APPID_SESSION_UDP_REVERSED))
                {
                    // To get here, we missed the initial query, got a
                    // response, and now we've got another query.
                    rval = validate_packet(data, size, dir,
                        pAppidActiveConfig->mod_config->dns_host_reporting, flowp);
                    if (rval == SERVICE_SUCCESS)
                        goto inprocess;
                }
                goto invalid;
            }
            else
            {
                // To get here, we missed the initial query, but now we've got
                // a response.
                rval = validate_packet(data, size, dir,
                    pAppidActiveConfig->mod_config->dns_host_reporting, flowp);
                if (rval == SERVICE_SUCCESS)
                {
                    setAppIdFlag(flowp, APPID_SESSION_UDP_REVERSED);
                    goto success;
                }
                goto nomatch;
            }
        }
        rval = (dir == APP_ID_FROM_INITIATOR) ? SERVICE_INVALID_CLIENT : SERVICE_NOMATCH;
        goto udp_done;
    }

    rval = validate_packet(data, size, dir,
        pAppidActiveConfig->mod_config->dns_host_reporting, flowp);
    if ((rval == SERVICE_SUCCESS) && (dir == APP_ID_FROM_INITIATOR))
        goto inprocess;

udp_done:
    switch (rval)
    {
    case SERVICE_SUCCESS:
success:
        setAppIdFlag(flowp, APPID_SESSION_CONTINUE);
        dns_service_mod.api->add_service(flowp, args->pkt, dir, &udp_svc_element,
            APP_ID_DNS, nullptr, nullptr, nullptr);
        appid_stats.dns_udp_flows++;
        return SERVICE_SUCCESS;
    case SERVICE_INVALID_CLIENT:
invalid:
        dns_service_mod.api->incompatible_data(flowp, args->pkt, dir, &udp_svc_element,
            dns_service_mod.flow_data_index,
            args->pConfig);
        return SERVICE_NOT_COMPATIBLE;
    case SERVICE_NOMATCH:
nomatch:
        dns_service_mod.api->fail_service(flowp, args->pkt, dir, &udp_svc_element,
            dns_service_mod.flow_data_index,
            args->pConfig);
        return SERVICE_NOMATCH;
    case SERVICE_INPROCESS:
inprocess:
        dns_udp_client_mod.api->add_app(flowp, APP_ID_NONE, APP_ID_DNS, nullptr);
        dns_service_mod.api->service_inprocess(flowp, args->pkt, dir, &udp_svc_element);
        return SERVICE_INPROCESS;
    default:
        return rval;
    }
}

static int dns_tcp_validate(ServiceValidationArgs* args)
{
    ServiceDNSData* dd;
    const DNSTCPHeader* hdr;
    uint16_t tmp;
    int rval;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;
    if (size < sizeof(DNSTCPHeader))
    {
        if (dir == APP_ID_FROM_INITIATOR)
            goto not_compatible;
        else
            goto fail;
    }
    hdr = (DNSTCPHeader*)data;
    data += sizeof(DNSTCPHeader);
    size -= sizeof(DNSTCPHeader);
    tmp = ntohs(hdr->length);
    if (tmp < sizeof(DNSHeader) || dns_validate_header(dir, (DNSHeader*)data,
        pAppidActiveConfig->mod_config->dns_host_reporting, flowp))
    {
        if (dir == APP_ID_FROM_INITIATOR)
            goto not_compatible;
        else
            goto fail;
    }

    if (tmp > size)
        goto not_compatible;
    rval = validate_packet(data, size, dir, pAppidActiveConfig->mod_config->dns_host_reporting,
        flowp);
    if (rval != SERVICE_SUCCESS)
        goto tcp_done;

    dd = static_cast<ServiceDNSData*>(dns_service_mod.api->data_get(flowp,
        dns_service_mod.flow_data_index));
    if (!dd)
    {
        dd = static_cast<ServiceDNSData*>(snort_calloc(sizeof(ServiceDNSData)));
        if (dns_service_mod.api->data_add(flowp, dd, dns_service_mod.flow_data_index, &snort_free))
            dd->state = DNS_STATE_QUERY;
    }

    if (dd->state == DNS_STATE_QUERY)
    {
        if (dir != APP_ID_FROM_INITIATOR)
            goto fail;
        dd->id = ((DNSHeader*)data)->id;
        dd->state = DNS_STATE_RESPONSE;
        goto inprocess;
    }
    else
    {
        if (dir != APP_ID_FROM_RESPONDER || dd->id != ((DNSHeader*)data)->id)
            goto fail;
    }

tcp_done:
    switch (rval)
    {
    case SERVICE_SUCCESS:
        goto success;
    case SERVICE_INVALID_CLIENT:
        goto not_compatible;
    case SERVICE_NOMATCH:
        goto fail;
    case SERVICE_INPROCESS:
        goto inprocess;
    default:
        return rval;
    }

success:
    setAppIdFlag(flowp, APPID_SESSION_CONTINUE);
    dns_service_mod.api->add_service(flowp, args->pkt, dir, &tcp_svc_element,
        APP_ID_DNS, nullptr, nullptr, nullptr);
    appid_stats.dns_tcp_flows++;
    return SERVICE_SUCCESS;

not_compatible:
    dns_service_mod.api->incompatible_data(flowp, args->pkt, dir, &tcp_svc_element,
        dns_service_mod.flow_data_index,
        args->pConfig);
    return SERVICE_NOT_COMPATIBLE;

fail:
    dns_service_mod.api->fail_service(flowp, args->pkt, dir, &tcp_svc_element,
        dns_service_mod.flow_data_index,
        args->pConfig);
    return SERVICE_NOMATCH;

inprocess:
    dns_tcp_client_mod.api->add_app(flowp, APP_ID_NONE, APP_ID_DNS, nullptr);
    dns_service_mod.api->service_inprocess(flowp, args->pkt, dir, &tcp_svc_element);
    return SERVICE_INPROCESS;
}

static int dns_host_scan_patterns(SearchTool* matcher, const u_int8_t* pattern, size_t size,
    AppId* ClientAppId, AppId* payloadId)
{
    MatchedDNSPatterns* mp = nullptr;
    MatchedDNSPatterns* tmpMp;
    DNSHostPattern* best_match;

    if (!matcher)
        return 0;

    matcher->find_all((char*)pattern, size, dns_host_pattern_match, false, &mp);

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

int dns_host_scan_hostname(const u_int8_t* pattern, size_t size, AppId* ClientAppId,
    AppId* payloadId, const ServiceDnsConfig* pDnsConfig)
{
    return dns_host_scan_patterns(pDnsConfig->dns_host_host_matcher, pattern, size, ClientAppId,
        payloadId);
}

void service_dns_host_clean(ServiceDnsConfig* pDnsConfig)
{
    if (pDnsConfig->dns_host_host_matcher )
    {
        delete pDnsConfig->dns_host_host_matcher;
        pDnsConfig->dns_host_host_matcher = nullptr;
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

int dns_add_host_pattern(uint8_t* pattern_str, size_t pattern_size, uint8_t type, AppId app_id,
    ServiceDnsConfig* pDnsConfig)
{
    return dns_add_pattern(&pDnsConfig->DetectorDNSHostPatternList, pattern_str, pattern_size,
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
            free (tmp_pattern->dpattern);
        }
        snort_free(tmp_pattern);
    }
}

void dns_detector_free_patterns(ServiceDnsConfig* pDnsConfig)
{
    dns_patterns_free(&pDnsConfig->DetectorDNSHostPatternList);
}

char* dns_parse_host(const uint8_t* host, uint8_t host_len)
{
    char* str;
    const uint8_t* src;
    char* dst;
    uint8_t len;
    uint32_t dstLen = 0;

    str = static_cast<char*>(snort_calloc(host_len + 1));    // plus '\0' at end
    src = host;
    dst = str;
    while (*src != 0)
    {
        len = *src;
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

