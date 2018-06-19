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

// service_ssl.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_ssl.h"

#include <openssl/x509.h>

#include "app_info_table.h"
#include "protocols/packet.h"

using namespace snort;

#define SSL_PORT    443

enum SSLContentType
{
    SSL_CHANGE_CIPHER = 20,
    SSL_ALERT = 21,
    SSL_HANDSHAKE = 22,
    SSL_APPLICATION_DATA = 23
};

#define SSL_CLIENT_HELLO 1
#define SSL_SERVER_HELLO 2
#define SSL_CERTIFICATE 11
#define SSL_SERVER_KEY_XCHG 12
#define SSL_SERVER_CERT_REQ 13
#define SSL_SERVER_HELLO_DONE 14
#define SSL2_SERVER_HELLO 4
#define PCT_SERVER_HELLO 2

#define FIELD_SEPARATOR "/"
#define COMMON_NAME_STR "/CN="
#define ORG_NAME_STR    "/O="

/* Extension types. */
#define SSL_EXT_SERVER_NAME 0

struct SSLCertPattern
{
    uint8_t type;
    AppId appId;
    uint8_t* pattern;
    int pattern_size;
};

struct DetectorSSLCertPattern
{
    SSLCertPattern* dpattern;
    DetectorSSLCertPattern* next;
};

struct MatchedSSLPatterns
{
    SSLCertPattern* mpattern;
    int match_start_pos;
    struct MatchedSSLPatterns* next;
};

enum SSLState
{
    SSL_STATE_INITIATE,      /* Client initiates. */
    SSL_STATE_CONNECTION,    /* Server responds... */
    SSL_STATE_HEADER,
    SSL_STATE_DONE
};

struct ServiceSSLData
{
    SSLState state;
    int pos;
    int length;
    int tot_length;
    /* From client: */
    char* host_name;
    int host_name_strlen;
    /* While collecting certificates: */
    unsigned certs_len;     /* (Total) length of certificate(s). */
    uint8_t* certs_data;    /* Certificate(s) data (each proceeded by length (3 bytes)). */
    int in_certs;           /* Currently collecting certificates? */
    int certs_curr_len;     /* Current amount of collected certificate data. */
    /* Data collected from certificates afterwards: */
    char* common_name;
    int common_name_strlen;
    char* org_name;
    int org_name_strlen;
};

struct ServiceSSLCertificate
{
    X509* cert;
    char* cert_name;
    uint8_t* common_name_ptr;
    int common_name_len;
    uint8_t* org_name_ptr;
    int org_name_len;
    struct ServiceSSLCertificate* next;
};

#pragma pack(1)

struct ServiceSSLV3Hdr    /* Actually a TLS Record. */
{
    uint8_t type;
    uint16_t version;
    uint16_t len;
};

struct ServiceSSLV3Record    /* Actually a Handshake. */
{
    uint8_t type;
    uint8_t length_msb;
    uint16_t length;
    uint16_t version;
    struct
    {
        uint32_t time;
        uint8_t data[28];
    } random;
};

struct ServiceSSLV3CertsRecord    /* Actually a Certificate(s) Handshake. */
{
    uint8_t type;
    uint8_t length_msb;
    uint16_t length;
    uint8_t certs_len[3];    /* 3-byte length, network byte order. */
    /* Certificate(s) follow.
     * For each:
     *  - Length: 3 bytes
     *  - Data  : "Length" bytes */
};

struct ServiceSSLV3ExtensionServerName
{
    uint16_t type;
    uint16_t length;
    uint16_t list_length;
    uint8_t string_length_msb;
    uint16_t string_length;
    /* String follows. */
};

struct ServiceSSLPCTHdr
{
    uint8_t len;
    uint8_t len2;
    uint8_t type;
    uint8_t pad;
    uint16_t version;
    uint8_t restart;
    uint8_t auth;
    uint32_t cipher;
    uint16_t hash;
    uint16_t cert;
    uint16_t exch;
    uint8_t id[32];
    uint16_t cert_len;
    uint16_t c_cert_len;
    uint16_t c_sig_len;
    uint16_t resp_len;
};

struct ServiceSSLV2Hdr
{
    uint8_t len;
    uint8_t len2;
    uint8_t type;
    uint8_t id;
    uint8_t cert;
    uint16_t version;
    uint16_t cert_len;
    uint16_t cipher_len;
    uint16_t conn_len;
};

struct ServiceSslConfig
{
    DetectorSSLCertPattern* DetectorSSLCertPatternList;
    DetectorSSLCertPattern* DetectorSSLCnamePatternList;
    SearchTool* ssl_host_matcher;
    SearchTool* ssl_cname_matcher;
};

static ServiceSslConfig service_ssl_config;

#pragma pack()

/* Convert 3-byte lengths in TLS headers to integers. */
#define ntoh3(msb_ptr) \
    ((uint32_t)(   (uint32_t)(((const uint8_t*)(msb_ptr))[0] << 16)    \
    + (uint32_t)(((const uint8_t*)(msb_ptr))[1] <<  8)    \
    + (uint32_t)(((const uint8_t*)(msb_ptr))[2]      ) ))

static int ssl_cert_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    MatchedSSLPatterns* cm;
    MatchedSSLPatterns** matches = (MatchedSSLPatterns**)data;
    SSLCertPattern* target = (SSLCertPattern*)id;

    cm = (MatchedSSLPatterns*)snort_alloc(sizeof(MatchedSSLPatterns));
    cm->mpattern = target;
    cm->match_start_pos = match_end_pos - target->pattern_size;
    cm->next = *matches;
    *matches = cm;

    return 0;
}

static int ssl_detector_create_matcher(SearchTool** matcher, DetectorSSLCertPattern* list)
{
    size_t* patternIndex;
    size_t size = 0;
    DetectorSSLCertPattern* element = nullptr;

    if (*matcher)
        delete *matcher;

    if (!(*matcher = new SearchTool("ac_full", true)))
        return 0;

    patternIndex = &size;

    /* Add patterns from Lua API */
    for (element = list; element; element = element->next)
    {
        (*matcher)->add(element->dpattern->pattern,
            element->dpattern->pattern_size,
            element->dpattern,
            true);
        (*patternIndex)++;
    }

    (*matcher)->prep();

    return 1;
}

int ssl_detector_process_patterns()
{
    int retVal = 1;
    if (!ssl_detector_create_matcher(&service_ssl_config.ssl_host_matcher,
        service_ssl_config.DetectorSSLCertPatternList))
        retVal = 0;
    if (!ssl_detector_create_matcher(&service_ssl_config.ssl_cname_matcher,
        service_ssl_config.DetectorSSLCnamePatternList))
        retVal = 0;
    return retVal;
}

static const uint8_t SSL_PATTERN_PCT[] = { 0x02, 0x00, 0x80, 0x01 };
static const uint8_t SSL_PATTERN3_0[] = { 0x16, 0x03, 0x00 };
static const uint8_t SSL_PATTERN3_1[] = { 0x16, 0x03, 0x01 };
static const uint8_t SSL_PATTERN3_2[] = { 0x16, 0x03, 0x02 };
static const uint8_t SSL_PATTERN3_3[] = { 0x16, 0x03, 0x03 };

SslServiceDetector::SslServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "ssl";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { SSL_PATTERN_PCT, sizeof(SSL_PATTERN_PCT), 2, 0, 0 },
        { SSL_PATTERN3_0, sizeof(SSL_PATTERN3_0), -1, 0, 0 },
        { SSL_PATTERN3_1, sizeof(SSL_PATTERN3_1), -1, 0, 0 },
        { SSL_PATTERN3_2, sizeof(SSL_PATTERN3_2), -1, 0, 0 },
        { SSL_PATTERN3_3, sizeof(SSL_PATTERN3_3), -1, 0, 0 }
    };

    appid_registry =
    {
        { APP_ID_SSL, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { 261, IpProtocol::TCP, false },
        { 261, IpProtocol::UDP, false },
        { 443, IpProtocol::TCP, false },
        { 443, IpProtocol::UDP, false },
        { 448, IpProtocol::TCP, false },
        { 448, IpProtocol::UDP, false },
        { 465, IpProtocol::TCP, false },
        { 563, IpProtocol::TCP, false },
        { 563, IpProtocol::UDP, false },
        { 585, IpProtocol::TCP, false },
        { 585, IpProtocol::UDP, false },
        { 614, IpProtocol::TCP, false },
        { 636, IpProtocol::TCP, false },
        { 636, IpProtocol::UDP, false },
        { 989, IpProtocol::TCP, false },
        { 990, IpProtocol::TCP, false },
        { 992, IpProtocol::TCP, false },
        { 992, IpProtocol::UDP, false },
        { 993, IpProtocol::TCP, false },
        { 993, IpProtocol::UDP, false },
        { 994, IpProtocol::TCP, false },
        { 994, IpProtocol::UDP, false },
        { 995, IpProtocol::TCP, false },
        { 995, IpProtocol::UDP, false },
        { 3269, IpProtocol::TCP, false },
        { 8305, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


static void ssl_free(void* ss)    /* AppIdFreeFCN */
{
    ServiceSSLData* ss_tmp = (ServiceSSLData*)ss;
    snort_free(ss_tmp->certs_data);
    snort_free(ss_tmp->host_name);
    snort_free(ss_tmp->common_name);
    snort_free(ss_tmp->org_name);
    snort_free(ss_tmp);
}

static void parse_client_initiation(const uint8_t* data, uint16_t size, ServiceSSLData* ss)
{
    const ServiceSSLV3Hdr* hdr3;
    const ServiceSSLV3Record* rec;
    unsigned length;
    uint16_t ver;

    /* Sanity check header stuff. */
    if (size < sizeof(ServiceSSLV3Hdr))
        return;
    hdr3 = (const ServiceSSLV3Hdr*)data;
    ver = ntohs(hdr3->version);
    if (hdr3->type != SSL_HANDSHAKE ||
        (ver != 0x0300 &&
        ver != 0x0301 &&
        ver != 0x0302 &&
        ver != 0x0303))
    {
        return;
    }
    data += sizeof(ServiceSSLV3Hdr);
    size -= sizeof(ServiceSSLV3Hdr);

    if (size < sizeof(ServiceSSLV3Record))
        return;
    rec = (const ServiceSSLV3Record*)data;
    ver = ntohs(rec->version);
    if (rec->type != SSL_CLIENT_HELLO ||
        (ver != 0x0300 &&
        ver != 0x0301 &&
        ver != 0x0302 &&
        ver != 0x0303) ||
        rec->length_msb)
    {
        return;
    }
    length = ntohs(rec->length) + offsetof(ServiceSSLV3Record, version);
    if (size < length)
        return;
    data += sizeof(ServiceSSLV3Record);
    size -= sizeof(ServiceSSLV3Record);

    /* Session ID (1-byte length). */
    if (size < 1)
        return;
    length = *((const uint8_t*)data);
    data += length + 1;
    if (size < (length + 1))
        return;
    size -= length + 1;

    /* Cipher Suites (2-byte length). */
    if (size < 2)
        return;
    length = ntohs(*((const uint16_t*)data));
    data += length + 2;
    if (size < (length + 2))
        return;
    size -= length + 2;

    /* Compression Methods (1-byte length). */
    if (size < 1)
        return;
    length = *((const uint8_t*)data);
    data += length + 1;
    if (size < (length + 1))
        return;
    size -= length + 1;

    /* Extensions (2-byte length) */
    if (size < 2)
        return;
    length = ntohs(*((const uint16_t*)data));
    data += 2;
    size -= 2;
    if (size < length)
        return;

    // We need at least type (2 bytes) and length (2 bytes) fields in the extension
    while (length >= 4)
    {
        const ServiceSSLV3ExtensionServerName* ext = (const ServiceSSLV3ExtensionServerName*)data;
        if (ntohs(ext->type) == SSL_EXT_SERVER_NAME)
        {
            /* Found server host name. */
            if (length < sizeof(ServiceSSLV3ExtensionServerName))
                return;

            unsigned len = ntohs(ext->string_length);
            if ((length - sizeof(ServiceSSLV3ExtensionServerName)) < len)
                return;

            const uint8_t* str = data
                + offsetof(ServiceSSLV3ExtensionServerName, string_length)
                + sizeof(ext->string_length);
            ss->host_name = (char*)snort_alloc(len + 1);     /* Plus nullptr term. */
            memcpy(ss->host_name, str, len);
            ss->host_name[len] = '\0';
            ss->host_name_strlen = len;
            return;
        }

        data   += ntohs(ext->length) + offsetof(ServiceSSLV3ExtensionServerName, list_length);
        length -= ntohs(ext->length) + offsetof(ServiceSSLV3ExtensionServerName, list_length);
    }
}

static bool parse_certificates(ServiceSSLData* ss)
{
    bool success = false;
    if (ss->certs_data && ss->certs_len)
    {
        /* Pull out certificates from block of data. */
        const uint8_t* data = ss->certs_data;
        int len  = ss->certs_len;
        ServiceSSLCertificate* certs_head = nullptr;
        ServiceSSLCertificate* certs_curr = nullptr;
        int common_name_tot_len = 0;
        int org_name_tot_len    = 0;
        int num_certs = 0;
        success = true;

        while (len > 0)
        {
            int cert_len = ntoh3(data);
            data += 3;
            len  -= 3;
            if (len < cert_len)
            {
                success = false;
                break;
            }
            X509* cert = d2i_X509(nullptr, (const unsigned char**)&data, cert_len);
            len -= cert_len;    /* Above call increments data pointer already. */
            if (!cert)
            {
                success = false;
                break;
            }

            /* Insert certificate entry into list. */
            certs_curr = (ServiceSSLCertificate*)snort_calloc(sizeof(ServiceSSLCertificate));
            certs_curr->cert = cert;
            certs_curr->next = certs_head;
            certs_head       = certs_curr;
            num_certs++;

            certs_curr->cert_name = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
            char* start = strstr(certs_curr->cert_name, COMMON_NAME_STR);
            if (start)
            {
                int length;

                start += strlen(COMMON_NAME_STR);
                certs_curr->common_name_ptr = (uint8_t*)start;
                char* end = strstr(start, FIELD_SEPARATOR);
                if (end)
                    length = end - start;
                else
                    length = strlen(start);

                certs_curr->common_name_len = length;
                common_name_tot_len += length;
            }

            start = strstr(certs_curr->cert_name, ORG_NAME_STR);
            if (start)
            {
                int length;

                start += strlen(ORG_NAME_STR);
                certs_curr->org_name_ptr = (uint8_t*)start;
                char* end = strstr(start, FIELD_SEPARATOR);
                if (end)
                    length = end - start;
                else
                    length = strlen(start);

                certs_curr->org_name_len = length;
                org_name_tot_len += length;
            }
        }

        if ( success )
        {
            char* common_name = nullptr;
            if (common_name_tot_len)
            {
                common_name_tot_len += num_certs;    /* Space between each and terminator at end.
                                                        */
                common_name = (char*)snort_calloc(common_name_tot_len);
            }

            char* org_name = nullptr;
            if (org_name_tot_len)
            {
                org_name_tot_len += num_certs;    /* Space between each and terminator at end. */
                org_name = (char*)snort_calloc(org_name_tot_len);
            }

            char* common_name_ptr = common_name;
            char* org_name_ptr = org_name;
            certs_curr = certs_head;
            while (certs_curr)
            {
                /* Grab this common name. */
                if (common_name_ptr && certs_curr->common_name_ptr && certs_curr->common_name_len)
                {
                    memcpy(common_name_ptr, certs_curr->common_name_ptr,
                        certs_curr->common_name_len);
                    common_name_ptr += certs_curr->common_name_len;
                    *common_name_ptr = ' ';
                    common_name_ptr += 1;
                }

                /* Grab this org name. */
                if (org_name_ptr && certs_curr->org_name_ptr && certs_curr->org_name_len)
                {
                    memcpy(org_name_ptr, certs_curr->org_name_ptr, certs_curr->org_name_len);
                    org_name_ptr += certs_curr->org_name_len;
                    *org_name_ptr = ' ';
                    org_name_ptr += 1;
                }

                certs_curr = certs_curr->next;
            }

            if (common_name_tot_len)
            {
                common_name_ptr  -= 1;
                *common_name_ptr  = '\0';
            }
            if (org_name_tot_len)
            {
                org_name_ptr     -= 1;
                *org_name_ptr     = '\0';
            }
            ss->common_name        = common_name;
            ss->common_name_strlen = common_name_tot_len - 1;    /* Minus terminator. */
            ss->org_name           = org_name;
            ss->org_name_strlen    = org_name_tot_len - 1;       /* Minus terminator. */
        }

        while (certs_head)
        {
            certs_curr = certs_head;
            certs_head = certs_head->next;
            X509_free(certs_curr->cert);
            OPENSSL_free(certs_curr->cert_name);
            snort_free(certs_curr);
        }

        /* No longer need entire certificates.  We have what we came for. */
        snort_free(ss->certs_data);
        ss->certs_data = nullptr;
        ss->certs_len  = 0;
    }

    return success;
}

int SslServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceSSLData* ss;
    const ServiceSSLPCTHdr* pct;
    const ServiceSSLV2Hdr* hdr2;
    const ServiceSSLV3Hdr* hdr3;
    const ServiceSSLV3Record* rec;
    const ServiceSSLV3CertsRecord* certs_rec;
    uint16_t ver;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;

    ss = (ServiceSSLData*)data_get(args.asd);
    if (!ss)
    {
        ss = (ServiceSSLData*)snort_calloc(sizeof(ServiceSSLData));
        data_add(args.asd, ss, &ssl_free);
        ss->state = SSL_STATE_INITIATE;
    }
    /* Start off with a Client Hello from client to server. */
    if (ss->state == SSL_STATE_INITIATE)
    {
        ss->state = SSL_STATE_CONNECTION;

        if (args.dir == APP_ID_FROM_INITIATOR)
        {
            parse_client_initiation(data, size, ss);
            goto inprocess;
        }
    }

    if (args.dir != APP_ID_FROM_RESPONDER)
    {
        goto inprocess;
    }

    switch (ss->state)
    {
    case SSL_STATE_CONNECTION:
        ss->state = SSL_STATE_DONE;
        pct = (const ServiceSSLPCTHdr*)data;
        hdr2 = (const ServiceSSLV2Hdr*)data;
        hdr3 = (const ServiceSSLV3Hdr*)data;
        if (size >= sizeof(ServiceSSLPCTHdr) && pct->len >= 0x80 &&
            pct->type == PCT_SERVER_HELLO && ntohs(pct->version) == 0x8001)
        {
            goto success;
        }
        if (size >= sizeof(ServiceSSLV2Hdr) && hdr2->len >= 0x80 &&
            hdr2->type == SSL2_SERVER_HELLO && !(hdr2->cert & 0xFE))
        {
            switch (ntohs(hdr2->version))
            {
            case 0x0002:
            case 0x0300:
            case 0x0301:
            case 0x0303:
                break;
            default:
                goto not_v2;
            }
            if (hdr2->cipher_len % 3)
                goto not_v2;

            goto success;
not_v2:     ;
        }
        if (size < sizeof(ServiceSSLV3Hdr) ||
            hdr3->type != SSL_HANDSHAKE ||
            (ntohs(hdr3->version) != 0x0300 &&
            ntohs(hdr3->version) != 0x0301 &&
            ntohs(hdr3->version) != 0x0302 &&
            ntohs(hdr3->version) != 0x0303))
        {
            goto fail;
        }
        data += sizeof(ServiceSSLV3Hdr);
        size -= sizeof(ServiceSSLV3Hdr);
        rec = (const ServiceSSLV3Record*)data;
        if (size < sizeof(ServiceSSLV3Record) ||
            rec->type != SSL_SERVER_HELLO ||
            (ntohs(rec->version) != 0x0300 &&
            ntohs(rec->version) != 0x0301 &&
            ntohs(rec->version) != 0x0302 &&
            ntohs(rec->version) != 0x0303) ||
            rec->length_msb)
        {
            goto fail;
        }
        ss->tot_length = ntohs(hdr3->len);
        ss->length = ntohs(rec->length) +
            offsetof(ServiceSSLV3Record, version);
        if (size == ss->length)
            goto success;                        /* Just a Server Hello. */
        if (ss->tot_length < ss->length)
            goto fail;
        ss->tot_length -= ss->length;
        if (size < ss->length)
            goto fail;
        data += ss->length;
        size -= ss->length;
        ss->state = SSL_STATE_HEADER;
        ss->pos = 0;
    /* fall through */
    case SSL_STATE_HEADER:
        ss->state = SSL_STATE_DONE;
        while (size > 0)
        {
            if (!ss->pos)
            {
                /* Need to move onto (and past) next header (i.e., record) if
                 * previous was completely consumed. */
                if (ss->tot_length == 0)
                {
                    hdr3 = (const ServiceSSLV3Hdr*)data;
                    ver = ntohs(hdr3->version);
                    if (size < sizeof(ServiceSSLV3Hdr) ||
                        hdr3->type != SSL_HANDSHAKE ||
                        (ver != 0x0300 &&
                        ver != 0x0301 &&
                        ver != 0x0302 &&
                        ver != 0x0303))
                    {
                        goto fail;
                    }
                    data += sizeof(ServiceSSLV3Hdr);
                    size -= sizeof(ServiceSSLV3Hdr);
                    ss->tot_length = ntohs(hdr3->len);
                }

                rec = (const ServiceSSLV3Record*)data;
                if (size < offsetof(ServiceSSLV3Record, version) ||
                    rec->length_msb)
                {
                    goto fail;
                }
                switch (rec->type)
                {
                case SSL_CERTIFICATE:
                    /* Start pulling out certificates. */
                    if (!ss->certs_data)
                    {
                        certs_rec = (const ServiceSSLV3CertsRecord*)data;
                        ss->certs_len = ntoh3(certs_rec->certs_len);
                        ss->certs_data = (uint8_t*)snort_alloc(ss->certs_len);
                        if ((size - sizeof(ServiceSSLV3CertsRecord)) < ss->certs_len)
                        {
                            /* Will have to get more next time around. */
                            ss->in_certs = 1;
                            // Skip over header to data
                            ss->certs_curr_len = size - sizeof(ServiceSSLV3CertsRecord);
                            memcpy(ss->certs_data, data + sizeof(ServiceSSLV3CertsRecord),
                                ss->certs_curr_len);
                        }
                        else
                        {
                            /* Can get it all this time. */
                            ss->in_certs       = 0;
                            ss->certs_curr_len = ss->certs_len;
                            memcpy(ss->certs_data, data + sizeof(ServiceSSLV3CertsRecord),
                                ss->certs_curr_len);
                            goto success;    /* We got everything we need. */
                        }
                    }
                /* fall through */
                case SSL_SERVER_KEY_XCHG:
                case SSL_SERVER_CERT_REQ:
                    ss->length = ntohs(rec->length) +
                        offsetof(ServiceSSLV3Record, version);
                    if (size == ss->length)
                        goto success;
                    if (ss->tot_length < ss->length)
                        goto fail;
                    ss->tot_length -= ss->length;
                    if (size < ss->length)
                    {
                        ss->pos = size;
                        size = 0;
                    }
                    else
                    {
                        data += ss->length;
                        size -= ss->length;
                        ss->pos = 0;
                    }
                    ss->state = SSL_STATE_HEADER;
                    break;
                case SSL_SERVER_HELLO_DONE:
                    if (rec->length)
                        goto fail;
                    if (ss->tot_length != offsetof(ServiceSSLV3Record, version))
                        goto fail;
                    goto success;
                default:
                    goto fail;
                }
            }
            else
            {
                /* See if there's more certificate data to grab. */
                if (ss->in_certs && ss->certs_data)
                {
                    if (size < (ss->certs_len - ss->certs_curr_len))
                    {
                        /* Will have to get more next time around. */
                        memcpy(ss->certs_data + ss->certs_curr_len, data, size);
                        ss->in_certs        = 1;
                        ss->certs_curr_len += size;
                    }
                    else
                    {
                        /* Can get it all this time. */
                        memcpy(ss->certs_data + ss->certs_curr_len, data, ss->certs_len -
                            ss->certs_curr_len);
                        ss->in_certs       = 0;
                        ss->certs_curr_len = ss->certs_len;
                        goto success;    /* We got everything we need. */
                    }
                }

                if (size+ss->pos < ss->length)
                {
                    ss->pos += size;
                    size = 0;
                }
                else
                {
                    data += ss->length - ss->pos;
                    size -= ss->length - ss->pos;
                    ss->pos = 0;
                }
                ss->state = SSL_STATE_HEADER;
            }
        }
        break;
    default:
        goto fail;
    }

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    snort_free(ss->certs_data);
    snort_free(ss->host_name);
    snort_free(ss->common_name);
    snort_free(ss->org_name);
    ss->certs_data = nullptr;
    ss->host_name = ss->common_name = ss->org_name = nullptr;
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;

success:
    if (ss->certs_data && ss->certs_len)
    {
        if (!parse_certificates(ss))
        {
            goto fail;
        }
    }

    args.asd.set_session_flags(APPID_SESSION_SSL_SESSION);
    if (ss->host_name || ss->common_name || ss->org_name)
    {
        if (!args.asd.tsession)
            args.asd.tsession = (TlsSession*)snort_calloc(sizeof(TlsSession));

        /* TLS Host */
        if (ss->host_name)
        {
            if (args.asd.tsession->tls_host)
                snort_free(args.asd.tsession->tls_host);
            args.asd.tsession->tls_host = ss->host_name;
            args.asd.tsession->tls_host_strlen = ss->host_name_strlen;
            args.asd.scan_flags |= SCAN_SSL_HOST_FLAG;
        }
        else if (ss->common_name)
        {
            // use common name (from server) if we didn't see host name (from client)
            char* common_name = snort_strdup(ss->common_name);

            if (args.asd.tsession->tls_host)
                snort_free(args.asd.tsession->tls_host);
            args.asd.tsession->tls_host = common_name;
            args.asd.tsession->tls_host_strlen = ss->common_name_strlen;
            args.asd.scan_flags |= SCAN_SSL_HOST_FLAG;
        }

        /* TLS Common Name */
        if (ss->common_name)
        {
            if (args.asd.tsession->tls_cname)
                snort_free(args.asd.tsession->tls_cname);
            args.asd.tsession->tls_cname = ss->common_name;
            args.asd.tsession->tls_cname_strlen = ss->common_name_strlen;
        }

        /* TLS Org Unit */
        if (ss->org_name)
        {
            if (args.asd.tsession->tls_orgUnit)
                snort_free(args.asd.tsession->tls_orgUnit);
            args.asd.tsession->tls_orgUnit = ss->org_name;
            args.asd.tsession->tls_orgUnit_strlen = ss->org_name_strlen;
        }

        ss->host_name = ss->common_name = ss->org_name = nullptr;
    }
    return add_service(args.asd, args.pkt, args.dir, getSslServiceAppId(args.pkt->ptrs.sp));
}

AppId getSslServiceAppId(short srcPort)
{
    switch (srcPort)
    {
    case 261:
        return APP_ID_NSIIOPS;
    case 443:
        return APP_ID_HTTPS;
    case 448:
        return APP_ID_DDM_SSL;
    case 465:
        return APP_ID_SMTPS;
    case 563:
        return APP_ID_NNTPS;
    case 585:  /*Currently 585 is de-registered at IANA but old implementation may still use it. */
    case 993:
        return APP_ID_IMAPS;
    case 614:
        return APP_ID_SSHELL;
    case 636:
        return APP_ID_LDAPS;
    case 989:
        return APP_ID_FTPSDATA;
    case 990:
        return APP_ID_FTPS;
    case 992:
        return APP_ID_TELNETS;
    case 994:
        return APP_ID_IRCS;
    case 995:
        return APP_ID_POP3S;
    case 3269:
        return APP_ID_MSFT_GC_SSL;
    case 8305:
        return APP_ID_SF_APPLIANCE_MGMT;
    default:
        return APP_ID_SSL;
    }
}

bool is_service_over_ssl(AppId appId)
{
    switch (appId)
    {
    case APP_ID_NSIIOPS:
    case APP_ID_HTTPS:
    case APP_ID_DDM_SSL:
    case APP_ID_SMTPS:
    case APP_ID_NNTPS:
    case APP_ID_IMAPS:
    case APP_ID_SSHELL:
    case APP_ID_LDAPS:
    case APP_ID_FTPSDATA:
    case APP_ID_FTPS:
    case APP_ID_TELNETS:
    case APP_ID_IRCS:
    case APP_ID_POP3S:
    case APP_ID_MSFT_GC_SSL:
    case APP_ID_SF_APPLIANCE_MGMT:
    case APP_ID_SSL:
        return true;
    }

    return false;
}

static int ssl_scan_patterns(SearchTool* matcher, const uint8_t* data, size_t size,
    AppId* ClientAppId, AppId* payloadId)
{
    MatchedSSLPatterns* mp = nullptr;
    SSLCertPattern* best_match;

    if (!matcher)
        return 0;

    matcher->find_all((const char*)data, size, ssl_cert_pattern_match, false, &mp);

    if (!mp)
        return 0;

    best_match = nullptr;
    while (mp)
    {
        //  Only patterns that match start of payload,
        //  or patterns starting with '.'
        //  or patterns following '.' in payload are considered a match.
        if (mp->match_start_pos == 0 ||
            *mp->mpattern->pattern == '.' ||
            data[mp->match_start_pos-1] == '.')
        {
            if (!best_match || mp->mpattern->pattern_size > best_match->pattern_size)
            {
                best_match = mp->mpattern;
            }
        }
        MatchedSSLPatterns* tmpMp = mp;
        mp = mp->next;
        snort_free(tmpMp);
    }
    if (!best_match)
        return 0;

    switch (best_match->type)
    {
    /* type 0 means WEB APP */
    case 0:
        *ClientAppId = APP_ID_SSL_CLIENT;
        *payloadId = best_match->appId;
        break;
    /* type 1 means CLIENT */
    case 1:
        *ClientAppId = best_match->appId;
        *payloadId = 0;
        break;
    default:
        return 0;
    }

    return 1;
}

int ssl_scan_hostname(const uint8_t* hostname, size_t size, AppId* ClientAppId, AppId* payloadId)
{
    return ssl_scan_patterns(service_ssl_config.ssl_host_matcher, hostname, size, ClientAppId,
        payloadId);
}

int ssl_scan_cname(const uint8_t* common_name, size_t size, AppId* ClientAppId, AppId* payloadId)
{
    return ssl_scan_patterns(service_ssl_config.ssl_cname_matcher, common_name, size, ClientAppId,
        payloadId);
}

void service_ssl_clean()
{
    ssl_detector_free_patterns();

    if (service_ssl_config.ssl_host_matcher)
    {
        delete service_ssl_config.ssl_host_matcher;
        service_ssl_config.ssl_host_matcher = nullptr;
    }
    if (service_ssl_config.ssl_cname_matcher)
    {
        delete service_ssl_config.ssl_cname_matcher;
        service_ssl_config.ssl_cname_matcher = nullptr;
    }
}

static int ssl_add_pattern(DetectorSSLCertPattern** list, uint8_t* pattern_str, size_t
    pattern_size, uint8_t type, AppId app_id)
{
    DetectorSSLCertPattern* new_ssl_pattern;

    new_ssl_pattern = (DetectorSSLCertPattern*)snort_calloc(sizeof(DetectorSSLCertPattern));
    new_ssl_pattern->dpattern = (SSLCertPattern*)snort_calloc(sizeof(SSLCertPattern));
    new_ssl_pattern->dpattern->type = type;
    new_ssl_pattern->dpattern->appId = app_id;
    new_ssl_pattern->dpattern->pattern = pattern_str;
    new_ssl_pattern->dpattern->pattern_size = pattern_size;

    new_ssl_pattern->next = *list;
    *list = new_ssl_pattern;

    return 1;
}

int ssl_add_cert_pattern(uint8_t* pattern_str, size_t pattern_size, uint8_t type, AppId app_id)
{
    return ssl_add_pattern(&service_ssl_config.DetectorSSLCertPatternList, pattern_str,
        pattern_size,
        type, app_id);
}

int ssl_add_cname_pattern(uint8_t* pattern_str, size_t pattern_size, uint8_t type, AppId app_id)
{
    return ssl_add_pattern(&service_ssl_config.DetectorSSLCnamePatternList, pattern_str,
        pattern_size,
        type, app_id);
}

static void ssl_patterns_free(DetectorSSLCertPattern** list)
{
    DetectorSSLCertPattern* tmp_pattern;

    while ((tmp_pattern = *list))
    {
        *list = tmp_pattern->next;
        if (tmp_pattern->dpattern)
        {
            if (tmp_pattern->dpattern->pattern)
                snort_free(tmp_pattern->dpattern->pattern);
            snort_free(tmp_pattern->dpattern);
        }
        snort_free(tmp_pattern);
    }
}

void ssl_detector_free_patterns()
{
    ssl_patterns_free(&service_ssl_config.DetectorSSLCertPatternList);
    ssl_patterns_free(&service_ssl_config.DetectorSSLCnamePatternList);
}

bool setSSLSquelch(Packet* p, int type, AppId appId, AppIdInspector& inspector)
{
    if (!AppInfoManager::get_instance().get_app_info_flags(appId, APPINFO_FLAG_SSL_SQUELCH))
        return false;

    const SfIp* dip = p->ptrs.ip_api.get_dst();
    const SfIp* sip = p->ptrs.ip_api.get_src();

    // FIXIT-H: Passing appId to create_future_session() is incorrect. We need to pass the snort_protocol_id associated with appId.
    AppIdSession* asd = AppIdSession::create_future_session(p, sip, 0, dip, p->ptrs.dp, IpProtocol::TCP,
        appId, 0, inspector);
    if ( asd )
    {
        switch (type)
        {
        case 1:
            asd->payload.set_id(appId);
            break;

        case 2:
            asd->client.set_id(appId);
            asd->client_disco_state = APPID_DISCO_STATE_FINISHED;
            break;

        default:
            return false;
        }

        return true;
    }
    else
        return false;
}

