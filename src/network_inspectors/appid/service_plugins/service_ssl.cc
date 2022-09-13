//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#define SSL_PORT 443

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
#define SSL_CERTIFICATE_STATUS 22
#define SSL2_SERVER_HELLO 4
#define PCT_SERVER_HELLO 2

#define FIELD_SEPARATOR "/"
#define COMMON_NAME_STR "/CN="
#define ORG_NAME_STR "/O="

/* Extension types. */
#define SSL_EXT_SERVER_NAME 0

enum SSLState
{
    SSL_STATE_INITIATE,    // Client initiates.
    SSL_STATE_CONNECTION,  // Server responds...
    SSL_STATE_HEADER,
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
    unsigned certs_len;   // (Total) length of certificate(s).
    uint8_t* certs_data;  // Certificate(s) data (each proceeded by length (3 bytes)).
    int in_certs;         // Currently collecting certificates?
    int certs_curr_len;   // Current amount of collected certificate data.
    /* Data collected from certificates afterwards: */
    char* common_name;
    int common_name_strlen;
    char* org_name;
    int org_name_strlen;
    uint8_t* cached_data;
    uint16_t cached_len;
};

#pragma pack(1)

/* Usually referred to as a TLS Record. */
struct ServiceSSLV3Hdr
{
    uint8_t type;
    uint16_t version;
    uint16_t len;
};

/* Usually referred to as a TLS Handshake. */
struct ServiceSSLV3Record
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

/* Usually referred to as a Certificate Handshake. */
struct ServiceSSLV3CertsRecord
{
    uint8_t type;
    uint8_t length_msb;
    uint16_t length;
    uint8_t certs_len[3];  // 3-byte length, network byte order.
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

#pragma pack()

/* Convert 3-byte lengths in TLS headers to integers. */
#define ntoh3(msb_ptr) \
    ((uint32_t)((uint32_t)(((const uint8_t*)(msb_ptr))[0] << 16) \
    + (uint32_t)(((const uint8_t*)(msb_ptr))[1] << 8) \
    + (uint32_t)(((const uint8_t*)(msb_ptr))[2])))

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
        { 853, IpProtocol::TCP, false },
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

static void ssl_cache_free(uint8_t*& ssl_cache, uint16_t& len)
{
    if (ssl_cache)
    {
        snort_free(ssl_cache);
        ssl_cache = nullptr;
    }
        
    len = 0;
}

static void ssl_free(void* ss)
{
    ServiceSSLData* ss_tmp = (ServiceSSLData*)ss;
    snort_free(ss_tmp->certs_data);
    snort_free(ss_tmp->host_name);
    snort_free(ss_tmp->common_name);
    snort_free(ss_tmp->org_name);
    ssl_cache_free(ss_tmp->cached_data, ss_tmp->cached_len);
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
    if (hdr3->type != SSL_HANDSHAKE || (ver != 0x0300 && ver != 0x0301 && ver != 0x0302 &&
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
    if (rec->type != SSL_CLIENT_HELLO || (ver != 0x0300 && ver != 0x0301 && ver != 0x0302 &&
        ver != 0x0303) || rec->length_msb)
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

    /* We need at least type (2 bytes) and length (2 bytes) in the extension. */
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

            const uint8_t* str = data + offsetof(ServiceSSLV3ExtensionServerName, string_length) +
                sizeof(ext->string_length);
            ss->host_name = snort_strndup((const char*)str, len);
            ss->host_name_strlen = len;
            return;
        }

        unsigned len = ntohs(ext->length) + offsetof(ServiceSSLV3ExtensionServerName, list_length);
        if (len > length)
            return;

        data += len;
        length -= len;
    }
}

static bool parse_certificates(ServiceSSLData* ss)
{
    bool success = false;
    if (ss->certs_data and ss->certs_len)
    {
        char* common_name = nullptr;
        char* org_name = nullptr;
        const uint8_t* data = ss->certs_data;
        int len = ss->certs_len;
        int common_name_tot_len = 0;
        int org_name_tot_len  = 0;
        success = true;

        while (len > 0 and !(common_name and org_name))
        {
            X509* cert = nullptr;
            char* cert_name = nullptr;
            char* start = nullptr;

            int cert_len = ntoh3(data);
            data += 3;
            len -= 3;
            if (len < cert_len)
            {
                success = false;
                break;
            }
            /* d2i_X509() increments the data ptr for us. */
            cert = d2i_X509(nullptr, (const unsigned char**)&data, cert_len);
            len -= cert_len;
            if (!cert)
            {
                success = false;
                break;
            }

            /* only look for common name or org name if we don't already have one */
            if (!common_name or !org_name)
            {
                if ((cert_name = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0)))
                {
                    if (!common_name)
                    {
                        if ((start = strstr(cert_name, COMMON_NAME_STR)))
                        {
                            int length = 0;
                            start += strlen(COMMON_NAME_STR);
                            length = strlen(start);
                            if (length > 2 and *start == '*' and *(start+1) == '.')
                            {
                                start += 2; // remove leading *.
                                length -= 2;
                            }
                            common_name = snort_strndup(start, length);
                            common_name_tot_len += length;
                            start = nullptr;
                        }
                    }
                    if (!org_name)
                    {
                        if ((start = strstr(cert_name, COMMON_NAME_STR)))
                        {
                            int length;
                            start += strlen(COMMON_NAME_STR);
                            length = strlen(start);
                            if (length > 2 and *start == '*' and *(start+1) == '.')
                            {
                                start += 2; // remove leading *.
                                length -= 2;
                            }
                            org_name = snort_strndup(start, length);
                            org_name_tot_len += length;
                            start = nullptr;
                        }
                    }
                    free(cert_name);
                    cert_name = nullptr;
                }
            }
            X509_free(cert);
        }

        if (common_name)
        {
            ss->common_name = common_name;
            ss->common_name_strlen = common_name_tot_len;
        }

        if (org_name)
        {
            ss->org_name = org_name;
            ss->org_name_strlen = org_name_tot_len;
        }

        /* No longer need entire certificates. We have what we came for. */
        snort_free(ss->certs_data);
        ss->certs_data = nullptr;
        ss->certs_len = 0;
    }

    return success;
}

static void save_ssl_cache(ServiceSSLData* ss, uint16_t size, const uint8_t* data)
{
    ss->cached_data = (uint8_t*)snort_calloc(size, sizeof(uint8_t));
    memcpy(ss->cached_data, data, size);
    ss->cached_len = size;               
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
    uint8_t* reallocated_data = nullptr;

    if (!size)
        goto inprocess;

    ss = (ServiceSSLData*)data_get(args.asd);
    if (!ss)
    {
        ss = (ServiceSSLData*)snort_calloc(sizeof(ServiceSSLData));
        data_add(args.asd, ss, &ssl_free);
        ss->state = SSL_STATE_INITIATE;
        ss->cached_data = nullptr;
        ss->cached_len = 0;
    }

    if (ss->cached_len and ss->cached_data and (args.dir == APP_ID_FROM_RESPONDER))
    {
        reallocated_data = (uint8_t*)snort_calloc(ss->cached_len + size, sizeof(uint8_t));
        memcpy(reallocated_data, ss->cached_data, ss->cached_len);
        memcpy(reallocated_data + ss->cached_len, args.data, args.size);
        size = ss->cached_len + args.size;
        ssl_cache_free(ss->cached_data, ss->cached_len);
        data = reallocated_data;
    }
    /* Start off with a Client Hello from client to server. */
    if (ss->state == SSL_STATE_INITIATE)
    {
        ss->state = SSL_STATE_CONNECTION;

        if (!(args.asd.scan_flags & SCAN_CERTVIZ_ENABLED_FLAG) and
            args.dir == APP_ID_FROM_INITIATOR)
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
        pct = (const ServiceSSLPCTHdr*)data;
        hdr2 = (const ServiceSSLV2Hdr*)data;
        hdr3 = (const ServiceSSLV3Hdr*)data;

        /* SSL PCT header? */
        if (size >= sizeof(ServiceSSLPCTHdr) && pct->len >= 0x80 &&
            pct->type == PCT_SERVER_HELLO && ntohs(pct->version) == 0x8001)
        {
            goto success;
        }

        /* SSL v2 header? */
        if (size >= sizeof(ServiceSSLV2Hdr) && hdr2->len >= 0x80 &&
            hdr2->type == SSL2_SERVER_HELLO && !(hdr2->cert & 0xFE))
        {
            uint16_t h2v = ntohs(hdr2->version);
            if ((h2v == 0x0002 || h2v == 0x0300 || h2v == 0x0301 ||
                h2v == 0x0303) && !(hdr2->cipher_len % 3))
            {
                goto success;
            }
        }

        /* Its probably an SSLv3, TLS 1.2, or TLS 1.3 header.
           First record must be a handshake (type 22). */
        if (size < sizeof(ServiceSSLV3Hdr) || hdr3->type != SSL_HANDSHAKE ||
            (ntohs(hdr3->version) != 0x0300 && ntohs(hdr3->version) != 0x0301 &&
            ntohs(hdr3->version) != 0x0302 && ntohs(hdr3->version) != 0x0303))
        {
            goto fail;
        }
        data += sizeof(ServiceSSLV3Hdr);
        size -= sizeof(ServiceSSLV3Hdr);
        rec = (const ServiceSSLV3Record*)data;
        if (size < sizeof(ServiceSSLV3Record) || rec->type != SSL_SERVER_HELLO ||
            (ntohs(rec->version) != 0x0300 && ntohs(rec->version) != 0x0301 &&
            ntohs(rec->version) != 0x0302 && ntohs(rec->version) != 0x0303) ||
            rec->length_msb)
        {
            goto fail;
        }
        ss->tot_length = ntohs(hdr3->len);
        ss->length = ntohs(rec->length) +
            offsetof(ServiceSSLV3Record, version);
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
        while (size > 0)
        {
            if (!ss->pos)
            {
                /* Need to move onto (and past) next header (i.e., record) if
                   previous was completely consumed. */
                if (ss->tot_length == 0)
                {
                    if (size < sizeof(ServiceSSLV3Hdr))
                    {
                        save_ssl_cache(ss, size, data);
                        goto inprocess;
                    }
                    
                    hdr3 = (const ServiceSSLV3Hdr*)data;
                    ver = ntohs(hdr3->version);
                    if ((hdr3->type != SSL_HANDSHAKE &&
                        hdr3->type != SSL_CHANGE_CIPHER && hdr3->type != SSL_APPLICATION_DATA) ||
                        (ver != 0x0300 && ver != 0x0301 && ver != 0x0302 && ver != 0x0303))
                    {
                        goto fail;
                    }
                    data += sizeof(ServiceSSLV3Hdr);
                    size -= sizeof(ServiceSSLV3Hdr);
                    ss->tot_length = ntohs(hdr3->len);

                    if (hdr3->type == SSL_CHANGE_CIPHER ||
                        hdr3->type == SSL_APPLICATION_DATA)
                    {
                        goto success;
                    }
                }

                if (size < offsetof(ServiceSSLV3Record, version))
                {
                    save_ssl_cache(ss, size, data);
                    goto inprocess;
                }

                rec = (const ServiceSSLV3Record*)data;
                if (rec->type != SSL_SERVER_HELLO_DONE and rec->length_msb)
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
                            /* Skip over header to data */
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
                            break;
                        }
                    }
                /* fall through */
                case SSL_CERTIFICATE_STATUS:
                case SSL_SERVER_KEY_XCHG:
                case SSL_SERVER_CERT_REQ:
                    ss->length = ntohs(rec->length) + offsetof(ServiceSSLV3Record, version);
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
                    break;
                case SSL_SERVER_HELLO_DONE:
                    if (size < offsetof(ServiceSSLV3Record, version))
                        goto success;
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
                        ss->in_certs = 1;
                        ss->certs_curr_len += size;
                    }
                    else
                    {
                        /* Can get it all this time. */
                        memcpy(ss->certs_data + ss->certs_curr_len, data,
                            ss->certs_len - ss->certs_curr_len);
                        ss->in_certs = 0;
                        ss->certs_curr_len = ss->certs_len;
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
            }
        }
        break;
    default:
        goto fail;
    }

inprocess:
    if (reallocated_data)
        snort_free(reallocated_data);
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    if (reallocated_data)
        snort_free(reallocated_data);
    snort_free(ss->certs_data);
    snort_free(ss->host_name);
    snort_free(ss->common_name);
    snort_free(ss->org_name);
    ss->certs_data = nullptr;
    ss->host_name = ss->common_name = ss->org_name = nullptr;
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;

success:
    if (reallocated_data)
        snort_free(reallocated_data);
        
    if (ss->certs_data && ss->certs_len)
    {
        if (!(args.asd.scan_flags & SCAN_CERTVIZ_ENABLED_FLAG) and
            (!parse_certificates(ss)))
        {
            goto fail;
        }
    }

    args.asd.set_session_flags(APPID_SESSION_SSL_SESSION);
    if (ss->host_name || ss->common_name || ss->org_name)
    {
        if (!args.asd.tsession)
            args.asd.tsession = new TlsSession();

        /* TLS Host */
        if (ss->host_name)
        {
            args.asd.tsession->set_tls_host(ss->host_name, 0, args.change_bits);
            args.asd.scan_flags |= SCAN_SSL_HOST_FLAG;
        }
        else if (ss->common_name)
        {
            /* Use common name (from server) if we didn't get host name (from client). */
            args.asd.tsession->set_tls_host(ss->common_name, ss->common_name_strlen, args.change_bits);
            args.asd.scan_flags |= SCAN_SSL_HOST_FLAG;
        }

        /* TLS Common Name */
        if (ss->common_name)
        {
            args.asd.tsession->set_tls_cname(ss->common_name, 0, args.change_bits);
            args.asd.scan_flags |= SCAN_SSL_CERTIFICATE_FLAG;
        }
        /* TLS Org Unit */
        if (ss->org_name)
            args.asd.tsession->set_tls_org_unit(ss->org_name, 0);

        ss->host_name = ss->common_name = ss->org_name = nullptr;
        args.asd.tsession->set_tls_handshake_done();
    }
    return add_service(args.change_bits, args.asd, args.pkt, args.dir,
        getSslServiceAppId(args.pkt->ptrs.sp));
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
    case 585:  // Currently 585 is de-registered at IANA but old implementation may still use it.
    case 993:
        return APP_ID_IMAPS;
    case 614:
        return APP_ID_SSHELL;
    case 636:
        return APP_ID_LDAPS;
    case 853:
        return APP_ID_DNS_OVER_TLS;
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
