//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "app_info_table.h"
#include "protocols/packet.h"
#include "protocols/ssl.h"

using namespace snort;

#define SSL_PORT 443

enum SSLContentType
{
    SSL_CHANGE_CIPHER = 20,
    SSL_ALERT = 21,
    SSL_HANDSHAKE = 22,
    SSL_APPLICATION_DATA = 23
};

#define SSL2_SERVER_HELLO 4
#define PCT_SERVER_HELLO 2

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
    SSLV3ClientHelloData client_hello;
    /* From server: */
    SSLV3ServerCertData server_cert;
    int in_certs;         // Currently collecting certificates?
    int certs_curr_len;   // Current amount of collected certificate data.
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
    ss_tmp->client_hello.clear();
    ss_tmp->server_cert.clear();
    ssl_cache_free(ss_tmp->cached_data, ss_tmp->cached_len);
    snort_free(ss_tmp);
}

static void parse_client_initiation(const uint8_t* data, uint16_t size, ServiceSSLData* ss)
{
    const ServiceSSLV3Hdr* hdr3;
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

    parse_client_hello_data(data, size, &ss->client_hello);
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
        if (size < sizeof(ServiceSSLV3Record) || rec->type != SSLV3RecordType::SERVER_HELLO ||
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
                if (rec->type != SSLV3RecordType::SERVER_HELLO_DONE and rec->length_msb)
                {
                    goto fail;
                }
                switch (rec->type)
                {
                case SSLV3RecordType::CERTIFICATE:
                    /* Start pulling out certificates. */
                    if (!ss->server_cert.certs_data)
                    {
                        if (size < sizeof(ServiceSSLV3CertsRecord))
                            goto fail;

                        certs_rec = (const ServiceSSLV3CertsRecord*)data;
                        ss->server_cert.certs_len = ntoh3(certs_rec->certs_len);
                        ss->server_cert.certs_data = (uint8_t*)snort_alloc(ss->server_cert.certs_len);
                        if ((size - sizeof(ServiceSSLV3CertsRecord)) < ss->server_cert.certs_len)
                        {
                            /* Will have to get more next time around. */
                            ss->in_certs = 1;
                            /* Skip over header to data */
                            ss->certs_curr_len = size - sizeof(ServiceSSLV3CertsRecord);
                            memcpy(ss->server_cert.certs_data, data + sizeof(ServiceSSLV3CertsRecord),
                                ss->certs_curr_len);
                        }
                        else
                        {
                            /* Can get it all this time. */
                            ss->in_certs       = 0;
                            ss->certs_curr_len = ss->server_cert.certs_len;
                            memcpy(ss->server_cert.certs_data, data + sizeof(ServiceSSLV3CertsRecord),
                                ss->certs_curr_len);
                            break;
                        }
                    }
                /* fall through */
                case SSLV3RecordType::CERTIFICATE_STATUS:
                case SSLV3RecordType::SERVER_KEY_XCHG:
                case SSLV3RecordType::SERVER_CERT_REQ:
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
                case SSLV3RecordType::SERVER_HELLO_DONE:
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
                if (ss->in_certs && ss->server_cert.certs_data)
                {
                    if (size < (ss->server_cert.certs_len - ss->certs_curr_len))
                    {
                        /* Will have to get more next time around. */
                        memcpy(ss->server_cert.certs_data + ss->certs_curr_len, data, size);
                        ss->in_certs = 1;
                        ss->certs_curr_len += size;
                    }
                    else
                    {
                        /* Can get it all this time. */
                        memcpy(ss->server_cert.certs_data + ss->certs_curr_len, data,
                            ss->server_cert.certs_len - ss->certs_curr_len);
                        ss->in_certs = 0;
                        ss->certs_curr_len = ss->server_cert.certs_len;
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
    {
        snort_free(reallocated_data);
        reallocated_data = nullptr;
    }
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

fail:
    if (reallocated_data)
    {
        snort_free(reallocated_data);
        reallocated_data = nullptr;
    }
    ss->client_hello.clear();
    ss->server_cert.clear();
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;

success:
    if (reallocated_data)
    {
        snort_free(reallocated_data);
        reallocated_data = nullptr;
    }

    if (ss->server_cert.certs_data && ss->server_cert.certs_len)
    {
        if (!(args.asd.scan_flags & SCAN_CERTVIZ_ENABLED_FLAG) and
            (!parse_server_certificates(&ss->server_cert)))
        {
            goto fail;
        }
    }

    args.asd.set_session_flags(APPID_SESSION_SSL_SESSION);
    if (ss->client_hello.host_name || ss->server_cert.common_name || ss->server_cert.org_name)
    {
        if (!args.asd.tsession)
            args.asd.tsession = new TlsSession();

        /* TLS Host */
        if (ss->client_hello.host_name)
        {
            args.asd.tsession->set_tls_host(ss->client_hello.host_name, 0, args.change_bits);
            args.asd.scan_flags |= SCAN_SSL_HOST_FLAG;
        }
        else if (ss->server_cert.common_name)
        {
            /* Use common name (from server) if we didn't get host name (from client). */
            args.asd.tsession->set_tls_host(ss->server_cert.common_name, ss->server_cert.common_name_strlen,
                args.change_bits);
            args.asd.scan_flags |= SCAN_SSL_HOST_FLAG;
        }

        /* TLS Common Name */
        if (ss->server_cert.common_name)
        {
            args.asd.tsession->set_tls_cname(ss->server_cert.common_name, 0, args.change_bits);
            args.asd.scan_flags |= SCAN_SSL_CERTIFICATE_FLAG;
        }
        /* TLS Org Unit */
        if (ss->server_cert.org_name)
            args.asd.tsession->set_tls_org_unit(ss->server_cert.org_name, 0);

        ss->client_hello.host_name = ss->server_cert.common_name = ss->server_cert.org_name = nullptr;
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
    case APP_ID_QUIC:
        return true;
    }

    return false;
}
