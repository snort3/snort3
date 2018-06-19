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

// detector_kerberos.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detector_kerberos.h"

#include "app_info_table.h"
#include "application_ids.h"

#include "protocols/packet.h"

using namespace snort;

enum KerberosState
{
    KRB_STATE_TCP_LENGTH,
    KRB_STATE_APP,
    KRB_STATE_SEQ,
    KRB_STATE_VERSION,
    KRB_STATE_VERSION_2,
    KRB_STATE_VERSION_VALUE,
    KRB_STATE_TYPE,
    KRB_STATE_TYPE_VALUE,
    KRB_STATE_ERROR,
    KRB_STATE_ERROR_VALUE,
    KRB_STATE_FIELD,
    KRB_STATE_FIELD_DATA,
    KRB_STATE_FIELD_DATA_2,
    KRB_STATE_CNAME_SEQ,
    KRB_STATE_CNAME_TYPE,
    KRB_STATE_CNAME_TYPE_2,
    KRB_STATE_CNAME_TYPE_VALUE,
    KRB_STATE_CNAME,
    KRB_STATE_CNAME_PRINCIPAL_SEQ,
    KRB_STATE_CNAME_PRINCIPAL_KS,
    KRB_STATE_CNAME_PRINCIPAL_DATA,
    KRB_STATE_CNAME_PRINCIPAL_DATA_2,
    KRB_STATE_LEN,
    KRB_STATE_LEN_2,
    KRB_STATE_REQBODY_SEQ,
    KRB_STATE_REQBODY_TYPE,
    KRB_STATE_FIELD_LEVEL2,
    KRB_STATE_FIELD_DATA_LEVEL2,
    KRB_STATE_FIELD_DATA_2_LEVEL2,
    KRB_STATE_INVALID,
};

/*error codes from RFC 4120 */
static const unsigned KDC_ERR_PREAUTH_FAILED = 24;

#define KRB_FLAG_AUTH_FAILED      0x01
#define KRB_FLAG_USER_DETECTED    0x02
#define KRB_FLAG_SERVICE_DETECTED 0x04

enum KRB_RETCODE
{
    KRB_INPROCESS,
    KRB_FAILED,
};

struct KRBState
{
    KerberosState state;
    KerberosState next_state;
    uint8_t msg_type;
    unsigned msg_len;
    uint8_t tag;
    unsigned len;
    unsigned pos;
    int added;
    unsigned cname_len;
    char cname[256];
    char ver[2];
    unsigned flags;
};

struct KerberosDetectorData
{
    KRBState clnt_state;
    KRBState svr_state;
    int need_continue;
};

#define ASN_1_APPLICATION   0x40
#define ASN_1_CONSTRUCT     0x20
#define ASN_1_TYPE_MASK     0xe0
#define AS_REQ_MSG_TYPE     0x0a
#define AS_REP_MSG_TYPE     0x0b
#define TGS_REQ_MSG_TYPE    0x0c
#define TGS_REP_MSG_TYPE    0x0d
#define ERROR_MSG_TYPE      0x1e

static KerberosClientDetector* krb_client_detector;
static KerberosServiceDetector* krb_service_detector;

static int krb_walk_server_packet(KRBState* krbs, const uint8_t* s, const uint8_t* end,
    AppIdSession& asd, snort::Packet* pkt, const AppidSessionDirection dir, const char* reqCname)
{
    static const uint8_t KRB_SERVER_VERSION[] = "\x0a0\x003\x002\x001";
    static const uint8_t KRB_SERVER_TYPE[] = "\x0a1\x003\x002\x001";
    static const uint8_t KRB_CNAME_TYPE[] = "\x0a0\x003\x002\x001";
    static const uint8_t KRB_ERROR[] = "\x003\x002\x001";
#define KRB_CNAME_TYPE_SIZE (sizeof(KRB_CNAME_TYPE) - 1)

    while (s < end)
    {
        switch (krbs->state)
        {
        case KRB_STATE_TCP_LENGTH:
            if (krbs->pos >= 3)
                krbs->state = KRB_STATE_APP;
            else
                krbs->pos++;
            break;
        case KRB_STATE_APP:
            if ((*s & ASN_1_TYPE_MASK) != (ASN_1_APPLICATION|ASN_1_CONSTRUCT))
                return KRB_FAILED;
            krbs->msg_type = *s & (~ASN_1_TYPE_MASK);
            switch (krbs->msg_type)
            {
            case AS_REP_MSG_TYPE:
            case TGS_REP_MSG_TYPE:
            case ERROR_MSG_TYPE:
            case 15:
            case 17:
            case 20:
            case 21:
            case 22:
                krbs->next_state = KRB_STATE_SEQ;
                break;
            default:
                return KRB_FAILED;
            }
            krbs->state = KRB_STATE_LEN;
            krbs->msg_len = 0xFFFFFFFF;
            break;
        case KRB_STATE_SEQ:
            if (krbs->len < 2 || *s != 0x30)
                return KRB_FAILED;
            krbs->msg_len = krbs->len;
            krbs->next_state = KRB_STATE_VERSION;
            krbs->state = KRB_STATE_LEN;
            krbs->pos = 0;
            break;
        case KRB_STATE_VERSION:
            if (krbs->len < 10 || krbs->len != krbs->msg_len)
                return KRB_FAILED;
            krbs->state = KRB_STATE_VERSION_2;
            krbs->pos = 0;
            // fallthrough
       case KRB_STATE_VERSION_2:
            if (*s != KRB_SERVER_VERSION[krbs->pos])
                return KRB_FAILED;
            krbs->pos++;
            if (krbs->pos >= sizeof(KRB_SERVER_VERSION) - 1)
                krbs->state = KRB_STATE_VERSION_VALUE;
            break;
        case KRB_STATE_VERSION_VALUE:
            if (*s != 5 && *s != 4)
                return KRB_FAILED;
            krbs->state = KRB_STATE_TYPE;
            krbs->pos = 0;
            krbs->ver[0] = *s + '0';
            break;
        case KRB_STATE_TYPE:
            if (*s != KRB_SERVER_TYPE[krbs->pos])
                return KRB_FAILED;
            if (krbs->pos >= (sizeof(KRB_SERVER_TYPE) - 1) - 1)
            {
                krbs->state = KRB_STATE_TYPE_VALUE;
                break;
            }
            krbs->pos++;
            break;
        case KRB_STATE_TYPE_VALUE:
            if (*s != krbs->msg_type)
                return KRB_FAILED;
            krbs->state = KRB_STATE_FIELD;
            krbs->tag = 0xa1;
            break;
        case KRB_STATE_ERROR:
            if (*s != KRB_ERROR[krbs->pos])
                return KRB_FAILED;
            if (krbs->pos >= (sizeof(KRB_ERROR) - 1) - 1)
            {
                krbs->state = KRB_STATE_ERROR_VALUE;
                break;
            }
            krbs->pos++;
            break;
        case KRB_STATE_ERROR_VALUE:
            if (krbs->msg_len <= 1)
            {
                krbs->flags |= KRB_FLAG_SERVICE_DETECTED;
                krbs->state = KRB_STATE_APP;
                if (!krbs->msg_len)
                    continue;
                break;
            }

            if (*s == KDC_ERR_PREAUTH_FAILED)
            {
                krbs->flags |= KRB_FLAG_AUTH_FAILED;
            }
            krbs->state = KRB_STATE_FIELD;
            break;
        case KRB_STATE_FIELD:
            if (krbs->msg_len < 2 || *s <= krbs->tag || (*s & ASN_1_TYPE_MASK) != 0xa0)
                return KRB_FAILED;
            krbs->tag = *s;
            if ((krbs->tag == 0xa4 && (krbs->msg_type == AS_REP_MSG_TYPE || krbs->msg_type ==
                TGS_REP_MSG_TYPE))
                || (krbs->tag == 0xa8 && (krbs->msg_type == ERROR_MSG_TYPE)))
            {
                krbs->next_state = KRB_STATE_CNAME_SEQ;
            }
            else if (krbs->tag == 0xa6 && krbs->msg_type == ERROR_MSG_TYPE)
            {
                krbs->state = KRB_STATE_ERROR;
                krbs->pos = 0;
                break;
            }
            else
                krbs->next_state = KRB_STATE_FIELD_DATA;
            krbs->state = KRB_STATE_LEN;
            break;
        case KRB_STATE_FIELD_DATA:
            if (krbs->msg_len < krbs->len)
                return KRB_FAILED;
            krbs->state = KRB_STATE_FIELD_DATA_2;
            // fallthrough
       case KRB_STATE_FIELD_DATA_2:
            if (krbs->len <= 1)
            {
                if (krbs->msg_len <= 1)
                {
                    krbs->flags |= KRB_FLAG_SERVICE_DETECTED;
                    krbs->state = KRB_STATE_APP;
                    if (!krbs->msg_len)
                        continue;
                    break;
                }
                krbs->state = KRB_STATE_FIELD;
                if (!krbs->len)
                    continue;
                break;
            }
            krbs->len--;
            break;
        case KRB_STATE_CNAME_SEQ:
            if (krbs->len < (KRB_CNAME_TYPE_SIZE + 5) || krbs->len > krbs->msg_len || *s != 0x30)
                return KRB_FAILED;
            krbs->cname_len = krbs->len;
            krbs->next_state = KRB_STATE_CNAME_TYPE;
            krbs->state = KRB_STATE_LEN;
            break;
        case KRB_STATE_CNAME_TYPE:
            if (krbs->len > krbs->cname_len || krbs->len < (KRB_CNAME_TYPE_SIZE + 3))
                return KRB_FAILED;
            krbs->state = KRB_STATE_CNAME_TYPE_2;
            krbs->pos = 0;
            // fallthrough
       case KRB_STATE_CNAME_TYPE_2:
            if (*s != KRB_CNAME_TYPE[krbs->pos])
                return KRB_FAILED;
            krbs->pos++;
            if (krbs->pos >= KRB_CNAME_TYPE_SIZE)
                krbs->state = KRB_STATE_CNAME_TYPE_VALUE;
            break;
        case KRB_STATE_CNAME_TYPE_VALUE:
            if (krbs->cname_len < 3 || (*s > 7 && *s != 10))
                return KRB_FAILED;
            if (*s != 1)
            {
                krbs->len = krbs->cname_len;
                krbs->state = KRB_STATE_FIELD_DATA_2;
                break;
            }
            krbs->state = KRB_STATE_CNAME;
            break;
        case KRB_STATE_CNAME:
            if (krbs->cname_len < 3 || *s != 0xa1)
                return KRB_FAILED;
            krbs->next_state = KRB_STATE_CNAME_PRINCIPAL_SEQ;
            krbs->state = KRB_STATE_LEN;
            break;
        case KRB_STATE_CNAME_PRINCIPAL_SEQ:
            if (krbs->len != krbs->cname_len || krbs->cname_len < 3 || *s != 0x30)
                return KRB_FAILED;
            krbs->next_state = KRB_STATE_CNAME_PRINCIPAL_KS;
            krbs->state = KRB_STATE_LEN;
            break;
        case KRB_STATE_CNAME_PRINCIPAL_KS:
            if (krbs->len != krbs->cname_len || krbs->cname_len < 3 || *s != 0x1b)
                return KRB_FAILED;
            krbs->next_state = KRB_STATE_CNAME_PRINCIPAL_DATA;
            krbs->state = KRB_STATE_LEN;
            break;
        case KRB_STATE_CNAME_PRINCIPAL_DATA:
            if (krbs->len != krbs->cname_len)
                return KRB_FAILED;
            krbs->state = KRB_STATE_CNAME_PRINCIPAL_DATA_2;
            krbs->pos = 0;
            // fallthrough
       case KRB_STATE_CNAME_PRINCIPAL_DATA_2:
            if (krbs->len)
            {
                if (krbs->pos < (sizeof(krbs->cname) - 2))
                {
                    if (isalnum(*s) || *s == '.' || *s == '@' || *s == '-' || *s == '_' || *s ==
                        '`' || *s == ' ')
                    {
                        krbs->cname[krbs->pos] = *s;
                        krbs->pos++;
                    }
                    else
                    {
                        krbs->len = krbs->cname_len;
                        krbs->state = KRB_STATE_FIELD_DATA_2;
                        break;
                    }
                }
            }
            if (krbs->len <= 1)
            {
                if (krbs->pos)
                {
                    krbs->cname[krbs->pos] = 0;
                    krbs->flags |= KRB_FLAG_USER_DETECTED;
                }
                if (krbs->msg_len <= 1)
                {
                    krbs->flags |= KRB_FLAG_SERVICE_DETECTED;
                    krbs->state = KRB_STATE_APP;
                    if (!krbs->msg_len)
                        continue;
                }
                krbs->state = KRB_STATE_FIELD;
                if (!krbs->len)
                    continue;
                break;
            }
            krbs->len--;
            break;
        case KRB_STATE_LEN:
            if (*s & 0x80)
            {
                krbs->pos = *s & 0x7F;
                if (!krbs->pos || krbs->pos > 4)
                {
                    /* Not handling indeterminate length or length greater than 32 bits */
                    return KRB_FAILED;
                }
                krbs->len = 0;
                krbs->state = KRB_STATE_LEN_2;
            }
            else
            {
                krbs->len = *s;
                krbs->state = krbs->next_state;
            }
            break;
        case KRB_STATE_LEN_2:
            if (krbs->msg_len)
            {
                krbs->len <<= 8;
                krbs->len |= *s;
                if (krbs->pos <= 1)
                {
                    krbs->state = krbs->next_state;
                    break;
                }
                krbs->pos--;
            }
            else
                return KRB_FAILED;
            break;
        default:
            /* This should never happen */
            return KRB_FAILED;
        }
        krbs->msg_len--;
        krbs->cname_len--;
        s++;
    }

    if (krbs->msg_len <= 1)
    {
        /*end of server response message */
        if (krbs->flags & KRB_FLAG_SERVICE_DETECTED)
            if (!asd.is_service_detected() && pkt)
                krb_service_detector->add_service(asd, pkt, dir, APP_ID_KERBEROS,
                    nullptr, krbs->ver, nullptr);

        if (krbs->flags & KRB_FLAG_AUTH_FAILED)
        {
            if (krb_client_detector->failed_login
                && ((krbs->flags & KRB_FLAG_USER_DETECTED) || reqCname))
            {
                krb_service_detector->add_user(asd,
                    (krbs->flags & KRB_FLAG_USER_DETECTED) ? krbs->cname : reqCname,
                    APP_ID_LDAP, false);
            }
        }
        else if (krbs->flags & KRB_FLAG_USER_DETECTED)
            krb_service_detector->add_user(asd, krbs->cname, APP_ID_LDAP, true);

        krbs->flags = 0;
    }

    return KRB_INPROCESS;
}

static const uint8_t AS_REP[] = "\x0a0\x003\x002\x001\x005\x0a1\x003\x002\x001\x00b";
static const uint8_t TGS_REP[] = "\x0a0\x003\x002\x001\x005\x0a1\x003\x002\x001\x00d";
static const uint8_t AS_REP_4[] = "\x0a0\x003\x002\x001\x004\x0a1\x003\x002\x001\x00b";
static const uint8_t TGS_REP_4[] = "\x0a0\x003\x002\x001\x004\x0a1\x003\x002\x001\x00d";

KerberosServiceDetector::KerberosServiceDetector(ServiceDiscovery* sd)
{
    krb_service_detector = this;
    handler = sd;
    name = "kerberos";
    proto = IpProtocol::TCP;
    provides_user = true;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { AS_REP, sizeof(AS_REP) - 1, -1, 0, 0 },
        { TGS_REP, sizeof(TGS_REP) - 1, -1, 0, 0 },
        { AS_REP_4, sizeof(AS_REP_4) - 1, -1, 0, 0 },
        { TGS_REP_4, sizeof(TGS_REP_4) - 1, -1, 0, 0 },
    };

    udp_patterns = tcp_patterns;

    appid_registry =
    {
        { APP_ID_KERBEROS, APPINFO_FLAG_CLIENT_USER | APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { 88, IpProtocol::TCP, false },
        { 88, IpProtocol::UDP, false },
    };

    handler->register_detector(name, this, proto);
}


int KerberosServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    KerberosDetectorData* fd;
    const uint8_t* s = args.data;
    const uint8_t* end = (args.data + args.size);

    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

#ifdef APP_ID_USES_REASSEMBLED
    Stream::flush_response_flush(pkt);
#endif

    if (!args.size)
        goto inprocess;

    // server side is seeing packets so no need for client side to process them
    args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    fd = krb_client_detector->get_common_data(args.asd);

    if (fd->need_continue)
        args.asd.set_session_flags(APPID_SESSION_CONTINUE);
    else
    {
        args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
        if (args.asd.is_service_detected())
            return APPID_SUCCESS;
    }

    if (krb_walk_server_packet(&fd->svr_state, s, end, args.asd, args.pkt, args.dir, fd->clnt_state.cname) ==
        KRB_FAILED)
    {
        if (!args.asd.is_service_detected())
        {
            fail_service(args.asd, args.pkt, args.dir);
            return APPID_NOMATCH;
        }
        args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
        return APPID_SUCCESS;
    }

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;
}

static const uint8_t AS_REQ[] = "\x0a1\x003\x002\x001\x005\x0a2\x003\x002\x001\x00a";
static const uint8_t TGS_REQ[] = "\x0a1\x003\x002\x001\x005\x0a2\x003\x002\x001\x00c";
static const uint8_t AS_REQ_4[] = "\x0a1\x003\x002\x001\x004\x0a2\x003\x002\x001\x00a";
static const uint8_t TGS_REQ_4[] = "\x0a1\x003\x002\x001\x004\x0a2\x003\x002\x001\x00c";

KerberosClientDetector::KerberosClientDetector(ClientDiscovery* cdm)
{
    krb_client_detector = this;
    handler = cdm;
    name = "kerberos";
    proto = IpProtocol::TCP;
    minimum_matches = 1;
    provides_user = true;

    tcp_patterns =
    {
        { AS_REQ, sizeof(AS_REQ) - 1, -1, 0, 0 },
        { TGS_REQ, sizeof(TGS_REQ) - 1, -1, 0, 0 },
        { AS_REQ_4, sizeof(AS_REQ_4) - 1, -1, 0, 0 },
        { TGS_REQ_4, sizeof(TGS_REQ_4) - 1, -1, 0, 0 }
    };

    udp_patterns = tcp_patterns;

    appid_registry =
    {
        { APP_ID_KERBEROS, APPINFO_FLAG_CLIENT_USER | APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    handler->register_detector(name, this, proto);
}


int KerberosClientDetector::krb_walk_client_packet(KRBState* krbs, const uint8_t* s,
    const  uint8_t* end, AppIdSession& asd)
{
    static const uint8_t KRB_CLIENT_VERSION[] = "\x0a1\x003\x002\x001";
    static const uint8_t KRB_CLIENT_TYPE[] = "\x0a2\x003\x002\x001";
    static const uint8_t KRB_CNAME_TYPE[] = "\x0a0\x003\x002\x001";
#define KRB_CNAME_TYPE_SIZE (sizeof(KRB_CNAME_TYPE) - 1)

    while (s < end)
    {
        switch (krbs->state)
        {
        case KRB_STATE_TCP_LENGTH:
            if (krbs->pos >= 3)
                krbs->state = KRB_STATE_APP;
            else
                krbs->pos++;
            break;
        case KRB_STATE_APP:
            if ((*s & ASN_1_TYPE_MASK) != (ASN_1_APPLICATION|ASN_1_CONSTRUCT))
                return KRB_FAILED;
            krbs->msg_type = *s & (~ASN_1_TYPE_MASK);
            switch (krbs->msg_type)
            {
            case AS_REQ_MSG_TYPE:
            case TGS_REQ_MSG_TYPE:
            case ERROR_MSG_TYPE:
            case 14:
            case 16:
            case 20:
            case 21:
            case 22:
                krbs->next_state = KRB_STATE_SEQ;
                break;
            default:
                return KRB_FAILED;
            }
            krbs->state = KRB_STATE_LEN;
            krbs->msg_len = 0xFFFFFFFF;
            break;
        case KRB_STATE_SEQ:
            if (krbs->len < 2 || *s != 0x30)
                return KRB_FAILED;
            krbs->msg_len = krbs->len;
            krbs->next_state = KRB_STATE_VERSION;
            krbs->state = KRB_STATE_LEN;
            krbs->pos = 0;
            break;
        case KRB_STATE_VERSION:
            if (krbs->len < 10 || krbs->len != krbs->msg_len)
                return KRB_FAILED;
            krbs->state = KRB_STATE_VERSION_2;
            krbs->pos = 0;
            // fallthrough
        case KRB_STATE_VERSION_2:
            if (*s != KRB_CLIENT_VERSION[krbs->pos])
                return KRB_FAILED;
            krbs->pos++;
            if (krbs->pos >= sizeof(KRB_CLIENT_VERSION) - 1)
                krbs->state = KRB_STATE_VERSION_VALUE;
            break;
        case KRB_STATE_VERSION_VALUE:
            if (*s != 5 && *s != 4)
                return KRB_FAILED;
            krbs->state = KRB_STATE_TYPE;
            krbs->pos = 0;
            krbs->ver[0] = *s + '0';
            break;
        case KRB_STATE_TYPE:
            if (*s != KRB_CLIENT_TYPE[krbs->pos])
                return KRB_FAILED;
            if (krbs->pos >= (sizeof(KRB_CLIENT_TYPE) - 1) - 1)
            {
                krbs->state = KRB_STATE_TYPE_VALUE;
                break;
            }
            krbs->pos++;
            break;
        case KRB_STATE_TYPE_VALUE:
            if (*s != krbs->msg_type)
                return KRB_FAILED;
            krbs->state = KRB_STATE_FIELD;
            krbs->tag = 0xa2;
            break;
        case KRB_STATE_FIELD:
            if (krbs->msg_len < 2 || *s <= krbs->tag || (*s & ASN_1_TYPE_MASK) != 0xa0)
                return KRB_FAILED;
            krbs->tag = *s;
            if (krbs->tag == 0xa4
                && (krbs->msg_type == AS_REQ_MSG_TYPE || krbs->msg_type == TGS_REQ_MSG_TYPE)
                && krb_client_detector->failed_login)
            {
                krbs->next_state = KRB_STATE_REQBODY_SEQ;
            }
            else
                krbs->next_state = KRB_STATE_FIELD_DATA;
            krbs->state = KRB_STATE_LEN;
            break;
        case KRB_STATE_FIELD_DATA:
            if (krbs->msg_len < krbs->len)
                return KRB_FAILED;
            krbs->state = KRB_STATE_FIELD_DATA_2;
            // fallthrough
       case KRB_STATE_FIELD_DATA_2:
            if (krbs->len <= 1)
            {
                if (krbs->msg_len <= 1)
                {
                    if (!krbs->added)
                    {
                        add_app(asd, APP_ID_KERBEROS, APP_ID_KERBEROS, krbs->ver);
                        krbs->added = 1;
                    }
                    krbs->state = KRB_STATE_APP;
                    if (!krbs->msg_len)
                        continue;
                    break;
                }
                krbs->state = KRB_STATE_FIELD;
                if (!krbs->len)
                    continue;
                break;
            }
            krbs->len--;
            break;
        case KRB_STATE_REQBODY_SEQ:
            /*REQ_BODY is the last level 1 element in AS-REQ and TSG-REQ messages therefore
              a. its length is not maintained, remaining msg_len is assumed to be req_body length
              b. krbs->rtag is reused at level 2 */

            if (*s != 0x30)
                return KRB_FAILED;

            krbs->next_state = KRB_STATE_FIELD_LEVEL2;
            krbs->state = KRB_STATE_LEN;
            krbs->tag = 0;
            break;

        case KRB_STATE_FIELD_LEVEL2:
            if (krbs->msg_len <= 1)
            {
                krbs->state = KRB_STATE_APP;
                if (!krbs->msg_len)
                    continue;
                break;
            }

            if (krbs->msg_len < 2 || *s <= krbs->tag || (*s & ASN_1_TYPE_MASK) != 0xa0)
                return KRB_FAILED;
            krbs->tag = *s;
            if (krbs->tag == 0xa1)
                krbs->next_state = KRB_STATE_CNAME_SEQ;
            else
                krbs->next_state = KRB_STATE_FIELD_DATA_LEVEL2;
            krbs->state = KRB_STATE_LEN;
            break;
        case KRB_STATE_FIELD_DATA_LEVEL2:
            if (krbs->msg_len < krbs->len)
                return KRB_FAILED;
            krbs->next_state = KRB_STATE_FIELD_DATA_2_LEVEL2;
            krbs->state = KRB_STATE_LEN;
            break;

        case KRB_STATE_FIELD_DATA_2_LEVEL2:
            if (krbs->len <= 1)
            {
                krbs->state = KRB_STATE_FIELD_LEVEL2;
                if (!krbs->len)
                    continue;
                break;
            }
            krbs->len--;
            break;

        case KRB_STATE_CNAME_SEQ:
            if (krbs->len < (KRB_CNAME_TYPE_SIZE + 5) || krbs->len > krbs->msg_len || *s != 0x30)
                return KRB_FAILED;
            krbs->cname_len = krbs->len;
            krbs->next_state = KRB_STATE_CNAME_TYPE;
            krbs->state = KRB_STATE_LEN;
            break;

        case KRB_STATE_CNAME_TYPE:
            if (krbs->len > krbs->cname_len || krbs->len < (KRB_CNAME_TYPE_SIZE + 3))
                return KRB_FAILED;
            krbs->state = KRB_STATE_CNAME_TYPE_2;
            krbs->pos = 0;
            // fallthrough
       case KRB_STATE_CNAME_TYPE_2:
            if (*s != KRB_CNAME_TYPE[krbs->pos])
                return KRB_FAILED;
            krbs->pos++;
            if (krbs->pos >= KRB_CNAME_TYPE_SIZE)
                krbs->state = KRB_STATE_CNAME_TYPE_VALUE;
            break;
        case KRB_STATE_CNAME_TYPE_VALUE:
            if (krbs->cname_len < 3 || (*s > 7 && *s != 10))
                return KRB_FAILED;
            if (*s != 1)
            {
                krbs->len = krbs->cname_len;
                krbs->state = KRB_STATE_FIELD_DATA_2;
                break;
            }
            krbs->state = KRB_STATE_CNAME;
            break;
        case KRB_STATE_CNAME:
            if (krbs->cname_len < 3 || *s != 0xa1)
                return KRB_FAILED;
            krbs->next_state = KRB_STATE_CNAME_PRINCIPAL_SEQ;
            krbs->state = KRB_STATE_LEN;
            break;
        case KRB_STATE_CNAME_PRINCIPAL_SEQ:
            if (krbs->len != krbs->cname_len || krbs->cname_len < 3 || *s != 0x30)
                return KRB_FAILED;
            krbs->next_state = KRB_STATE_CNAME_PRINCIPAL_KS;
            krbs->state = KRB_STATE_LEN;
            break;
        case KRB_STATE_CNAME_PRINCIPAL_KS:
            if (krbs->len != krbs->cname_len || krbs->cname_len < 3 || *s != 0x1b)
                return KRB_FAILED;
            krbs->next_state = KRB_STATE_CNAME_PRINCIPAL_DATA;
            krbs->state = KRB_STATE_LEN;
            break;
        case KRB_STATE_CNAME_PRINCIPAL_DATA:
            if (krbs->len != krbs->cname_len)
                return KRB_FAILED;
            krbs->state = KRB_STATE_CNAME_PRINCIPAL_DATA_2;
            krbs->pos = 0;
            // fallthrough
       case KRB_STATE_CNAME_PRINCIPAL_DATA_2:
            if (krbs->len)
            {
                if (krbs->pos < (sizeof(krbs->cname) - 2))
                {
                    if (isalnum(*s) || *s == '.' || *s == '@' || *s == '-' || *s == '_' || *s ==
                        '`' || *s == ' ')
                    {
                        krbs->cname[krbs->pos] = *s;
                        krbs->pos++;
                    }
                    else
                    {
                        krbs->len = krbs->cname_len;
                        krbs->state = KRB_STATE_FIELD_DATA_2;
                        break;
                    }
                }
            }
            if (krbs->len <= 1)
            {
                if (krbs->pos)
                {
                    krbs->cname[krbs->pos] = 0;
                }
                if (krbs->msg_len <= 1)
                {
                    krbs->state = KRB_STATE_APP;
                    if (!krbs->msg_len)
                        continue;
                }
                krbs->state = KRB_STATE_FIELD_LEVEL2;
                if (!krbs->len)
                    continue;
                break;
            }
            krbs->len--;
            break;
        case KRB_STATE_LEN:
            if (*s & 0x80)
            {
                krbs->pos = *s & 0x7F;
                if (!krbs->pos || krbs->pos > 4)
                {
                    /* Not handling indeterminate length or length greater than 32 bits */
                    return KRB_FAILED;
                }
                krbs->len = 0;
                krbs->state = KRB_STATE_LEN_2;
            }
            else
            {
                krbs->len = *s;
                krbs->state = krbs->next_state;
            }
            break;
        case KRB_STATE_LEN_2:
            if (krbs->msg_len)
            {
                krbs->len <<= 8;
                krbs->len |= *s;
                if (krbs->pos <= 1)
                {
                    krbs->state = krbs->next_state;
                    break;
                }
                krbs->pos--;
            }
            else
                return KRB_FAILED;
            break;
        default:
            /* This should never happen */
            return KRB_FAILED;
        }
        krbs->msg_len--;
        krbs->cname_len--;
        s++;
    }

    return KRB_INPROCESS;
}

KerberosDetectorData* KerberosClientDetector::get_common_data(AppIdSession& asd)
{
    KerberosDetectorData* dd = (KerberosDetectorData*)data_get(asd);
    if (!dd)
    {
        dd = (KerberosDetectorData*)snort_calloc(sizeof(KerberosDetectorData));
        data_add(asd, dd, &snort_free);
        if (asd.protocol == IpProtocol::TCP)
        {
            dd->clnt_state.state = KRB_STATE_TCP_LENGTH;
            dd->svr_state.state = KRB_STATE_TCP_LENGTH;
        }
        else
        {
            dd->clnt_state.state = KRB_STATE_APP;
            dd->svr_state.state = KRB_STATE_APP;
        }

        dd->need_continue = 1;
        asd.set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    return dd;
}

int KerberosClientDetector::validate(AppIdDiscoveryArgs& args)
{
    const uint8_t* s = args.data;
    const uint8_t* end = (args.data + args.size);

#ifdef APP_ID_USES_REASSEMBLED
    Stream::flush_response_flush(pkt);
#else
    UNUSED(args.pkt);
#endif

    if (!args.size)
        return APPID_INPROCESS;

    KerberosDetectorData* fd = get_common_data(args.asd);

    if (args.dir == APP_ID_FROM_INITIATOR)
    {
        if (krb_walk_client_packet(&fd->clnt_state, s, end, args.asd) == KRB_FAILED)
        {
            args.asd.set_client_detected();
            args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
            return APPID_SUCCESS;
        }
    }
    else if (krb_walk_server_packet(&fd->svr_state, s, end, args.asd, nullptr, args.dir,
        fd->clnt_state.cname) == KRB_FAILED)
    {
        args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }
    return APPID_INPROCESS;
}

