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

// detector_kerberos.cc author Sourcefire Inc.

#include "app_info_table.h"
#include "application_ids.h"
#include "client_plugins/client_app_api.h"
#include "service_plugins/service_api.h"

#include "main/snort_debug.h"
#include "utils/util.h"

/*#define DEBUG_KERBEROS  1 */

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
#ifdef DEBUG_KERBEROS
    KerberosState last_state;
#endif
    unsigned flags;
};

struct KRB_CLIENT_APP_CONFIG
{
    int enabled;
    int failedLogin;
};

struct DetectorData
{
    KRBState clnt_state;
    KRBState svr_state;
    int set_flags;
    int need_continue;
};

// FIXIT-L THREAD_LOCAL?
static KRB_CLIENT_APP_CONFIG krb_client_config;

static CLIENT_APP_RETCODE krb_client_init(const IniClientAppAPI* const init_api, SF_LIST* config);
static CLIENT_APP_RETCODE krb_client_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet* pkt, struct Detector* userData,
    const AppIdConfig* pConfig);

static RNAClientAppModule client_app_mod =
{
    "KERBEROS",
    IpProtocol::UDP,
    &krb_client_init,
    nullptr,
    &krb_client_validate,
    1,
    nullptr,
    nullptr,
    0,
    nullptr,
    1,
    0
};

struct Detector_Pattern
{
    const uint8_t* pattern;
    unsigned length;
};

static const uint8_t AS_REQ[] = "\x0a1\x003\x002\x001\x005\x0a2\x003\x002\x001\x00a";
static const uint8_t TGS_REQ[] = "\x0a1\x003\x002\x001\x005\x0a2\x003\x002\x001\x00c";
static const uint8_t AS_REQ_4[] = "\x0a1\x003\x002\x001\x004\x0a2\x003\x002\x001\x00a";
static const uint8_t TGS_REQ_4[] = "\x0a1\x003\x002\x001\x004\x0a2\x003\x002\x001\x00c";

static Detector_Pattern client_patterns[] =
{
    { AS_REQ, sizeof(AS_REQ)-1 },
    { TGS_REQ, sizeof(TGS_REQ)-1 },
    { AS_REQ_4, sizeof(AS_REQ_4)-1 },
    { TGS_REQ_4, sizeof(TGS_REQ_4)-1 },
};

static int krb_server_init(const IniServiceAPI* const init_api);
static int krb_server_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &krb_server_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "kerberos"
};

static RNAServiceValidationPort pp[] =
{
    { &krb_server_validate, 88, IpProtocol::TCP, 0 },
    { &krb_server_validate, 88, IpProtocol::UDP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

static RNAServiceValidationModule service_mod =
{
    "KRB",
    &krb_server_init,
    pp,
    nullptr,
    nullptr,
    1,
    nullptr,
    0
};

static const uint8_t AS_REP[] = "\x0a0\x003\x002\x001\x005\x0a1\x003\x002\x001\x00b";
static const uint8_t TGS_REP[] = "\x0a0\x003\x002\x001\x005\x0a1\x003\x002\x001\x00d";
static const uint8_t AS_REP_4[] = "\x0a0\x003\x002\x001\x004\x0a1\x003\x002\x001\x00b";
static const uint8_t TGS_REP_4[] = "\x0a0\x003\x002\x001\x004\x0a1\x003\x002\x001\x00d";

static Detector_Pattern service_patterns[] =
{
    { AS_REP, sizeof(AS_REP)-1 },
    { TGS_REP, sizeof(TGS_REP)-1 },
    { AS_REP_4, sizeof(AS_REP_4)-1 },
    { TGS_REP_4, sizeof(TGS_REP_4)-1 },
};

SO_PUBLIC RNADetectorValidationModule kerberos_detector_mod =
{
    &service_mod,
    &client_app_mod,
    nullptr,
    0,
    nullptr
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_KERBEROS, APPINFO_FLAG_CLIENT_USER | APPINFO_FLAG_SERVICE_ADDITIONAL }
};

static CLIENT_APP_RETCODE krb_client_init(const IniClientAppAPI* const init_api, SF_LIST* config)
{
    unsigned i;
    RNAClientAppModuleConfigItem* item;

    krb_client_config.enabled = 1;
    krb_client_config.failedLogin = 0;

    if (config)
    {
        SF_LNODE* iter = nullptr;

        for (item = (RNAClientAppModuleConfigItem*)sflist_first(config, &iter);
            item;
            item = (RNAClientAppModuleConfigItem*)sflist_next(&iter))
        {
            DebugFormat(DEBUG_INSPECTOR,"Processing %s: %s\n",item->name, item->value);
            if (strcasecmp(item->name, "enabled") == 0)
            {
                krb_client_config.enabled = atoi(item->value);
            }
            if (strcasecmp(item->name, "failed-login") == 0)
            {
                krb_client_config.failedLogin = atoi(item->value);
            }
        }
    }

    if (krb_client_config.enabled)
    {
        for (i=0; i < sizeof(client_patterns)/sizeof(*client_patterns); i++)
        {
            DebugFormat(DEBUG_INSPECTOR,"registering pattern with length %u\n",
                client_patterns[i].length);
            init_api->RegisterPattern(&krb_client_validate, IpProtocol::UDP,
                client_patterns[i].pattern, client_patterns[i].length, -1, init_api->pAppidConfig);
            init_api->RegisterPattern(&krb_client_validate, IpProtocol::TCP,
                client_patterns[i].pattern, client_patterns[i].length, -1, init_api->pAppidConfig);
        }
    }

    unsigned j;
    for (j=0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[j].appId);
        init_api->RegisterAppId(&krb_client_validate, appIdRegistry[j].appId,
            appIdRegistry[j].additionalInfo, init_api->pAppidConfig);
    }

    return CLIENT_APP_SUCCESS;
}

static int krb_server_init(const IniServiceAPI* const init_api)
{
    unsigned i;

    for (i=0; i < sizeof(service_patterns)/sizeof(*service_patterns); i++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering pattern with length %u\n",
            service_patterns[i].length);
        init_api->RegisterPatternUser(&krb_server_validate, IpProtocol::UDP,
            service_patterns[i].pattern,
            service_patterns[i].length, -1, "kerberos", init_api->pAppidConfig);
        init_api->RegisterPatternUser(&krb_server_validate, IpProtocol::TCP,
            service_patterns[i].pattern,
            service_patterns[i].length, -1, "kerberos", init_api->pAppidConfig);
    }

    unsigned j;
    for (j=0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[j].appId);
        init_api->RegisterAppId(&krb_server_validate, appIdRegistry[j].appId,
            appIdRegistry[j].additionalInfo, init_api->pAppidConfig);
    }

    return 0;
}

#define ASN_1_APPLICATION   0x40
#define ASN_1_CONSTRUCT     0x20
#define ASN_1_TYPE_MASK     0xe0
#define AS_REQ_MSG_TYPE     0x0a
#define AS_REP_MSG_TYPE     0x0b
#define TGS_REQ_MSG_TYPE    0x0c
#define TGS_REP_MSG_TYPE    0x0d
#define ERROR_MSG_TYPE      0x1e

static KRB_RETCODE krb_walk_client_packet(KRBState* krbs, const uint8_t* s, const uint8_t* end,
    AppIdData* flowp)
{
    static const uint8_t KRB_CLIENT_VERSION[] = "\x0a1\x003\x002\x001";
    static const uint8_t KRB_CLIENT_TYPE[] = "\x0a2\x003\x002\x001";
    static const uint8_t KRB_CNAME_TYPE[] = "\x0a0\x003\x002\x001";
#define KRB_CNAME_TYPE_SIZE (sizeof(KRB_CNAME_TYPE) - 1)

    while (s < end)
    {
#ifdef DEBUG_KERBEROS
        if (krbs->state != krbs->last_state)
        {
            DebugFormat(DEBUG_INSPECTOR,"%p State %d\n",flowp, krbs->state);
            krbs->last_state = krbs->state;
        }
#endif
        switch (krbs->state)
        {
        case KRB_STATE_TCP_LENGTH:
            if (krbs->pos >= 3)
                krbs->state = KRB_STATE_APP;
            else
                krbs->pos++;
            break;
        case KRB_STATE_APP:
#ifdef DEBUG_KERBEROS
            DebugFormat(DEBUG_INSPECTOR,"%p Type %u (%02X)\n",flowp, *s & (~ASN_1_TYPE_MASK), *s);
#endif
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
#ifdef DEBUG_KERBEROS
            DebugFormat(DEBUG_INSPECTOR,"%p Tag %02X\n",flowp, *s);
#endif
            if (krbs->msg_len < 2 || *s <= krbs->tag || (*s & ASN_1_TYPE_MASK) != 0xa0)
                return KRB_FAILED;
            krbs->tag = *s;
            if (krbs->tag == 0xa4
                && (krbs->msg_type == AS_REQ_MSG_TYPE || krbs->msg_type == TGS_REQ_MSG_TYPE)
                && krb_client_config.failedLogin)
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
        case KRB_STATE_FIELD_DATA_2:
            if (krbs->len <= 1)
            {
                if (krbs->msg_len <= 1)
                {
#ifdef DEBUG_KERBEROS
                    DebugFormat(DEBUG_INSPECTOR,"%p Valid\n",flowp);
#endif
                    if (!krbs->added)
                    {
                        client_app_mod.api->add_app(flowp, APP_ID_KERBEROS, APP_ID_KERBEROS,
                            krbs->ver);
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
#ifdef DEBUG_KERBEROS
            DebugFormat(DEBUG_INSPECTOR,"%p Tag %02X\n",flowp, *s);
#endif
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
#ifdef DEBUG_KERBEROS
                    DebugFormat(DEBUG_INSPECTOR,"%p Name %u\n",flowp, krbs->pos);
#endif
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

static KRB_RETCODE krb_walk_server_packet(KRBState* krbs, const uint8_t* s, const uint8_t* end,
    AppIdData* flowp, Packet* pkt, const int dir,
    const char* reqCname)
{
    static const uint8_t KRB_SERVER_VERSION[] = "\x0a0\x003\x002\x001";
    static const uint8_t KRB_SERVER_TYPE[] = "\x0a1\x003\x002\x001";
    static const uint8_t KRB_CNAME_TYPE[] = "\x0a0\x003\x002\x001";
    static const uint8_t KRB_ERROR[] = "\x003\x002\x001";
#define KRB_CNAME_TYPE_SIZE (sizeof(KRB_CNAME_TYPE) - 1)

    while (s < end)
    {
#ifdef DEBUG_KERBEROS
        if (krbs->state != krbs->last_state)
        {
            DebugFormat(DEBUG_INSPECTOR,"%p State %d\n",flowp, krbs->state);
            krbs->last_state = krbs->state;
        }
#endif
        switch (krbs->state)
        {
        case KRB_STATE_TCP_LENGTH:
            if (krbs->pos >= 3)
                krbs->state = KRB_STATE_APP;
            else
                krbs->pos++;
            break;
        case KRB_STATE_APP:
#ifdef DEBUG_KERBEROS
            DebugFormat(DEBUG_INSPECTOR,"%p Type %u (%02X)\n",flowp, *s & (~ASN_1_TYPE_MASK), *s);
#endif
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
#ifdef DEBUG_KERBEROS
            DebugFormat(DEBUG_INSPECTOR,"%p Error %u\n",flowp, *s);
#endif
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
#ifdef DEBUG_KERBEROS
                DebugFormat(DEBUG_INSPECTOR,"%p unAuthorized\n",flowp);
#endif
                krbs->flags |= KRB_FLAG_AUTH_FAILED;
            }
            krbs->state = KRB_STATE_FIELD;
            break;
        case KRB_STATE_FIELD:
#ifdef DEBUG_KERBEROS
            DebugFormat(DEBUG_INSPECTOR,"%p Tag %02X\n",flowp, *s);
#endif
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
#ifdef DEBUG_KERBEROS
                    DebugFormat(DEBUG_INSPECTOR,"%p Name %u\n",flowp, krbs->pos);
#endif
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
#ifdef DEBUG_KERBEROS
        DebugFormat(DEBUG_INSPECTOR,"%p Valid\n",flowp);
#endif
        if (krbs->flags & KRB_FLAG_SERVICE_DETECTED)
        {
            if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED) && pkt)
            {
                service_mod.api->add_service(flowp, pkt, dir, &svc_element, APP_ID_KERBEROS,
                    nullptr, krbs->ver, nullptr);
                setAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED);
            }
        }

        if (krbs->flags & KRB_FLAG_AUTH_FAILED)
        {
            if (krb_client_config.failedLogin
                && ((krbs->flags & KRB_FLAG_USER_DETECTED) || reqCname))
            {
                service_mod.api->add_user(flowp,
                    (krbs->flags & KRB_FLAG_USER_DETECTED) ? krbs->cname : reqCname,
                    APP_ID_LDAP, 0);
            }
        }
        else if (krbs->flags & KRB_FLAG_USER_DETECTED)
        {
            service_mod.api->add_user(flowp, krbs->cname, APP_ID_LDAP, 1);
        }

        krbs->flags = 0;
    }

    return KRB_INPROCESS;
}

static CLIENT_APP_RETCODE krb_client_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet*, struct Detector*, const AppIdConfig*)
{
    const uint8_t* s = data;
    const uint8_t* end = (data + size);
    DetectorData* fd;

#ifdef DEBUG_KERBEROS
    DebugFormat(DEBUG_INSPECTOR, "%p Processing %u %u->%u %u %d", flowp, flowp->proto,
        pkt->src_port,
        pkt->dst_port, size, dir);
#endif

#ifdef APP_ID_USES_REASSEMBLED
    kerberos_detector_mod.streamAPI->response_flush_stream(pkt);
#endif

    if (!size)
        return CLIENT_APP_INPROCESS;

    fd = (DetectorData*)kerberos_detector_mod.api->data_get(flowp,
        kerberos_detector_mod.flow_data_index);
    if (!fd)
    {
        fd = (DetectorData*)snort_calloc(sizeof(DetectorData));
        kerberos_detector_mod.api->data_add(flowp, fd,
            kerberos_detector_mod.flow_data_index, &snort_free);
        if (flowp->proto == IpProtocol::TCP)
        {
            fd->clnt_state.state = KRB_STATE_TCP_LENGTH;
            fd->svr_state.state = KRB_STATE_TCP_LENGTH;
        }
        else
        {
            fd->clnt_state.state = KRB_STATE_APP;
            fd->svr_state.state = KRB_STATE_APP;
        }
#ifdef DEBUG_KERBEROS
        fd->clnt_state.last_state = KRB_STATE_INVALID;
        fd->svr_state.last_state = KRB_STATE_INVALID;
#endif
    }

    if (!fd->set_flags)
    {
        fd->need_continue = 1;
        fd->set_flags = 1;
        setAppIdFlag(flowp, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    if (dir == APP_ID_FROM_INITIATOR)
    {
        if (krb_walk_client_packet(&fd->clnt_state, s, end, flowp) == KRB_FAILED)
        {
#ifdef DEBUG_KERBEROS
            DebugFormat(DEBUG_INSPECTOR,"%p Failed\n",flowp);
#endif
            setAppIdFlag(flowp, APPID_SESSION_CLIENT_DETECTED);
            clearAppIdFlag(flowp, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
            return CLIENT_APP_SUCCESS;
        }
    }
    else if (krb_walk_server_packet(&fd->svr_state, s, end, flowp, nullptr, dir,
        fd->clnt_state.cname) == KRB_FAILED)
    {
#ifdef DEBUG_KERBEROS
        DebugFormat(DEBUG_INSPECTOR,"%p Server Failed\n",flowp);
#endif
        clearAppIdFlag(flowp, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }
    return CLIENT_APP_INPROCESS;
}

static int krb_server_validate(ServiceValidationArgs* args)
{
    DetectorData* fd;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    Packet* pkt = args->pkt;
    const int dir = args->dir;
    uint16_t size = args->size;
    const uint8_t* s = data;
    const uint8_t* end = (data + size);

#ifdef DEBUG_KERBEROS
    DebugFormat(DEBUG_INSPECTOR, "%p Processing %u %u->%u %u %d", flowp, flowp->proto,
        pkt->src_port,
        pkt->dst_port, size, dir);
#endif

    if (dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

#ifdef APP_ID_USES_REASSEMBLED
    kerberos_detector_mod.streamAPI->response_flush_stream(pkt);
#endif

    if (!size)
        goto inprocess;

    fd = (DetectorData*)kerberos_detector_mod.api->data_get(flowp,
        kerberos_detector_mod.flow_data_index);
    if (!fd)
    {
        fd = (DetectorData*)snort_calloc(sizeof(DetectorData));
        kerberos_detector_mod.api->data_add(flowp, fd,
            kerberos_detector_mod.flow_data_index, &snort_free);
        if (flowp->proto == IpProtocol::TCP)
        {
            fd->clnt_state.state = KRB_STATE_TCP_LENGTH;
            fd->svr_state.state = KRB_STATE_TCP_LENGTH;
        }
        else
        {
            fd->clnt_state.state = KRB_STATE_APP;
            fd->svr_state.state = KRB_STATE_APP;
        }
#ifdef DEBUG_KERBEROS
        fd->clnt_state.last_state = KRB_STATE_INVALID;
        fd->svr_state.last_state = KRB_STATE_INVALID;
#endif
    }

    if (fd->need_continue)
        setAppIdFlag(flowp, APPID_SESSION_CONTINUE);
    else
    {
        clearAppIdFlag(flowp, APPID_SESSION_CONTINUE);
        if (getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
            return SERVICE_SUCCESS;
    }

    if (krb_walk_server_packet(&fd->svr_state, s, end, flowp, pkt, dir, fd->clnt_state.cname) ==
        KRB_FAILED)
    {
#ifdef DEBUG_KERBEROS
        DebugFormat(DEBUG_INSPECTOR,"%p Failed\n",flowp);
#endif
        if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
        {
            service_mod.api->fail_service(flowp, pkt, dir, &svc_element,
                service_mod.flow_data_index, args->pConfig);
            return SERVICE_NOMATCH;
        }
        clearAppIdFlag(flowp, APPID_SESSION_CONTINUE);
        return SERVICE_SUCCESS;
    }

inprocess:
    service_mod.api->service_inprocess(flowp, pkt, dir, &svc_element);
    return SERVICE_INPROCESS;
}

