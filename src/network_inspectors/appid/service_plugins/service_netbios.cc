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

// service_netbios.cc author Sourcefire Inc.

#include "service_netbios.h"

#ifdef HAVE_CONFIG_H
#include "config.h"     /* for WORDS_BIGENDIAN */
#endif

#include "log/messages.h"
#include "main/snort_debug.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "appid_api.h"
#include "appid_flow_data.h"
#include "application_ids.h"
#include "dcerpc.h"
#include "service_api.h"

/*#define RNA_DEBUG_NETBIOS   1 */

#define NBSS_PORT   139

#define NBNS_NB 32
#define NBNS_NBSTAT 33
#define NBNS_LENGTH_FLAGS 0xC0

#define NBNS_OPCODE_QUERY           0
#define NBNS_OPCODE_REGISTRATION    5
#define NBNS_OPCODE_RELEASE         6
#define NBNS_OPCODE_WEACK           7
#define NBNS_OPCODE_REFRESH         8
#define NBNS_OPCODE_REFRESHALT      9
#define NBNS_OPCODE_MHREGISTRATION 15

#define NBSS_COUNT_THRESHOLD 4

#define NBNS_REPLYCODE_MAX  7

#define NBSS_TYPE_MESSAGE       0x00
#define NBSS_TYPE_REQUEST       0x81
#define NBSS_TYPE_RESP_POSITIVE 0x82
#define NBSS_TYPE_RESP_NEGATIVE 0x83
#define NBSS_TYPE_RESP_RETARGET 0x84
#define NBSS_TYPE_KEEP_ALIVE    0x85

enum NBSSState
{
    NBSS_STATE_CONNECTION,
    NBSS_STATE_FLOW,
    NBSS_STATE_CONT,
    NBSS_STATE_ERROR
};

#define NBDGM_TYPE_DIRECT_UNIQUE        0x10
#define NBDGM_TYPE_DIRECT_GROUP         0x11
#define NBDGM_TYPE_BROADCAST            0x12
#define NBDGM_TYPE_ERROR                0x13
#define NBDGM_TYPE_REQUEST              0x14
#define NBDGM_TYPE_POSITIVE_REPSONSE    0x15
#define NBDGM_TYPE_NEGATIVE_RESPONSE    0x16

#define NBDGM_ERROR_CODE_MIN    0x82
#define NBDGM_ERROR_CODE_MAX    0x84

#define min(x,y) ((x)<(y) ? (x) : (y))

#pragma pack(1)

struct NBNSHeader
{
    uint16_t id;
#if defined(WORDS_BIGENDIAN)
    uint8_t response : 1,
        Opcode : 4,
        auth : 1,
        trunc : 1,
        RD : 1;
    uint8_t RA : 1,
        unused : 2,
        broadcast : 1,
        replycode : 4;
#else
    uint8_t RD : 1,
        trunc : 1,
        auth : 1,
        Opcode : 4,
        response : 1;
    uint8_t replycode : 4,
        broadcast : 1,
        unused : 2,
        RA : 1;
#endif
    uint16_t QCount;
    uint16_t ACount;
    uint16_t NSCount;
    uint16_t ARCount;
};

#define NBNS_NAME_LEN 0x20
struct NBNSLabelLength
{
    uint8_t len;
};

struct NBNSLabelData
{
    uint8_t len;
    uint8_t data[NBNS_NAME_LEN];
    uint8_t zero;
};

struct NBNSLabel
{
    uint16_t type;
    uint16_t class_id;
};

struct NBNSLabelPtr
{
    uint8_t flag;
    uint8_t position;
};

struct NBNSAnswerData
{
    uint32_t ttl;
    uint16_t data_len;
};

struct NBSSHeader
{
    uint8_t type;
    uint8_t flags;
    uint16_t length;
};

uint8_t NB_SMB_BANNER[] =
{
    0xFF, 'S', 'M', 'B'
};

struct ServiceSMBHeader
{
    uint8_t command;
    uint32_t status;
    uint8_t flags[3];
    uint16_t pid_high;
    uint8_t signature[8];
    uint16_t reserved2;
    uint16_t tid;
    uint16_t pid;
    uint16_t uid;
    uint16_t mid;
};

struct ServiceSMBAndXResponse
{
    uint8_t wc;
    uint8_t cmd;
    uint8_t reserved;
    uint16_t offset;
    uint16_t action;
    uint16_t sec_len;
};

struct ServiceSMBNegotiateProtocolResponse
{
    uint8_t wc;
    uint16_t dialect_index;
    uint8_t security_mode;
    uint16_t max_mpx_count;
    uint16_t max_vcs;
    uint32_t max_buffer_size;
    uint32_t max_raw_buffer;
    uint32_t session_key;
    uint32_t capabilities;
    uint32_t system_time[2];
    uint16_t time_zone;
    uint8_t sec_len;
};

struct ServiceSMBTransactionHeader
{
    uint8_t wc;
    uint16_t total_pc;
    uint16_t total_dc;
    uint16_t max_pc;
    uint16_t max_dc;
    uint8_t max_sc;
    uint8_t reserved;
    uint16_t flags;
    uint32_t timeout;
    uint16_t reserved2;
    uint16_t pc;
    uint16_t po;
    uint16_t dc;
    uint16_t offset;
    uint8_t sc;
    uint8_t reserved3;
};
/* sc * 2 to get to the transaction name */

#define SERVICE_SMB_STATUS_SUCCESS              0x00000000
#define SERVICE_SMB_TRANSACTION_COMMAND         0x25
#define SERVICE_SMB_COMMAND_SESSION_SETUP_ANDX_RESPONSE 0x73
#define SERVICE_SMB_COMMAND_NEGOTIATE_PROTOCOL          0x72
#define SERVICE_SMB_CAPABILITIES_EXTENDED_SECURITY  0x80000000
#define SERVICE_SMB_CAPABILITIES_UNICODE            0x00000004
#define SERVICE_SMB_FLAGS_RESPONSE              0x80
#define SERVICE_SMB_FLAGS_UNICODE               0x80
#define SERVICE_SMB_NOT_TRANSACTION_WC          8
#define SERVICE_SMB_MAILSLOT_HOST               0x01
#define SERVICE_SMB_MAILSLOT_LOCAL_MASTER       0x0f
#define SERVICE_SMB_MAILSLOT_SERVER_TYPE_XENIX  0x00000800
#define SERVICE_SMB_MAILSLOT_SERVER_TYPE_NT     0x00001000
static char mailslot[] = "\\MAILSLOT\\BROWSE";

struct ServiceSMBBrowserHeader
{
    uint8_t command;
    uint8_t count;
    uint32_t period;
    uint8_t hostname[16];
    uint8_t major;
    uint8_t minor;
    uint32_t server_type;
};

struct ServiceNBSSData
{
    NBSSState state;
    unsigned count;
    uint32_t length;
    AppId serviceAppId;
    AppId miscAppId;
};

struct NBDgmHeader
{
    uint8_t type;
#if defined(WORDS_BIGENDIAN)
    uint8_t zero : 4,
        SNT : 2,
        first : 1,
        more : 1;
#else
    uint8_t more : 1,
        first : 1,
        SNT : 2,
        zero : 4;
#endif
    uint16_t id;
    uint32_t src_ip;
    uint16_t src_port;
};

struct NBDgmError
{
    uint8_t code;
};

#pragma pack()

static int netbios_init(const IniServiceAPI* const init_api);
static int nbns_validate(ServiceValidationArgs* args);
static int nbss_validate(ServiceValidationArgs* args);
static int nbdgm_validate(ServiceValidationArgs* args);

static RNAServiceElement nbns_svc_element
{
    nullptr,
    &nbns_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "nbns"
};
static RNAServiceElement nbdgm_svc_element
{
    nullptr,
    &nbdgm_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "nbdgm"
};
static RNAServiceElement nbss_svc_element
{
    nullptr,
    &nbss_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "nbss"
};

static RNAServiceValidationPort pp[]
{
    { &nbns_validate, 137, IpProtocol::TCP, 0 },
    { &nbns_validate, 137, IpProtocol::UDP, 0 },
    { &nbns_validate, 137, IpProtocol::UDP, 1 },
    { &nbdgm_validate, 138, IpProtocol::UDP, 0 },
    { &nbss_validate, 139, IpProtocol::TCP, 0 },
    { &nbss_validate, 445, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

RNAServiceValidationModule netbios_service_mod
{
    "NETBIOS",
    &netbios_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static int netbios_init(const IniServiceAPI* const init_api)
{
    init_api->RegisterPattern(&nbss_validate, IpProtocol::TCP, NB_SMB_BANNER,
        sizeof(NB_SMB_BANNER),
        -1, "netbios", init_api->pAppidConfig);

    DebugFormat(DEBUG_INSPECTOR,"registering appId: %d for NetBIOS-ns\n",APP_ID_NETBIOS_NS);
    init_api->RegisterAppId(&nbns_validate, APP_ID_NETBIOS_NS, APPINFO_FLAG_SERVICE_UDP_REVERSED,
        init_api->pAppidConfig);

    DebugFormat(DEBUG_INSPECTOR,"registering appId: %d for NetBIOS-dgm\n",APP_ID_NETBIOS_DGM);
    init_api->RegisterAppId(&nbdgm_validate, APP_ID_NETBIOS_DGM, APPINFO_FLAG_SERVICE_ADDITIONAL,
        init_api->pAppidConfig);

    DebugFormat(DEBUG_INSPECTOR,"registering appId: %d for NetBIOS-ssn\n",APP_ID_NETBIOS_SSN);
    init_api->RegisterAppId(&nbss_validate, APP_ID_NETBIOS_SSN, APPINFO_FLAG_SERVICE_ADDITIONAL,
        init_api->pAppidConfig);

    DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",APP_ID_DCE_RPC);
    init_api->RegisterAppId(&nbss_validate, APP_ID_DCE_RPC, 0, init_api->pAppidConfig);

    return 0;
}

static int netbios_validate_name_and_decode(const uint8_t** data,
    const uint8_t* const begin,
    const uint8_t* const end,
    char* name)
{
    const NBNSLabelLength* lbl_len;
    const NBNSLabelData* lbl_data;
    const NBNSLabelPtr* lbl_ptr;
    int i;
    int j;

    if (end - *data < (int)sizeof(NBNSLabelLength))
        return -1;
    lbl_len = (NBNSLabelLength*)(*data);
    switch (lbl_len->len & NBNS_LENGTH_FLAGS)
    {
    case 0x00:
        lbl_data = (NBNSLabelData*)(*data);
        if (end - *data < (int)sizeof(NBNSLabelData))
            return -1;
        *data += sizeof(NBNSLabelData);
        break;
    case 0xC0:
        lbl_ptr = (NBNSLabelPtr*)(*data);
        *data += sizeof(NBNSLabelPtr);
        if (begin + lbl_ptr->position + sizeof(NBNSLabelData) > end)
            return -1;
        lbl_data = (NBNSLabelData*)(begin + lbl_ptr->position);
        break;
    default:
        return -1;
    }
    if (lbl_data->len != NBNS_NAME_LEN)
        return -1;
    if (lbl_data->zero)
        return -1;
    for (i=0; i<(NBNS_NAME_LEN/2); i++)
    {
        j = 2 * i;
        if (lbl_data->data[j] < 'A' || lbl_data->data[j] > 'Z')
            return -1;
        name[i] = (uint8_t)(((uint8_t)(lbl_data->data[j] - 'A')) << 4);
        j++;
        if (lbl_data->data[i] < 'A' || lbl_data->data[i] > 'Z')
            return -1;
        name[i] |= (uint8_t)(lbl_data->data[j] - 'A');
    }
    name[(NBNS_NAME_LEN/2)] = 0;
    for (i=(NBNS_NAME_LEN/2)-1; i >= 0; i--)
    {
        if (name[i] == ' ')
            name[i] = 0;
        else if (name[i])
            break;
    }
    return 0;
}

static int netbios_validate_name(const uint8_t** data,
    const uint8_t* const begin,
    const uint8_t* const end)
{
    const NBNSLabelLength* lbl_len;
    const NBNSLabelData* lbl_data;
    const NBNSLabelPtr* lbl_ptr;
    int i;

    if (end - *data < (int)sizeof(NBNSLabelLength))
        return -1;
    lbl_len = (NBNSLabelLength*)(*data);
    switch (lbl_len->len & NBNS_LENGTH_FLAGS)
    {
    case 0x00:
        lbl_data = (NBNSLabelData*)(*data);
        if (end - *data < (int)sizeof(NBNSLabelData))
            return -1;
        *data += sizeof(NBNSLabelData);
        break;
    case 0xC0:
        lbl_ptr = (NBNSLabelPtr*)(*data);
        *data += sizeof(NBNSLabelPtr);
        if (begin + lbl_ptr->position + sizeof(NBNSLabelData) > end)
            return -1;
        lbl_data = (NBNSLabelData*)(begin + lbl_ptr->position);
        break;
    default:
        return -1;
    }
    if (lbl_data->len != NBNS_NAME_LEN)
        return -1;
    if (lbl_data->zero)
        return -1;
    for (i=0; i<NBNS_NAME_LEN; i++)
        if (lbl_data->data[i] < 'A' || lbl_data->data[i] > 'Z')
            return -1;
    return 0;
}

static int netbios_validate_label(const uint8_t** data,
    const uint8_t* const end)
{
    const NBNSLabel* lbl;
    uint16_t tmp;

    if (end - *data < (int)sizeof(NBNSLabel))
        return -1;
    lbl = (NBNSLabel*)(*data);
    *data += sizeof(NBNSLabel);
    tmp = ntohs(lbl->type);
    if (tmp != NBNS_NB && tmp != NBNS_NBSTAT)
        return -1;
    return 0;
}

static int nbns_validate_query(const uint8_t** data, const uint8_t* const begin,
    const uint8_t* const end)
{
    int ret;

    ret = netbios_validate_name(data, begin, end);
    if (!ret)
    {
        return netbios_validate_label(data, end);
    }
    return ret;
}

static int nbns_validate_answer(const uint8_t** data, const uint8_t* const begin,
    const uint8_t* const end)
{
    int ret;
    uint16_t tmp;

    ret = netbios_validate_name(data, begin, end);
    if (ret)
        return ret;
    ret = netbios_validate_label(data, end);
    if (!ret)
    {
        const NBNSAnswerData* ad = (const NBNSAnswerData*)(*data);
        if (end - *data < (int)sizeof(NBNSAnswerData))
            return -1;
        *data += sizeof(NBNSAnswerData);
        tmp = ntohs(ad->data_len);
        if (end - *data < tmp)
            return -1;
        *data += tmp;
    }
    return ret;
}

static int nbns_validate(ServiceValidationArgs* args)
{
    uint16_t i;
    uint16_t count;
    const NBNSHeader* hdr;
    const uint8_t* begin;
    const uint8_t* end;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;
    if (size < sizeof(NBNSHeader))
        goto fail;
    hdr = (NBNSHeader*)data;
    if ((hdr->Opcode > NBNS_OPCODE_QUERY &&
        hdr->Opcode < NBNS_OPCODE_REGISTRATION) ||
        (hdr->Opcode > NBNS_OPCODE_REFRESHALT &&
        hdr->Opcode < NBNS_OPCODE_MHREGISTRATION))
    {
        goto fail;
    }
    if (hdr->trunc)
        goto not_compatible;
    if (hdr->broadcast)
        goto not_compatible;

    begin = data;
    end = data + size;
    data += sizeof(NBNSHeader);

    if (!hdr->response)
    {
        if (dir == APP_ID_FROM_RESPONDER)
        {
            if (getAppIdFlag(flowp, APPID_SESSION_UDP_REVERSED))
                goto success;
            goto fail;
        }
        goto inprocess;
    }

    if (hdr->replycode > NBNS_REPLYCODE_MAX)
        goto fail;

    if (hdr->QCount)
    {
        count = ntohs(hdr->QCount);
        for (i=0; i<count; i++)
        {
            if (nbns_validate_query(&data, begin, end))
                goto fail;
        }
    }

    if (hdr->ACount)
    {
        count = ntohs(hdr->ACount);
        for (i=0; i<count; i++)
        {
            if (nbns_validate_answer(&data, begin, end))
                goto fail;
        }
    }

    if (hdr->NSCount)
    {
        count = ntohs(hdr->NSCount);
        for (i=0; i<count; i++)
        {
            if (nbns_validate_answer(&data, begin, end))
                goto fail;
        }
    }

    if (hdr->ARCount)
    {
        count = ntohs(hdr->ARCount);
        for (i=0; i<count; i++)
        {
            if (nbns_validate_answer(&data, begin, end))
                goto fail;
        }
    }

    if (dir == APP_ID_FROM_INITIATOR)
    {
        setAppIdFlag(flowp, APPID_SESSION_UDP_REVERSED);
        goto inprocess;
    }

success:
    netbios_service_mod.api->add_service(flowp, args->pkt, dir, &nbns_svc_element,
        APP_ID_NETBIOS_NS, nullptr, nullptr, nullptr);
    return SERVICE_SUCCESS;

inprocess:
    netbios_service_mod.api->service_inprocess(flowp, args->pkt, dir, &nbns_svc_element);
    return SERVICE_INPROCESS;

fail:
    netbios_service_mod.api->fail_service(flowp, args->pkt, dir, &nbns_svc_element,
        netbios_service_mod.flow_data_index,
        args->pConfig);
    return SERVICE_NOMATCH;

not_compatible:
    netbios_service_mod.api->incompatible_data(flowp, args->pkt, dir, &nbns_svc_element,
        netbios_service_mod.flow_data_index,
        args->pConfig);
    return SERVICE_NOT_COMPATIBLE;
}

static void nbss_free_state(void* data)
{
    ServiceNBSSData* nd = (ServiceNBSSData*)data;

    if (nd)
    {
        snort_free(nd);
    }
}

static inline void smb_domain_skip_string(const uint8_t** data, uint16_t* size, uint16_t* offset,
    const uint8_t unicode)
{
    if (unicode)
    {
        if (*size != 0 && ((*offset) % 2))
        {
            (*offset)++;
            (*data)++;
            (*size)--;
        }
        while (*size > 1)
        {
            *size -= 2;
            *offset += 2;
            if (**data == 0)
            {
                *data += 2;
                break;
            }
            else
            {
                *data += 2;
            }
        }
    }
    else
    {
        while (*size)
        {
            (*size)--;
            (*offset)++;
            if (**data == 0)
            {
                (*data)++;
                break;
            }
            else
            {
                (*data)++;
            }
        }
    }
}

static inline void smb_find_domain(const uint8_t* data, uint16_t size, const int,
    AppIdData* flowp, const Packet* pkt)
{
    const ServiceSMBHeader* smb;
    const ServiceSMBAndXResponse* resp;
    const ServiceSMBNegotiateProtocolResponse* np;
    char domain[NBNS_NAME_LEN+1];
    unsigned pos = 0;
    uint16_t byte_count;
    uint16_t sec_len;
    uint16_t wc;
    uint8_t unicode;
    uint32_t capabilities;
    uint16_t offset;

    if (size < sizeof(*smb) + sizeof(wc))
        return;
    smb = (ServiceSMBHeader*)data;
    if (smb->status != SERVICE_SMB_STATUS_SUCCESS)
        return;
    if (!(smb->flags[0] & SERVICE_SMB_FLAGS_RESPONSE))
        return;
    unicode = smb->flags[2] & SERVICE_SMB_FLAGS_UNICODE;
    data += sizeof(*smb);
    size -= sizeof(*smb);
    resp = (ServiceSMBAndXResponse*)data;
    np = (ServiceSMBNegotiateProtocolResponse*)data;
    wc = 2 * (uint16_t)*data;
    offset = 1;
    data++;
    size--;
    if (size < (wc + sizeof(byte_count)))
        return;
    data += wc;
    size -= wc;
    byte_count = LETOHS(data);
    data += sizeof(byte_count);
    size -= sizeof(byte_count);
    if (size < byte_count)
        return;
    offset += sizeof(byte_count);
    offset += wc;
    if (smb->command == SERVICE_SMB_COMMAND_SESSION_SETUP_ANDX_RESPONSE)
    {
        if (wc == 8)
        {
            sec_len = LETOHS(&resp->sec_len);
            if (sec_len >= byte_count)
                return;
            data += sec_len;
            byte_count -= sec_len;
        }
        else if (wc != 6)
            return;
        smb_domain_skip_string(&data, &byte_count, &offset, unicode);
        smb_domain_skip_string(&data, &byte_count, &offset, unicode);
        if (byte_count != 0 && (offset % 2))
        {
            data++;
            byte_count--;
        }
    }
    else if (smb->command == SERVICE_SMB_COMMAND_NEGOTIATE_PROTOCOL)
    {
        if (wc == 34)
        {
            capabilities = LETOHL(&np->capabilities);
            if (capabilities & SERVICE_SMB_CAPABILITIES_EXTENDED_SECURITY)
                return;
            unicode = (capabilities & SERVICE_SMB_CAPABILITIES_UNICODE) || unicode;
        }
        else if (wc != 26)
            return;
        if (np->sec_len >= byte_count)
            return;
        data += np->sec_len;
        byte_count -= np->sec_len;
    }
    else
        return;
    if (unicode)
    {
        int found = 0;
        while (byte_count > 1)
        {
            byte_count -= 2;
            if (*data == 0)
            {
                data += 2;
                found = 1;
                break;
            }
            else
            {
                if (pos < NBNS_NAME_LEN)
                {
                    domain[pos] = *data;
                    pos++;
                    domain[pos] = 0;
                }
                data++;
                if (*data != 0)
                {
#ifdef RNA_DEBUG_NETBIOS
                    _dpd.errMsg("Failed command %02X  %u  0x%08X:%u->0x%08X:%u",
                        smb->command, byte_count, pkt->src_ip.s_addr, pkt->ptrs.sp,
                        pkt->dst_ip.s_addr, pkt->ptrs.dp);
#else
                    UNUSED(pkt);
#endif
                    return;
                }
                data++;
            }
        }
        if (!found && byte_count == 1 && *data == 0)
        {
            byte_count--;
        }
        if (byte_count && smb->command != SERVICE_SMB_COMMAND_NEGOTIATE_PROTOCOL)
        {
#ifdef RNA_DEBUG_NETBIOS
            _dpd.errMsg("Failed command %02X  %u  0x%08X:%u->0x%08X:%u",
                smb->command, byte_count, pkt->src_ip.s_addr, pkt->src_port, pkt->dst_ip.s_addr,
                pkt->dst_port);
#endif
            return;
        }
    }
    else
    {
        while (byte_count)
        {
            byte_count--;
            if (*data == 0)
            {
                data++;
                break;
            }
            else
            {
                if (pos < NBNS_NAME_LEN)
                {
                    domain[pos] = *data;
                    pos++;
                    domain[pos] = 0;
                }
                data++;
            }
        }
        if (byte_count && smb->command != SERVICE_SMB_COMMAND_NEGOTIATE_PROTOCOL)
        {
#ifdef RNA_DEBUG_NETBIOS
            _dpd.errMsg("Failed command %02X  %u  0x%08X:%u->0x%08X:%u",
                smb->command, byte_count, pkt->src_ip.s_addr, pkt->src_port, pkt->dst_ip.s_addr,
                pkt->dst_port);
#endif
            return;
        }
    }
    if (pos)
    {
#ifdef RNA_DEBUG_NETBIOS
        _dpd.debugMsg(DEBUG_LOG, "Found domain %s for command %02X 0x%08X:%u->0x%08X:%u",
            domain, smb->command, pkt->src_ip.s_addr, pkt->src_port, pkt->dst_ip.s_addr,
            pkt->dst_port);
#endif
        if (!flowp->netbiosDomain)
            flowp->netbiosDomain = snort_strdup(domain);
    }
}

static int nbss_validate(ServiceValidationArgs* args)
{
    ServiceNBSSData* nd;
    const NBSSHeader* hdr;
    const uint8_t* end;
    uint32_t tmp;
    int retval = -1;
    AppIdData* flowp = args->flowp;
    Packet* pkt = args->pkt;
    const uint8_t* data = args->data;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (dir != APP_ID_FROM_RESPONDER)
        goto inprocess;
    if (!size)
        goto inprocess;

    nd = (ServiceNBSSData*)netbios_service_mod.api->data_get(flowp,
        netbios_service_mod.flow_data_index);
    if (!nd)
    {
        nd = (ServiceNBSSData*)snort_calloc(sizeof(ServiceNBSSData));
        netbios_service_mod.api->data_add(flowp, nd,
            netbios_service_mod.flow_data_index, &nbss_free_state);
        nd->state = NBSS_STATE_CONNECTION;
        nd->serviceAppId = APP_ID_NETBIOS_SSN;
        nd->miscAppId = APP_ID_NONE;
    }

    end = data + size;
    while (data < end)
    {
        switch (nd->state)
        {
        case NBSS_STATE_CONNECTION:
            if (size < sizeof(NBSSHeader))
                goto fail;
            hdr = (NBSSHeader*)data;
            data += sizeof(NBSSHeader);
            nd->state = NBSS_STATE_ERROR;
            switch (hdr->type)
            {
            case NBSS_TYPE_RESP_POSITIVE:
                if (hdr->flags || hdr->length)
                    goto fail;
                nd->state = NBSS_STATE_FLOW;
                break;
            case NBSS_TYPE_RESP_NEGATIVE:
                if (hdr->flags || ntohs(hdr->length) != 1)
                    goto fail;
                if (data >= end)
                    goto fail;
                if (*data < 0x80 || (*data > 0x83 && *data < 0x8F) || *data > 0x8F)
                    goto fail;
                data++;
                break;
            case NBSS_TYPE_MESSAGE:
                if (hdr->flags & 0xFE)
                    goto fail;
                nd->length = ((uint32_t)(hdr->flags & 0x01)) << 16;
                nd->length |= (uint32_t)ntohs(hdr->length);
                tmp = end - data;
                if (tmp >= sizeof(NB_SMB_BANNER) &&
                    nd->length >= sizeof(NB_SMB_BANNER) &&
                    !memcmp(data, NB_SMB_BANNER, sizeof(NB_SMB_BANNER)))
                {
                    if (nd->serviceAppId != APP_ID_DCE_RPC)
                    {
                        nd->serviceAppId = APP_ID_NETBIOS_SSN;
                    }

                    if (nd->length <= tmp)
                    {
                        smb_find_domain(data + sizeof(NB_SMB_BANNER),
                            nd->length - sizeof(NB_SMB_BANNER),
                            dir, flowp, pkt);
                    }
                }
                else if (tmp >= 4 && nd->length >= 4 &&
                    !(*((uint32_t*)data)) &&
                    dcerpc_validate(data+4, ((int)min(tmp, nd->length)) - 4) > 0)
                {
                    nd->serviceAppId = APP_ID_DCE_RPC;
                    nd->miscAppId = APP_ID_NETBIOS_SSN;
                }

                if (tmp < nd->length)
                {
                    data = end;
                    nd->length -= tmp;
                    nd->state = NBSS_STATE_CONT;
                }
                else
                {
                    data += nd->length;
                    nd->count++;
                    nd->state = NBSS_STATE_FLOW;
                }
                break;
            case NBSS_TYPE_RESP_RETARGET:
                if (hdr->flags || ntohs(hdr->length) != 6)
                    goto fail;
                if (end - data < 6)
                    goto fail;
                data += 6;
                break;
            default:
                goto fail;
            }
            break;
        case NBSS_STATE_FLOW:
            if (size < sizeof(NBSSHeader))
                goto fail;
            hdr = (NBSSHeader*)data;
            data += sizeof(NBSSHeader);
            switch (hdr->type)
            {
            case NBSS_TYPE_KEEP_ALIVE:
                if (hdr->flags || hdr->length)
                    goto fail;
                break;
            case NBSS_TYPE_MESSAGE:
                if (hdr->flags & 0xFE)
                    goto fail;
                nd->length = ((uint32_t)(hdr->flags & 0x01)) << 16;
                nd->length += (uint32_t)ntohs(hdr->length);
                tmp = end - data;
                if (tmp >= sizeof(NB_SMB_BANNER) &&
                    nd->length >= sizeof(NB_SMB_BANNER) &&
                    !memcmp(data, NB_SMB_BANNER, sizeof(NB_SMB_BANNER)))
                {
                    if (nd->serviceAppId != APP_ID_DCE_RPC)
                    {
                        nd->serviceAppId = APP_ID_NETBIOS_SSN;
                    }
                    if (nd->length <= tmp)
                    {
                        smb_find_domain(data + sizeof(NB_SMB_BANNER), nd->length, dir, flowp, pkt);
                    }
                }
                else if (tmp >= 4 && nd->length >= 4 &&
                    !(*((uint32_t*)data)) &&
                    !(dcerpc_validate(data+4, ((int)min(tmp, nd->length)) - 4) > 0))
                {
                    nd->serviceAppId = APP_ID_DCE_RPC;
                    nd->miscAppId = APP_ID_NETBIOS_SSN;
                }

                if (tmp < nd->length)
                {
                    data = end;
                    nd->length -= tmp;
                    nd->state = NBSS_STATE_CONT;
                }
                else
                {
                    data += nd->length;
                    if (nd->count < NBSS_COUNT_THRESHOLD)
                    {
                        nd->count++;
                        if (nd->count >= NBSS_COUNT_THRESHOLD)
                        {
                            retval = SERVICE_SUCCESS;
                        }
                    }
                }
                break;
            default:
                goto fail;
            }
            break;
        case NBSS_STATE_CONT:
            tmp = end - data;
            if (tmp < nd->length)
            {
                data = end;
                nd->length -= tmp;
            }
            else
            {
                data += nd->length;
                nd->state = NBSS_STATE_FLOW;
                if (nd->count < NBSS_COUNT_THRESHOLD)
                {
                    nd->count++;
                    if (nd->count >= NBSS_COUNT_THRESHOLD)
                    {
                        retval = SERVICE_SUCCESS;
                    }
                }
            }
            break;
        default:
            goto fail;
        }
    }
    if (retval == -1)
        goto inprocess;

    if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
    {
        if (netbios_service_mod.api->add_service(flowp, pkt, dir, &nbss_svc_element,
            nd->serviceAppId, nullptr, nullptr, nullptr) == SERVICE_SUCCESS)
        {
            netbios_service_mod.api->add_misc(flowp, nd->miscAppId);
        }
    }
    return SERVICE_SUCCESS;

inprocess:
    if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
    {
        netbios_service_mod.api->service_inprocess(flowp, pkt, dir, &nbss_svc_element);
    }
    return SERVICE_INPROCESS;

fail:
    if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
    {
        netbios_service_mod.api->fail_service(flowp, pkt, dir, &nbss_svc_element,
            netbios_service_mod.flow_data_index, args->pConfig);
    }
    return SERVICE_NOMATCH;
}

static int nbdgm_validate(ServiceValidationArgs* args)
{
    const NBDgmHeader* hdr;
    const NBDgmError* err;
    const uint8_t* end;
    const ServiceSMBHeader* smb;
    const ServiceSMBTransactionHeader* trans;
    const ServiceSMBBrowserHeader* browser;
    uint16_t len;
    char source_name[(NBNS_NAME_LEN/2)+1];
    uint32_t server_type;
    AppId serviceAppId = APP_ID_NETBIOS_DGM;
    AppId miscAppId = APP_ID_NONE;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    Packet* pkt = args->pkt;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;
    if (size < sizeof(NBDgmHeader))
        goto fail;
    if (pkt->ptrs.sp != pkt->ptrs.dp)
        goto fail;

    source_name[0] = 0;
    end = data + size;

    hdr = (NBDgmHeader*)data;
    data += sizeof(NBDgmHeader);
    if (hdr->zero)
        goto fail;
    if (!hdr->first || hdr->more)
        goto fail;

    switch (hdr->type)
    {
    case NBDGM_TYPE_POSITIVE_REPSONSE:
    case NBDGM_TYPE_NEGATIVE_RESPONSE:
    case NBDGM_TYPE_REQUEST:
        if (netbios_validate_name(&data, data, end))
            goto fail;
        if (end != data)
            goto fail;
        goto success;
    case NBDGM_TYPE_DIRECT_UNIQUE:
    case NBDGM_TYPE_DIRECT_GROUP:
    case NBDGM_TYPE_BROADCAST:
        data += sizeof(uint16_t) + sizeof(uint16_t); /* dgm_length and packet_offset */
        if (data >= end)
            goto fail;
        if (netbios_validate_name_and_decode(&data, data, end, source_name))
            goto fail;
        if (data >= end)
            goto fail;
        if (netbios_validate_name(&data, data, end))
            goto fail;
        if (data >= end)
            goto fail;
        if (end-data >= (int)sizeof(NB_SMB_BANNER) &&
            !memcmp(data, NB_SMB_BANNER, sizeof(NB_SMB_BANNER)))
        {
            if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
            {
                serviceAppId = APP_ID_NETBIOS_DGM;
            }
            data += sizeof(NB_SMB_BANNER);
            if (end-data < (int)sizeof(ServiceSMBHeader))
                goto not_mailslot;
            smb = (ServiceSMBHeader*)data;
            data += sizeof(ServiceSMBHeader);
            if (smb->command != SERVICE_SMB_TRANSACTION_COMMAND)
                goto not_mailslot;
            if (end-data < (int)sizeof(ServiceSMBTransactionHeader))
                goto not_mailslot;
            trans = (ServiceSMBTransactionHeader*)data;
            data += sizeof(ServiceSMBTransactionHeader);
            if (trans->wc == SERVICE_SMB_NOT_TRANSACTION_WC)
                goto not_mailslot;
            if ((unsigned)(end-data) < (trans->sc*2)+sizeof(uint16_t)+sizeof(mailslot)+
                sizeof(ServiceSMBBrowserHeader))
                goto not_mailslot;
            data += (trans->sc*2);
            len = *((uint16_t*)data);
            data += sizeof(uint16_t);
            if (end-data < len)
                goto not_mailslot;
            if (memcmp(data, mailslot, sizeof(mailslot)))
                goto not_mailslot;
            data += sizeof(mailslot);
            browser = (ServiceSMBBrowserHeader*)data;
            if (browser->command != SERVICE_SMB_MAILSLOT_HOST &&
                browser->command != SERVICE_SMB_MAILSLOT_LOCAL_MASTER)
            {
                goto not_mailslot;
            }
            server_type = LETOHL(&browser->server_type);
            netbios_service_mod.api->analyzefp(flowp, browser->major, browser->minor, server_type);
        }
not_mailslot:
        if (source_name[0])
            netbios_service_mod.api->add_host_info(flowp, SERVICE_HOST_INFO_NETBIOS_NAME,
                source_name);
        setAppIdFlag(flowp, APPID_SESSION_CONTINUE);
        goto success;
    case NBDGM_TYPE_ERROR:
        if (end-data < (int)sizeof(NBDgmError))
            goto fail;
        err = (NBDgmError*)data;
        data += sizeof(NBDgmError);
        if (end != data)
            goto fail;
        if (err->code < NBDGM_ERROR_CODE_MIN ||
            err->code > NBDGM_ERROR_CODE_MAX)
        {
            goto fail;
        }
        goto success;
    default:
        break;
    }

fail:
    if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
    {
        netbios_service_mod.api->fail_service(flowp, pkt, dir, &nbdgm_svc_element,
            netbios_service_mod.flow_data_index,
            args->pConfig);
    }
    clearAppIdFlag(flowp, APPID_SESSION_CONTINUE);
    return SERVICE_NOMATCH;

success:
    if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
    {
        if (dir == APP_ID_FROM_RESPONDER)
        {
            if (netbios_service_mod.api->add_service(flowp, pkt, dir, &nbdgm_svc_element,
                serviceAppId, nullptr, nullptr, nullptr) == SERVICE_SUCCESS)
            {
                netbios_service_mod.api->add_misc(flowp, miscAppId);
            }
        }
    }
    return SERVICE_SUCCESS;

inprocess:
    if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
    {
        netbios_service_mod.api->service_inprocess(flowp, pkt, dir, &nbdgm_svc_element);
    }
    return SERVICE_INPROCESS;
}

