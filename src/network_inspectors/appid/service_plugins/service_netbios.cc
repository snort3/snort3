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

// service_netbios.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_netbios.h"
#include "detection/detection_engine.h"
#include "protocols/packet.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/smb_events.h"
#include "utils/endian.h"
#include "utils/util_cstring.h"

#include "app_info_table.h"
#include "appid_inspector.h"
#include "dcerpc.h"

using namespace snort;

#define NBNS_NB                     32
#define NBNS_NBSTAT                 33
#define NBNS_LENGTH_FLAGS           0xC0
#define NBNS_OPCODE_QUERY           0
#define NBNS_OPCODE_REGISTRATION    5
#define NBNS_OPCODE_RELEASE         6
#define NBNS_OPCODE_WEACK           7
#define NBNS_OPCODE_REFRESH         8
#define NBNS_OPCODE_REFRESHALT      9
#define NBNS_OPCODE_MHREGISTRATION 15
#define NBNS_REPLYCODE_MAX          7

#define NBDGM_TYPE_DIRECT_UNIQUE        0x10
#define NBDGM_TYPE_DIRECT_GROUP         0x11
#define NBDGM_TYPE_BROADCAST            0x12
#define NBDGM_TYPE_ERROR                0x13
#define NBDGM_TYPE_REQUEST              0x14
#define NBDGM_TYPE_POSITIVE_REPSONSE    0x15
#define NBDGM_TYPE_NEGATIVE_RESPONSE    0x16
#define NBDGM_ERROR_CODE_MIN            0x82
#define NBDGM_ERROR_CODE_MAX            0x84

#define FINGERPRINT_UDP_FLAGS_XENIX 0x00000800
#define FINGERPRINT_UDP_FLAGS_NT    0x00001000
#define FINGERPRINT_UDP_FLAGS_MASK  (FINGERPRINT_UDP_FLAGS_XENIX | FINGERPRINT_UDP_FLAGS_NT)

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

#define SERVICE_SMB_TRANSACTION_COMMAND         0x25
#define SERVICE_SMB_NOT_TRANSACTION_WC          8
#define SERVICE_SMB_MAILSLOT_HOST               0x01
#define SERVICE_SMB_MAILSLOT_LOCAL_MASTER       0x0f
static char mailslot[] = "\\MAILSLOT\\BROWSE";

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

static int netbios_validate_name_and_decode(const uint8_t** data,
    const uint8_t* const begin,
    const uint8_t* const end,
    char* name)
{
    const NBNSLabelLength* lbl_len;
    const NBNSLabelData* lbl_data;
    const NBNSLabelPtr* lbl_ptr;
    int i;

    if (end - *data < (int)sizeof(NBNSLabelLength))
        return -1;
    lbl_len = (const NBNSLabelLength*)(*data);
    switch (lbl_len->len & NBNS_LENGTH_FLAGS)
    {
    case 0x00:
        lbl_data = (const NBNSLabelData*)(*data);
        if (end - *data < (int)sizeof(NBNSLabelData))
            return -1;
        *data += sizeof(NBNSLabelData);
        break;
    case 0xC0:
        lbl_ptr = (const NBNSLabelPtr*)(*data);
        *data += sizeof(NBNSLabelPtr);
        if (begin + lbl_ptr->position + sizeof(NBNSLabelData) > end)
            return -1;
        lbl_data = (const NBNSLabelData*)(begin + lbl_ptr->position);
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
        int j = 2 * i;
        if (lbl_data->data[j] < 'A' or lbl_data->data[j] > 'Z')
            return -1;
        name[i] = (uint8_t)(((uint8_t)(lbl_data->data[j] - 'A')) << 4);
        j++;
        if (lbl_data->data[i] < 'A' or lbl_data->data[i] > 'Z')
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
    lbl_len = (const NBNSLabelLength*)(*data);
    switch (lbl_len->len & NBNS_LENGTH_FLAGS)
    {
    case 0x00:
        lbl_data = (const NBNSLabelData*)(*data);
        if (end - *data < (int)sizeof(NBNSLabelData))
            return -1;
        *data += sizeof(NBNSLabelData);
        break;
    case 0xC0:
        lbl_ptr = (const NBNSLabelPtr*)(*data);
        *data += sizeof(NBNSLabelPtr);
        if (begin + lbl_ptr->position + sizeof(NBNSLabelData) > end)
            return -1;
        lbl_data = (const NBNSLabelData*)(begin + lbl_ptr->position);
        break;
    default:
        return -1;
    }
    if (lbl_data->len != NBNS_NAME_LEN)
        return -1;
    if (lbl_data->zero)
        return -1;
    for (i=0; i<NBNS_NAME_LEN; i++)
        if (lbl_data->data[i] < 'A' or lbl_data->data[i] > 'Z')
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
    lbl = (const NBNSLabel*)(*data);
    *data += sizeof(NBNSLabel);
    tmp = ntohs(lbl->type);
    if (tmp != NBNS_NB and tmp != NBNS_NBSTAT)
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
        uint16_t tmp = ntohs(ad->data_len);

        if (end - *data < tmp)
            return -1;
        *data += tmp;
    }
    return ret;
}

NbnsServiceDetector::NbnsServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "nbns";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_NETBIOS_NS, APPINFO_FLAG_SERVICE_UDP_REVERSED }
    };

    service_ports =
    {
        { 137, IpProtocol::TCP, false },
        { 137, IpProtocol::UDP, false },
        { 137, IpProtocol::UDP, true }
    };

    handler->register_detector(name, this, proto);
}

int NbnsServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    uint16_t i;
    uint16_t count;
    const NBNSHeader* hdr;
    const uint8_t* begin;
    const uint8_t* end;
    const uint8_t* data = args.data;
    const AppidSessionDirection dir = args.dir;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;
    if (size < sizeof(NBNSHeader))
        goto fail;
    hdr = (const NBNSHeader*)data;
    if ((hdr->Opcode > NBNS_OPCODE_QUERY and
        hdr->Opcode < NBNS_OPCODE_REGISTRATION) or
        (hdr->Opcode > NBNS_OPCODE_REFRESHALT and
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
            if (args.asd.get_session_flags(APPID_SESSION_UDP_REVERSED))
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
        // Coverity doesn't realize that nbns_validate_query() checks the packet data for valid values
        // which validates the count
        // coverity[tainted_scalar]
        for (i=0; i<count; i++)
        {
            if (nbns_validate_query(&data, begin, end))
                goto fail;
        }
    }

    if (hdr->ACount)
    {
        count = ntohs(hdr->ACount);
        // Coverity doesn't realize that nbns_validate_answer() checks the packet data for valid values
        // which validates the count
        // coverity[tainted_scalar]
        for (i=0; i<count; i++)
        {
            if (nbns_validate_answer(&data, begin, end))
                goto fail;
        }
    }

    if (hdr->NSCount)
    {
        count = ntohs(hdr->NSCount);
        // Coverity doesn't realize that nbns_validate_answer() checks the packet data for valid values
        // which validates the count
        // coverity[tainted_scalar]
        for (i=0; i<count; i++)
        {
            if (nbns_validate_answer(&data, begin, end))
                goto fail;
        }
    }

    if (hdr->ARCount)
    {
        count = ntohs(hdr->ARCount);
        // Coverity doesn't realize that nbns_validate_answer() checks the packet data for valid values
        // which validates the count
        // coverity[tainted_scalar]
        for (i=0; i<count; i++)
        {
            if (nbns_validate_answer(&data, begin, end))
                goto fail;
        }
    }

    if (dir == APP_ID_FROM_INITIATOR)
    {
        args.asd.set_session_flags(APPID_SESSION_UDP_REVERSED);
        goto inprocess;
    }

success:
    return add_service(args.change_bits, args.asd, args.pkt, dir, APP_ID_NETBIOS_NS);

inprocess:
    service_inprocess(args.asd, args.pkt, dir);
    return APPID_INPROCESS;

fail:
    fail_service(args.asd, args.pkt, dir);
    return APPID_NOMATCH;

not_compatible:
    incompatible_data(args.asd, args.pkt, dir);
    return APPID_NOT_COMPATIBLE;
}

NbdgmServiceDetector::NbdgmServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "nbdgm";
    proto = IpProtocol::UDP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_NETBIOS_DGM, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { 138, IpProtocol::UDP, false }
    };

    handler->register_detector(name, this, proto);
}

int NbdgmServiceDetector::validate(AppIdDiscoveryArgs& args)
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
    const uint8_t* data = args.data;
    const AppidSessionDirection dir = args.dir;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;
    if (size < sizeof(NBDgmHeader))
        goto fail;
    if (args.pkt->ptrs.sp != args.pkt->ptrs.dp)
        goto fail;

    source_name[0] = 0;
    end = data + size;

    hdr = (const NBDgmHeader*)data;
    data += sizeof(NBDgmHeader);
    if (hdr->zero)
        goto fail;
    if (!hdr->first or hdr->more)
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
        if (end-data >= (int)sizeof(NB_SMB_BANNER) and
            !memcmp(data, NB_SMB_BANNER, sizeof(NB_SMB_BANNER)))
        {
            if (!args.asd.is_service_detected())
                serviceAppId = APP_ID_NETBIOS_DGM;

            data += sizeof(NB_SMB_BANNER);
            if (end-data < (int)sizeof(ServiceSMBHeader))
                goto not_mailslot;
            smb = (const ServiceSMBHeader*)data;
            data += sizeof(ServiceSMBHeader);
            if (smb->command != SERVICE_SMB_TRANSACTION_COMMAND)
                goto not_mailslot;
            if (end-data < (int)sizeof(ServiceSMBTransactionHeader))
                goto not_mailslot;
            trans = (const ServiceSMBTransactionHeader*)data;
            data += sizeof(ServiceSMBTransactionHeader);
            if (trans->wc == SERVICE_SMB_NOT_TRANSACTION_WC)
                goto not_mailslot;
            if ((unsigned)(end-data) < (trans->sc*2)+sizeof(uint16_t)+sizeof(mailslot)+
                sizeof(ServiceSMBBrowserHeader))
                goto not_mailslot;
            data += (trans->sc*2);
            len = *((const uint16_t*)data);
            data += sizeof(uint16_t);
            if (end-data < len)
                goto not_mailslot;
            if (memcmp(data, mailslot, sizeof(mailslot)))
                goto not_mailslot;
            data += sizeof(mailslot);
            browser = (const ServiceSMBBrowserHeader*)data;
            if (browser->command != SERVICE_SMB_MAILSLOT_HOST and
                browser->command != SERVICE_SMB_MAILSLOT_LOCAL_MASTER)
            {
                goto not_mailslot;
            }
            server_type = LETOHL_UNALIGNED(&browser->server_type);
            add_smb_info(args.asd, browser->major, browser->minor, server_type);
        }
not_mailslot:
        if (source_name[0])
            args.asd.set_netbios_name(args.change_bits, (const char*)source_name);
        args.asd.set_session_flags(APPID_SESSION_CONTINUE);
        goto success;
    case NBDGM_TYPE_ERROR:
        if (end-data < (int)sizeof(NBDgmError))
            goto fail;
        err = (const NBDgmError*)data;
        data += sizeof(NBDgmError);
        if (end != data)
            goto fail;
        if (err->code < NBDGM_ERROR_CODE_MIN or
            err->code > NBDGM_ERROR_CODE_MAX)
        {
            goto fail;
        }
        goto success;
    default:
        break;
    }

fail:
    if (!args.asd.is_service_detected())
    {
        fail_service(args.asd, args.pkt, dir);
    }
    args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
    return APPID_NOMATCH;

success:
    if (!args.asd.is_service_detected())
    {
        if (dir == APP_ID_FROM_RESPONDER)
        {
            if (add_service(args.change_bits, args.asd, args.pkt, dir, serviceAppId) == APPID_SUCCESS)
                add_miscellaneous_info(args.asd, miscAppId);
        }
    }
    return APPID_SUCCESS;

inprocess:
    if (!args.asd.is_service_detected())
        service_inprocess(args.asd, args.pkt, dir);
    return APPID_INPROCESS;
}

void NbdgmServiceDetector::add_smb_info(AppIdSession& asd, unsigned major, unsigned minor,
    uint32_t flags)
{
    if (flags & FINGERPRINT_UDP_FLAGS_XENIX)
        return;
    if (asd.get_session_flags(APPID_SESSION_HAS_SMB_INFO))
        return;
    asd.set_session_flags(APPID_SESSION_HAS_SMB_INFO);
    Packet* p = DetectionEngine::get_current_packet();
    FpSMBDataEvent event(p, major, minor, (flags & FINGERPRINT_UDP_FLAGS_MASK));
    DataBus::publish(AppIdInspector::get_pub_id(), AppIdEventIds::FP_SMB_DATA, event, p->flow);
}
