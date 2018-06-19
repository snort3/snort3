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

// service_tftp.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_tftp.h"

#include "protocols/packet.h"

#include "app_info_table.h"
#include "appid_debug.h"
#include "appid_inspector.h"

using namespace snort;

#define TFTP_PORT   69
#define TFTP_COUNT_THRESHOLD 1
#define TFTP_MAX_PACKET_SIZE 512

enum TFTPState
{
    TFTP_STATE_CONNECTION,
    TFTP_STATE_TRANSFER,
    TFTP_STATE_ACK,
    TFTP_STATE_DATA,
    TFTP_STATE_ERROR
};

struct ServiceTFTPData
{
    TFTPState state;
    unsigned count;
    int last;
    uint16_t block;
};

#pragma pack(1)

struct ServiceTFTPHeader
{
    uint16_t opcode;
    union
    {
        uint16_t block;
        uint16_t errorcode;
    } d;
};

#pragma pack()

TftpServiceDetector::TftpServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "tftp";
    proto = IpProtocol::UDP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_TFTP, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { TFTP_PORT, IpProtocol::UDP, false }
    };

    handler->register_detector(name, this, proto);
}


static int tftp_verify_header(const uint8_t* data, uint16_t size,
    uint16_t* block)
{
    if (size < sizeof(ServiceTFTPHeader))
        return -1;
    const ServiceTFTPHeader* hdr = (const ServiceTFTPHeader*)data;
    switch (ntohs(hdr->opcode))
    {
    case 3:
        if (size > sizeof(ServiceTFTPHeader) + TFTP_MAX_PACKET_SIZE)
            return -1;
        *block = ntohs(hdr->d.block);
        return TFTP_STATE_DATA;
    case 4:
        if (size != sizeof(ServiceTFTPHeader))
            return -1;
        *block = ntohs(hdr->d.block);
        return TFTP_STATE_ACK;
    case 5:
        if (ntohs(hdr->d.errorcode) > 7)
            return -1;
        if (size <= sizeof(ServiceTFTPHeader))
            return -1;
        if (data[size-1] != 0)
            return -1;
        return TFTP_STATE_ERROR;
    default:
        return -1;
    }
}

int TftpServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceTFTPData* td = nullptr;
    ServiceTFTPData* tmp_td = nullptr;
    int mode = 0;
    uint16_t block = 0;
    uint16_t tmp = 0;
    const snort::SfIp* sip = nullptr;
    const snort::SfIp* dip = nullptr;
    AppIdSession* pf = nullptr;
    const uint8_t* data = args.data;
    uint16_t size = args.size;
    //FIXIT-M - Avoid thread locals
    static THREAD_LOCAL SnortProtocolId tftp_snort_protocol_id = UNKNOWN_PROTOCOL_ID;

    if (!size)
        goto inprocess;

    td = (ServiceTFTPData*)data_get(args.asd);
    if (!td)
    {
        td = (ServiceTFTPData*)snort_calloc(sizeof(ServiceTFTPData));
        data_add(args.asd, td, &snort_free);
        td->state = TFTP_STATE_CONNECTION;
    }
    if (appidDebug->is_active())
        LogMessage("AppIdDbg %s TFTP state %d\n", appidDebug->get_debug_session(), td->state);

    if (td->state == TFTP_STATE_CONNECTION && args.dir == APP_ID_FROM_RESPONDER)
        goto fail;
    if ((td->state == TFTP_STATE_TRANSFER || td->state == TFTP_STATE_DATA) &&
        args.dir == APP_ID_FROM_INITIATOR)
    {
        goto inprocess;
    }
    switch (td->state)
    {
    case TFTP_STATE_CONNECTION:
        if (size < 6)
            goto bail;
        tmp = ntohs(*((const uint16_t*)data));
        if (tmp != 0x0001 && tmp != 0x0002)
            goto bail;
        data += sizeof(uint16_t);
        size -= sizeof(uint16_t);
        if (!(*data))
            goto bail;
        for (; *data && size; data++, size--)
        {
            if (!isprint(*data))
                goto bail;
        }
        if (!size)
            goto bail;
        size--;
        data++;
        if (!size || !(*data))
            goto bail;
        if (data[size-1])
            goto bail;
        if (strcasecmp((const char*)data, "netascii") && strcasecmp((const char*)data, "octet"))
            goto bail;

        if(tftp_snort_protocol_id == UNKNOWN_PROTOCOL_ID)
            tftp_snort_protocol_id = snort::SnortConfig::get_conf()->proto_ref->find("tftp");

        tmp_td = (ServiceTFTPData*)snort_calloc(sizeof(ServiceTFTPData));
        tmp_td->state = TFTP_STATE_TRANSFER;
        dip = args.pkt->ptrs.ip_api.get_dst();
        sip = args.pkt->ptrs.ip_api.get_src();
        pf = AppIdSession::create_future_session(args.pkt, dip, 0, sip,
            args.pkt->ptrs.sp, args.asd.protocol, tftp_snort_protocol_id, APPID_EARLY_SESSION_FLAG_FW_RULE,
            handler->get_inspector());
        if (pf)
        {
            data_add(*pf, tmp_td, &snort_free);
            if (pf->add_flow_data_id(args.pkt->ptrs.dp, this))
            {
                pf->set_session_flags(APPID_SESSION_SERVICE_DETECTED);
                pf->clear_session_flags(APPID_SESSION_CONTINUE);
                tmp_td->state = TFTP_STATE_ERROR;
                return APPID_ENOMEM;
            }
            initialize_expected_session(args.asd, *pf, APPID_SESSION_EXPECTED_EVALUATE, APP_ID_FROM_RESPONDER);
            pf->common.initiator_ip = *sip;
            pf->service_disco_state = APPID_DISCO_STATE_STATEFUL;
            pf->scan_flags |= SCAN_HOST_PORT_FLAG;
        }
        else
        {
            snort_free(tmp_td);
            goto inprocess;   /* Assume that the flow already exists
                                 as in a retransmit situation */
        }
        break;
    case TFTP_STATE_TRANSFER:
        if ((mode=tftp_verify_header(data, size, &block)) < 0)
        {
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s TFTP failed to verify\n", appidDebug->get_debug_session());
            goto fail;
        }
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s TFTP mode %d and block %u\n", appidDebug->get_debug_session(),
                mode, (unsigned)block);
        if (mode == TFTP_STATE_ACK)
        {
            if (block != 0)
            {
                td->state = TFTP_STATE_ERROR;
                goto fail;
            }
            td->last = 0;
            td->block = 0;
            td->state = TFTP_STATE_ACK;
        }
        else if (mode == TFTP_STATE_DATA)
        {
            if (block != 1)
            {
                td->state = TFTP_STATE_ERROR;
                goto fail;
            }
            td->block = 1;
            td->state = TFTP_STATE_DATA;
        }
        else if (mode == TFTP_STATE_ERROR)
            break;
        else
        {
            td->state = TFTP_STATE_ERROR;
            goto fail;
        }
        break;
    case TFTP_STATE_ACK:
        if ((mode=tftp_verify_header(data, size, &block)) < 0)
        {
            if (args.dir == APP_ID_FROM_RESPONDER)
                goto fail;
            else
            {
                if (appidDebug->is_active())
                    LogMessage("AppIdDbg %s TFTP failed to verify\n", appidDebug->get_debug_session());
                goto bail;
            }
        }
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s TFTP mode %d\n", appidDebug->get_debug_session(), mode);
        if (mode == TFTP_STATE_ERROR)
        {
            td->state = TFTP_STATE_TRANSFER;
            break;
        }
        if (args.dir == APP_ID_FROM_INITIATOR && mode != TFTP_STATE_DATA)
        {
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s TFTP bad mode\n", appidDebug->get_debug_session());
            goto bail;
        }
        if (args.dir == APP_ID_FROM_RESPONDER && mode != TFTP_STATE_ACK)
            goto fail;
        if (args.dir == APP_ID_FROM_INITIATOR)
        {
            if (size < sizeof(ServiceTFTPHeader) + TFTP_MAX_PACKET_SIZE)
                td->last = 1;
            break;
        }
        if (block == (uint16_t)(td->block + 1))
            td->block++;
        else if (block != td->block)
            goto fail;
        td->count++;
        if (td->count >= TFTP_COUNT_THRESHOLD)
            goto success;
        if (td->last)
            td->state = TFTP_STATE_TRANSFER;
        break;
    case TFTP_STATE_DATA:
        if ((mode=tftp_verify_header(data, size, &block)) < 0)
            goto fail;
        if (mode == TFTP_STATE_ERROR)
            td->state = TFTP_STATE_TRANSFER;
        else if (mode != TFTP_STATE_DATA)
            goto fail;
        if (block == (uint16_t)(td->block + 1))
            td->block++;
        else if (block != td->block)
            goto fail;
        td->count++;
        if (td->count >= TFTP_COUNT_THRESHOLD)
            goto success;
        if (size < sizeof(ServiceTFTPHeader) + TFTP_MAX_PACKET_SIZE)
            td->state = TFTP_STATE_TRANSFER;
        break;
    case TFTP_STATE_ERROR:
    default:
        goto fail;
    }

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    if (appidDebug->is_active())
        LogMessage("AppIdDbg %s TFTP success\n", appidDebug->get_debug_session());
    return add_service(args.asd, args.pkt, args.dir, APP_ID_TFTP);

bail:
    incompatible_data(args.asd, args.pkt, args.dir);
    return APPID_NOT_COMPATIBLE;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

