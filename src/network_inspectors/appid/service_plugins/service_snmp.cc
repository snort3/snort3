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

// service_snmp.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_snmp.h"

#include "log/messages.h"
#include "protocols/packet.h"

#include "app_info_table.h"
#include "appid_debug.h"
#include "appid_inspector.h"

#define SNMP_PORT   161

#define SNMP_VERSION_1  0
#define SNMP_VERSION_2c 1
#define SNMP_VERSION_2u 2
#define SNMP_VERSION_3  3

#define SNMP_VENDOR_STR     "SNMP"
#define SNMP_VERSION_STR_1  "v1"
#define SNMP_VERSION_STR_2c "v2c"
#define SNMP_VERSION_STR_2u "v2u"
#define SNMP_VERSION_STR_3  "v3"

enum SNMPState
{
    SNMP_STATE_CONNECTION,
    SNMP_STATE_RESPONSE,
    SNMP_STATE_REQUEST,
    SNMP_STATE_R_RESPONSE,
    SNMP_STATE_R_REQUEST,
    SNMP_STATE_ERROR
};

struct ServiceSNMPData
{
    SNMPState state;
};

enum SNMPPDUType
{
    SNMP_PDU_GET_REQUEST,
    SNMP_PDU_GET_NEXT_REQUEST,
    SNMP_PDU_GET_RESPONSE,
    SNMP_PDU_SET_REQUEST,
    SNMP_PDU_TRAP,
    SNMP_PDU_GET_BULK_REQUEST,
    SNMP_PDU_INFORM_REQUEST,
    SNMP_PDU_TRAPV2
};

#pragma pack(1)

struct ServiceSNMPHeader
{
    uint16_t opcode;
    union
    {
        uint16_t block;
        uint16_t errorcode;
    } d;
};

#pragma pack()

static const uint8_t SNMP_PATTERN_2[] = { 0x02, 0x01, 0x00, 0x04 };
static const uint8_t SNMP_PATTERN_3[] = { 0x02, 0x01, 0x01, 0x04 };
static const uint8_t SNMP_PATTERN_4[] = { 0x02, 0x01, 0x03, 0x30 };

SnmpServiceDetector::SnmpServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "snmp";
    proto = IpProtocol::UDP;
    detectorType = DETECTOR_TYPE_DECODER;

    udp_patterns =
    {
        { SNMP_PATTERN_2, sizeof(SNMP_PATTERN_2), 2, 0, 0 },
        { SNMP_PATTERN_3, sizeof(SNMP_PATTERN_3), 2, 0, 0 },
        { SNMP_PATTERN_4, sizeof(SNMP_PATTERN_4), 2, 0, 0 },
        { SNMP_PATTERN_2, sizeof(SNMP_PATTERN_2), 3, 0, 0 },
        { SNMP_PATTERN_3, sizeof(SNMP_PATTERN_3), 3, 0, 0 },
        { SNMP_PATTERN_4, sizeof(SNMP_PATTERN_4), 3, 0, 0 },
        { SNMP_PATTERN_2, sizeof(SNMP_PATTERN_2), 4, 0, 0 },
        { SNMP_PATTERN_3, sizeof(SNMP_PATTERN_3), 4, 0, 0 },
        { SNMP_PATTERN_4, sizeof(SNMP_PATTERN_4), 4, 0, 0 }
    };

    appid_registry =
    {
        { APP_ID_SNMP, APPINFO_FLAG_SERVICE_UDP_REVERSED|APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { SNMP_PORT, IpProtocol::TCP, false },
        { SNMP_PORT, IpProtocol::UDP, false },
        { 162, IpProtocol::UDP, false }
    };

    handler->register_detector(name, this, proto);
}


static int snmp_ans1_length(const uint8_t** const data,
    const uint8_t* const end,
    uint32_t* const length)
{
    *length = 0;
    if (**data == 0x80)
        return -1;
    if (**data < 0x80)
    {
        *length = (uint32_t)**data;
        (*data)++;
    }
    else
    {
        int cnt = (**data) & 0x7F;
        (*data)++;
        for (; *data<end && cnt; cnt--, (*data)++)
        {
            *length <<= 8;
            *length |= **data;
        }
        if (cnt)
            return -1;
    }
    return 0;
}

static int snmp_verify_packet(const uint8_t** const data,
    const uint8_t* const end, uint8_t* const pdu,
    uint8_t* version_ret)
{
    uint32_t overall_length;
    uint32_t community_length;
    uint32_t global_length;
    uint32_t length;
    uint8_t version;
    uint8_t cls;
    const uint8_t* p;

    if (**data != 0x30)
        return -1;
    (*data)++;
    if (*data >= end)
        return -1;
    if (snmp_ans1_length(data, end, &overall_length))
        return -1;
    if (overall_length < 3 || (int)overall_length > end-(*data))
        return -1;
    if (**data != 0x02)
        return -1;
    (*data)++;
    if (**data != 0x01)
        return -1;
    (*data)++;
    version = **data;
    (*data)++;
    overall_length -= 3;
    if (!overall_length)
        return -1;
    switch (version)
    {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
        if (**data != 0x04)
            return -1;
        (*data)++;
        overall_length--;
        if (!overall_length)
            return -1;
        p = *data;
        if (snmp_ans1_length(data, *data+overall_length, &community_length))
            return -1;
        overall_length -= *data - p;
        if (overall_length < community_length)
            return -1;
        for (;
            community_length;
            (*data)++, community_length--, overall_length--)
        {
            if (!isprint(**data))
                return -1;
        }
        break;
    case SNMP_VERSION_2u:
        if (**data != 0x04)
            return -1;
        (*data)++;
        overall_length--;
        if (!overall_length)
            return -1;
        p = *data;
        if (snmp_ans1_length(data, *data+overall_length, &community_length))
            return -1;
        overall_length -= *data - p;
        if (!community_length || overall_length < community_length)
            return -1;
        if (**data != 1)
            return -1;
        *data += community_length;
        overall_length -= community_length;
        break;
    case SNMP_VERSION_3:
        /* Global header */
        if (**data != 0x30)
            return -1;
        (*data)++;
        overall_length--;
        if (!overall_length)
            return -1;
        p = *data;
        if (snmp_ans1_length(data, *data+overall_length, &global_length))
            return -1;
        overall_length -= *data - p;
        if (global_length < 2 || overall_length < global_length)
            return -1;

        /* Message id */
        if (**data != 0x02)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (global_length < length || length > sizeof(uint32_t))
            return -1;
        *data += length;
        global_length -= length;
        overall_length -= length;

        /* Max message size */
        if (global_length < 2)
            return -1;
        if (**data != 0x02)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (global_length < length || length > sizeof(uint32_t))
            return -1;
        *data += length;
        global_length -= length;
        overall_length -= length;

        /* Message flags */
        if (global_length < 2)
            return -1;
        if (**data != 0x04)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (length != 1 || global_length < length)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;

        /* Security model */
        if (global_length < 2)
            return -1;
        if (**data != 0x02)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (global_length < length || length > sizeof(uint32_t))
            return -1;
        *data += length;
        global_length -= length;
        overall_length -= length;

        /* Security Parameters */
        if (overall_length < 2)
            return -1;
        if (**data != 0x04)
            return -1;
        (*data)++;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+overall_length, &global_length))
            return -1;
        overall_length -= *data - p;
        if (overall_length < global_length)
            return -1;
        *data += global_length;
        overall_length -= global_length;

        /* Message */
        if (overall_length < 2)
            return -1;
        if (**data != 0x30)
            return -1;
        (*data)++;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+overall_length, &global_length))
            return -1;
        overall_length -= *data - p;
        if (overall_length < global_length)
            return -1;

        /* Context Engine ID */
        if (global_length < 2)
            return -1;
        if (**data != 0x04)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (global_length < length)
            return -1;
        *data += length;
        global_length -= length;
        overall_length -= length;

        /* Context Name */
        if (global_length < 2)
            return -1;
        if (**data != 0x04)
            return -1;
        (*data)++;
        global_length--;
        overall_length--;
        p = *data;
        if (snmp_ans1_length(data, *data+global_length, &length))
            return -1;
        global_length -= *data - p;
        overall_length -= *data - p;
        if (global_length < length)
            return -1;
        *data += length;
        global_length -= length;
        overall_length -= length;
        break;
    default:
        return -1;
    }
    if (!overall_length)
        return -1;
    cls = (**data) & 0xC0;
    if (cls != 0x80 && cls != 0x40)
        return -1;
    *pdu = (**data) & 0x1F;
    *version_ret = version;
    return 0;
}

int SnmpServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceSNMPData* sd = nullptr;
    ServiceSNMPData* tmp_sd = nullptr;
    uint8_t pdu = 0;
    uint8_t version = 0;
    const char* version_str = nullptr;
    const uint8_t* data = args.data;
    uint16_t size = args.size;
    //FIXIT-M - Avoid thread locals
    static THREAD_LOCAL SnortProtocolId snmp_snort_protocol_id = UNKNOWN_PROTOCOL_ID;

    if (!size)
        goto inprocess;

    sd = (ServiceSNMPData*)data_get(args.asd);
    if (!sd)
    {
        sd = (ServiceSNMPData*)snort_calloc(sizeof(ServiceSNMPData));
        data_add(args.asd, sd, &snort_free);
        sd->state = SNMP_STATE_CONNECTION;
    }

    if (snmp_verify_packet(&data, data+size, &pdu, &version))
    {
        if (appidDebug->is_active())
            snort::LogMessage("AppIdDbg %s SNMP payload verify failed\n", appidDebug->get_debug_session());
        if (args.asd.get_session_flags(APPID_SESSION_UDP_REVERSED))
        {
            if (args.dir == APP_ID_FROM_RESPONDER)
                goto bail;
            else
                goto fail;
        }
        else
        {
            if (args.dir == APP_ID_FROM_RESPONDER)
                goto fail;
            else
                goto bail;
        }
    }

    if (appidDebug->is_active())
        snort::LogMessage("AppIdDbg %s SNMP state %d\n", appidDebug->get_debug_session(), sd->state);

    switch (sd->state)
    {
    case SNMP_STATE_CONNECTION:
    {
        if (pdu != SNMP_PDU_GET_RESPONSE && args.dir == APP_ID_FROM_RESPONDER)
        {
            sd->state = SNMP_STATE_R_RESPONSE;
            args.asd.set_session_flags(APPID_SESSION_UDP_REVERSED);
            break;
        }
        if (pdu == SNMP_PDU_GET_RESPONSE && args.dir == APP_ID_FROM_INITIATOR)
        {
            sd->state = SNMP_STATE_R_REQUEST;
            args.asd.set_session_flags(APPID_SESSION_UDP_REVERSED);
            break;
        }

        if (args.dir == APP_ID_FROM_RESPONDER)
        {
            sd->state = SNMP_STATE_REQUEST;
            break;
        }

        if (pdu == SNMP_PDU_TRAP || pdu == SNMP_PDU_TRAPV2)
        {
            args.asd.set_session_flags(APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_NOT_A_SERVICE);
            args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
            args.asd.service.set_id(APP_ID_SNMP);
            break;
        }
        sd->state = SNMP_STATE_RESPONSE;

        /*adding expected connection in case the server doesn't send from 161*/
        if(snmp_snort_protocol_id == UNKNOWN_PROTOCOL_ID)
            snmp_snort_protocol_id = snort::SnortConfig::get_conf()->proto_ref->find("snmp");

        const snort::SfIp* dip = args.pkt->ptrs.ip_api.get_dst();
        const snort::SfIp* sip = args.pkt->ptrs.ip_api.get_src();
        AppIdSession* pf = AppIdSession::create_future_session(args.pkt, dip, 0, sip,
            args.pkt->ptrs.sp, args.asd.protocol, snmp_snort_protocol_id, 0, handler->get_inspector());
        if (pf)
        {
            tmp_sd = (ServiceSNMPData*)snort_calloc(sizeof(ServiceSNMPData));
            tmp_sd->state = SNMP_STATE_RESPONSE;
            data_add(*pf, tmp_sd, &snort_free);
            if (pf->add_flow_data_id(args.pkt->ptrs.dp, this))
            {
                pf->set_session_flags(APPID_SESSION_SERVICE_DETECTED);
                pf->clear_session_flags(APPID_SESSION_CONTINUE);
                tmp_sd->state = SNMP_STATE_ERROR;
                return APPID_ENULL;
            }
            initialize_expected_session(args.asd, *pf, APPID_SESSION_EXPECTED_EVALUATE, APP_ID_APPID_SESSION_DIRECTION_MAX);
            pf->service_disco_state = APPID_DISCO_STATE_STATEFUL;
            pf->scan_flags |= SCAN_HOST_PORT_FLAG;
            pf->common.initiator_ip = *sip;
        }
    }
    break;
    case SNMP_STATE_RESPONSE:
        if (pdu == SNMP_PDU_GET_RESPONSE)
        {
            if (args.dir == APP_ID_FROM_RESPONDER)
                goto success;
            goto fail;
        }
        if (args.dir == APP_ID_FROM_RESPONDER)
            goto fail;
        break;
    case SNMP_STATE_REQUEST:
        if (pdu != SNMP_PDU_GET_RESPONSE)
        {
            if (args.dir == APP_ID_FROM_INITIATOR)
                goto success;
            goto fail;
        }
        if (args.dir == APP_ID_FROM_INITIATOR)
            goto fail;
        break;
    case SNMP_STATE_R_RESPONSE:
        if (pdu == SNMP_PDU_GET_RESPONSE)
        {
            if (args.dir == APP_ID_FROM_INITIATOR)
                goto success;
            goto fail;
        }
        if (args.dir == APP_ID_FROM_INITIATOR)
            goto fail;
        break;
    case SNMP_STATE_R_REQUEST:
        if (pdu != SNMP_PDU_GET_RESPONSE)
        {
            if (args.dir == APP_ID_FROM_RESPONDER)
                goto success;
            goto fail;
        }
        if (args.dir == APP_ID_FROM_RESPONDER)
            goto fail;
        break;
    default:
        if (args.dir == APP_ID_FROM_RESPONDER)
            goto fail;
        else
            goto bail;
    }

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    switch (version)
    {
    case SNMP_VERSION_1:
        version_str = SNMP_VERSION_STR_1;
        break;
    case SNMP_VERSION_2c:
        version_str = SNMP_VERSION_STR_2c;
        break;
    case SNMP_VERSION_2u:
        version_str = SNMP_VERSION_STR_2u;
        break;
    case SNMP_VERSION_3:
        version_str = SNMP_VERSION_STR_3;
        break;
    default:
        version_str = nullptr;
        break;
    }
    return add_service(args.asd, args.pkt, args.dir, APP_ID_SNMP, SNMP_VENDOR_STR, version_str, nullptr);

bail:
    incompatible_data(args.asd, args.pkt, args.dir);
    return APPID_NOT_COMPATIBLE;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

