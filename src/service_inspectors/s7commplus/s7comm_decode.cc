//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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

// s7comm_decode.cc author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

/*
 * This is the encapsulation of S7comm/S7comm-plus protocol:
 *   Ethernet | IP | TCP (server port 102) | TPKT | COTP | S7comm or S7comm-plus
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "s7comm_decode.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "protocols/packet.h"

#include "s7comm.h"
#include "s7comm_module.h"

#pragma pack(1)
/* TPKT header */
struct TpktHeader
{
    uint8_t version;
    uint8_t reserved;
    uint16_t length;
};

/* COTP header */
struct CotpHeader
{
    uint8_t length;
    uint8_t pdu_type;
    uint8_t tpdu_num;
};

struct S7commplusHeader
{
    uint8_t proto_id;
    uint8_t proto_version;
    uint16_t data_len;
};

struct S7commplusDataHeader
{
    uint8_t opcode;
    uint16_t reserved_1;
    uint16_t function;
    uint16_t reserved_2;
};
#pragma pack()

using namespace snort;

static bool S7commPlusProtocolDecode(S7commplusSessionData* session, Packet* p)
{
    const S7commplusHeader* s7commplus_header;
    const S7commplusDataHeader* s7commplus_data_header;
    int offset;

    if ( p->dsize < (sizeof(TpktHeader) + sizeof(CotpHeader) + \
        sizeof(S7commplusHeader) + sizeof(S7commplusDataHeader)) )
        return false;

    offset = sizeof(TpktHeader) + sizeof(CotpHeader);

    s7commplus_header = (const S7commplusHeader*)(p->data + offset);
    /* Set the session data. Swap byte order for 16-bit fields. */
    session->s7commplus_proto_id = s7commplus_header->proto_id;
    session->s7commplus_proto_version = s7commplus_header->proto_version;
    session->s7commplus_data_len = ntohs(s7commplus_header->data_len);

    if (s7commplus_header->proto_version <= HDR_VERSION_TWO)
    {
        /* V1 or V2 header packets */
        offset += sizeof(S7commplusHeader);
    }
    else
    {
        /* 33 byte Integrity part for V3 header packets */
        offset += sizeof(S7commplusHeader) + INTEGRITY_PART_LEN ;
    }

    s7commplus_data_header = (const S7commplusDataHeader*)(p->data + offset);
    /* Set the session data. Swap byte order for 16-bit fields. */
    session->s7commplus_opcode = s7commplus_data_header->opcode;
    session->s7commplus_reserved_1 = ntohs(s7commplus_data_header->reserved_1);
    session->s7commplus_function = ntohs(s7commplus_data_header->function);
    session->s7commplus_reserved_2 = ntohs(s7commplus_data_header->reserved_2);

    return true;
}

bool S7commplusDecode(Packet* p, S7commplusFlowData* mfd)
{
    const TpktHeader* tpkt_header;
    const CotpHeader* cotp_header;
    const S7commplusHeader* s7commplus_header;
    uint16_t tpkt_length;

    if (p->dsize < TPKT_MIN_HDR_LEN)
        return false;

    tpkt_header = (const TpktHeader*)p->data;
    cotp_header = (const CotpHeader*)(p->data + sizeof(TpktHeader));
    tpkt_length = ntohs(tpkt_header->length);

    /* It might be a TPKT/COTP packet for other purpose, e.g. connect */
    if (cotp_header->length != COTP_HDR_LEN_FOR_S7COMMPLUS||
        cotp_header->pdu_type != COTP_HDR_PDU_TYPE_DATA)
        return true;
    /* It might be COTP fragment data */
    if (tpkt_length == TPKT_MIN_HDR_LEN)
    {
        mfd->reset();
        return true;
    }

    s7commplus_header = (const S7commplusHeader*)(p->data +
        sizeof(TpktHeader) + sizeof(CotpHeader));

    if (s7commplus_header->proto_id == S7COMMPLUS_PROTOCOL_ID)
    {
        return (S7commPlusProtocolDecode(&mfd->ssn_data, p));
    }
    else
    {
        DetectionEngine::queue_event(GID_S7COMMPLUS, S7COMMPLUS_BAD_PROTO_ID);
        return false;
    }
}

