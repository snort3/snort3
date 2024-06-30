//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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


#pragma pack()

using namespace snort;

static bool S7commProtocolDecode(S7commSessionData* session, Packet* p)
{
    const S7commHeader* s7comm_header;
    int offset;

    if (p->dsize < (sizeof(TpktHeader) + sizeof(CotpHeader) + sizeof(S7commHeader) - 2)) // -2 for optional fields
        return false;

    offset = sizeof(TpktHeader) + sizeof(CotpHeader);

    s7comm_header = (const S7commHeader*)(p->data + offset);
    /* Set the session data. Swap byte order for 16-bit fields. */
    session->s7comm_proto_id = s7comm_header->proto_id;
    session->s7comm_message_type = s7comm_header->message_type;
    session->s7comm_reserved = ntohs(s7comm_header->reserved);
    session->s7comm_pdu_reference = ntohs(s7comm_header->pdu_reference);
    session->s7comm_parameter_length = ntohs(s7comm_header->parameter_length);
    session->s7comm_data_length = ntohs(s7comm_header->data_length);

    offset += sizeof(S7commHeader) - 2; // -2 for optional fields


    //In case the its a ack_Data message
    if (s7comm_header->message_type == ACK_DATA && p->dsize >= (offset + 2)) {
        /* Set the session data. */
        session->s7comm_error_class = s7comm_header->error_class;
        session->s7comm_error_code = s7comm_header->error_code;
        offset +=2;
    }


    if ((s7comm_header->message_type == ACK_DATA || s7comm_header->message_type == JOB_REQUEST) && p->dsize >= (offset + 2)) {
        const S7commParameterHeader* s7comm_param_header;
        s7comm_param_header=(const S7commParameterHeader*)(p->data + offset);
        session->s7comm_function_code = s7comm_param_header->function_code;
        if (session->s7comm_function_code == 0x04 or session->s7comm_function_code == 0x05){ // the message has either read var or write var function
            session->is_read_write_var= true;
        }
        session->s7comm_item_count = s7comm_param_header->item_count;
        offset +=2;
    }

    return true;
}

bool S7commDecode(Packet* p, S7commFlowData* mfd)
{
    const TpktHeader* tpkt_header;
    const CotpHeader* cotp_header;
    const S7commHeader* s7comm_header;
    uint16_t tpkt_length;

    if (p->dsize < TPKT_MIN_HDR_LEN)
        return false;

    tpkt_header = (const TpktHeader*)p->data;
    cotp_header = (const CotpHeader*)(p->data + sizeof(TpktHeader));
    tpkt_length = ntohs(tpkt_header->length);

    /* It might be a TPKT/COTP packet for other purpose, e.g. connect */
    if (cotp_header->length != COTP_HDR_LEN_FOR_S7COMM)
        return true;
    /* It might be COTP fragment data */
    if (tpkt_length == TPKT_MIN_HDR_LEN)
    {
        mfd->reset();
        return true;
    }

    s7comm_header = (const S7commHeader*)(p->data +
        sizeof(TpktHeader) + sizeof(CotpHeader));

    if (s7comm_header->proto_id == S7COMM_PROTOCOL_ID)
    {
        return (S7commProtocolDecode(&mfd->ssn_data, p));
    }
    else
    {
        DetectionEngine::queue_event(GID_S7COMM, S7COMM_BAD_PROTO_ID);
        return false;
    }
}
