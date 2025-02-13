//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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
// dce_curses.cc author Maya Dagon <mdagon@cisco.com>
// Refactored from curses.cc

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_curse.h"
#include "curse_book.h"

enum DceRpcPduType
{
    DCERPC_PDU_TYPE__REQUEST = 0,
    DCERPC_PDU_TYPE__PING,
    DCERPC_PDU_TYPE__RESPONSE,
    DCERPC_PDU_TYPE__FAULT,
    DCERPC_PDU_TYPE__WORKING,
    DCERPC_PDU_TYPE__NOCALL,
    DCERPC_PDU_TYPE__REJECT,
    DCERPC_PDU_TYPE__ACK,
    DCERPC_PDU_TYPE__CL_CANCEL,
    DCERPC_PDU_TYPE__FACK,
    DCERPC_PDU_TYPE__CANCEL_ACK,
    DCERPC_PDU_TYPE__BIND,
    DCERPC_PDU_TYPE__BIND_ACK,
    DCERPC_PDU_TYPE__BIND_NACK,
    DCERPC_PDU_TYPE__ALTER_CONTEXT,
    DCERPC_PDU_TYPE__ALTER_CONTEXT_RESP,
    DCERPC_PDU_TYPE__AUTH3,
    DCERPC_PDU_TYPE__SHUTDOWN,
    DCERPC_PDU_TYPE__CO_CANCEL,
    DCERPC_PDU_TYPE__ORPHANED,
    DCERPC_PDU_TYPE__MICROSOFT_PROPRIETARY_OUTLOOK2003_RPC_OVER_HTTP,
    DCERPC_PDU_TYPE__MAX
};

/* Version 4 is for Connectionless
 * Version 5 is for Connection oriented */
enum DceRpcProtoMajorVers
{
    DCERPC_PROTO_MAJOR_VERS__4 = 4,
    DCERPC_PROTO_MAJOR_VERS__5 = 5
};

enum DceRpcProtoMinorVers
{
    DCERPC_PROTO_MINOR_VERS__0 = 0,
    DCERPC_PROTO_MINOR_VERS__1 = 1
};

bool CurseBook::dce_udp_curse(const uint8_t* data, unsigned len, CurseTracker*)
{
    const uint8_t dcerpc_cl_hdr_len = 80;
    const uint8_t cl_len_offset = 74;

    if ( len >= dcerpc_cl_hdr_len )
    {
        uint8_t version = data[0];
        uint8_t pdu_type = data[1];
        bool little_endian = ((data[4] & 0x10) >> 4) ? true : false;
        uint16_t cl_len;

#ifdef WORDS_BIGENDIAN
        if ( !little_endian )
#else
        if ( little_endian )
#endif  /* WORDS_BIGENDIAN */
            cl_len = (data[cl_len_offset+1] << 8) | data[cl_len_offset];
        else
            cl_len = (data[cl_len_offset] << 8) | data[cl_len_offset+1];

        if ( (version == DCERPC_PROTO_MAJOR_VERS__4) and
            ((pdu_type == DCERPC_PDU_TYPE__REQUEST) or
            (pdu_type == DCERPC_PDU_TYPE__RESPONSE) or
            (pdu_type == DCERPC_PDU_TYPE__FAULT) or
            (pdu_type == DCERPC_PDU_TYPE__REJECT) or
            (pdu_type == DCERPC_PDU_TYPE__FACK)) and
            ((cl_len != 0) and
            (cl_len + (unsigned)dcerpc_cl_hdr_len) <= len) )
            return true;
    }

    return false;
}

bool CurseBook::dce_tcp_curse(const uint8_t* data, unsigned len, CurseTracker* tracker)
{
    const uint8_t dce_rpc_co_hdr_len = 16;
    DceTracker& dce = tracker->dce;

    uint32_t n = 0;
    while ( n < len )
    {
        switch ( dce.state )
        {
        case DCE_STATE__0: // check major version
            if ( data[n] != DCERPC_PROTO_MAJOR_VERS__5 )
            {
                // go to bad state
                dce.state = DCE_STATE__10;

                return false;
            }

            dce.state = (DCE_State)((int)dce.state + 1);
            break;

        case DCE_STATE__1: // check minor version
            if ( data[n] != DCERPC_PROTO_MINOR_VERS__0 )
            {
                // go to bad state
                dce.state = DCE_STATE__10;

                return false;
            }

            dce.state = (DCE_State)((int)dce.state + 1);
            break;

        case DCE_STATE__2: // pdu_type
        {
            uint8_t pdu_type = data[n];

            if ( (pdu_type != DCERPC_PDU_TYPE__BIND) and
                (pdu_type != DCERPC_PDU_TYPE__BIND_ACK) )
            {
                // go to bad state
                dce.state = DCE_STATE__10;

                return false;
            }

            dce.state = (DCE_State)((int)dce.state + 1);
            break;
        }

        case DCE_STATE__4: //little endian
            dce.helper = (data[n] & 0x10) << 20;
            dce.state = (DCE_State)((int)dce.state + 1);
            break;
        case DCE_STATE__8:
            dce.helper |= data[n];
            dce.state = (DCE_State)((int)dce.state + 1);
            break;
        case DCE_STATE__9:
#ifdef WORDS_BIGENDIAN
            if ( !(dce.helper >> 24) )
#else
            if ( dce.helper >> 24 )
#endif  /* WORDS_BIGENDIAN */
                dce.helper = (data[n] << 8) | (dce.helper & 0XFF);
            else
            {
                dce.helper <<=8;
                dce.helper |= data[n];
            }

            if ( dce.helper >= dce_rpc_co_hdr_len )
                return true;

            dce.state = DCE_STATE__10;
            break;

        case DCE_STATE__10:
            // no match
            return false;
        default:
            dce.state = (DCE_State)((int)dce.state + 1);
            break;
        }

        n++;
    }

    return false;
}

bool CurseBook::dce_smb_curse(const uint8_t* data, unsigned len, CurseTracker* tracker)
{
    const uint32_t dce_smb_id = 0xff534d42;  /* \xffSMB */
    const uint32_t dce_smb2_id = 0xfe534d42;  /* \xfeSMB */
    const uint8_t session_request = 0x81, session_response = 0x82, session_message = 0x00;
    DceTracker& dce = tracker->dce;

    uint32_t n = 0;
    while ( n < len )
    {
        switch ( dce.state )
        {
        case DCE_STATE__0:
            if ( data[n] == session_message )
            {
                dce.state = (DCE_State)((int)dce.state + 2);
                break;
            }

            if ( data[n] == session_request or data[n] == session_response )
            {
                dce.state = (DCE_State)((int)dce.state + 1);

                return false;
            }

            dce.state = DCE_STATE__9;

            return false;

        case DCE_STATE__1:
            if ( data[n] == session_message )
            {
                dce.state = (DCE_State)((int)dce.state + 1);
                break;
            }

            dce.state = DCE_STATE__9;

            return false;

        case DCE_STATE__5:
            dce.helper = data[n];
            dce.state = (DCE_State)((int)dce.state + 1);
            break;

        case DCE_STATE__6:
        case DCE_STATE__7:
            dce.helper <<= 8;
            dce.helper |= data[n];
            dce.state = (DCE_State)((int)dce.state + 1);
            break;

        case DCE_STATE__8:
            dce.helper <<= 8;
            dce.helper |= data[n];

            if ( (dce.helper == dce_smb_id) or (dce.helper == dce_smb2_id) )
                return true;

            dce.state = (DCE_State)((int)dce.state + 1);
            break;

        case DCE_STATE__9:
            // no match
            return false;

        default:
            dce.state = (DCE_State)((int)dce.state + 1);
            break;
        }

        n++;
    }

    return false;
}
