//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
// curses.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "curses.h"

using namespace std;

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

static bool dce_udp_curse(const uint8_t* data, unsigned len, CurseTracker*)
{
    const uint8_t dcerpc_cl_hdr_len = 80;
    const uint8_t cl_len_offset = 74;

    if (len >= dcerpc_cl_hdr_len)
    {
        uint8_t version = data[0];
        uint8_t pdu_type = data[1];
        bool little_endian = ((data[4] & 0x10) >> 4) ? true : false;
        uint16_t cl_len;

#ifdef WORDS_BIGENDIAN
        if (!little_endian)
#else
        if (little_endian)
#endif  /* WORDS_BIGENDIAN */
            cl_len = (data[cl_len_offset+1] << 8) | data[cl_len_offset];
        else
            cl_len = (data[cl_len_offset] << 8) | data[cl_len_offset+1];

        if ((version == DCERPC_PROTO_MAJOR_VERS__4) &&
            ((pdu_type == DCERPC_PDU_TYPE__REQUEST) ||
            (pdu_type == DCERPC_PDU_TYPE__RESPONSE) ||
            (pdu_type == DCERPC_PDU_TYPE__FAULT) ||
            (pdu_type == DCERPC_PDU_TYPE__REJECT) ||
            (pdu_type == DCERPC_PDU_TYPE__FACK)) &&
            ((cl_len != 0) &&
            (cl_len + (unsigned)dcerpc_cl_hdr_len) <= len))
            return true;
    }

    return false;
}

static bool dce_tcp_curse(const uint8_t* data, unsigned len, CurseTracker* tracker)
{
    const uint8_t dce_rpc_co_hdr_len = 16;

    uint32_t n = 0;
    while (n < len)
    {
        switch (tracker->state)
        {
        case STATE_0: // check major version
        {
            if (data[n] != DCERPC_PROTO_MAJOR_VERS__5)
            {
                // go to bad state
                tracker->state = STATE_10;
                return false;
            }
            tracker->state = (DCE_States)((int)tracker->state + 1);
            break;
        }

        case STATE_1: // check minor version
        {
            if (data[n] != DCERPC_PROTO_MINOR_VERS__0)
            {
                // go to bad state
                tracker->state = STATE_10;
                return false;
            }
            tracker->state = (DCE_States)((int)tracker->state + 1);
            break;
        }

        case STATE_2: // pdu_type
        {
            uint8_t pdu_type = data[n];
            if ((pdu_type != DCERPC_PDU_TYPE__BIND) &&
                (pdu_type != DCERPC_PDU_TYPE__BIND_ACK))
            {
                // go to bad state
                tracker->state = STATE_10;
                return false;
            }
            tracker->state = (DCE_States)((int)tracker->state + 1);
            break;
        }

        case STATE_4: //little endian
            tracker->helper = (data[n] & 0x10) << 20;
            tracker->state = (DCE_States)((int)tracker->state + 1);
            break;
        case STATE_8:
            tracker->helper |= data[n];
            tracker->state = (DCE_States)((int)tracker->state + 1);
            break;
        case STATE_9:
        {
#ifdef WORDS_BIGENDIAN
            if (!(tracker->helper >> 24))
#else
            if (tracker->helper >> 24)
#endif  /* WORDS_BIGENDIAN */
                tracker->helper = (data[n] << 8) | (tracker->helper & 0XFF);
            else
            {
                tracker->helper <<=8;
                tracker->helper |= data[n];
            }

            if (tracker->helper >= dce_rpc_co_hdr_len)
                return true;

            tracker->state = STATE_10;
            break;
        }

        case STATE_10:
            // no match
            return false;
        default:
            tracker->state = (DCE_States)((int)tracker->state + 1);
            break;
        }
        n++;
    }

    return false;
}

static bool dce_smb_curse(const uint8_t* data, unsigned len, CurseTracker* tracker)
{
    const uint32_t dce_smb_id = 0xff534d42;  /* \xffSMB */
    const uint32_t dce_smb2_id = 0xfe534d42;  /* \xfeSMB */
    const uint8_t nbss_type_message = 0;

    uint32_t n = 0;
    while (n < len)
    {
        switch (tracker->state)
        {
        case STATE_0:
        {
            if (data[n] != nbss_type_message)
            {
                tracker->state = STATE_8;
                return false;
            }
            tracker->state = (DCE_States)((int)tracker->state + 1);
            break;
        }
        case STATE_4:
        {
            tracker->helper = data[n];
            tracker->state = (DCE_States)((int)tracker->state + 1);
            break;
        }
        case STATE_5:
        case STATE_6:
        {
            tracker->helper <<= 8;
            tracker->helper |= data[n];
            tracker->state = (DCE_States)((int)tracker->state + 1);
            break;
        }

        case STATE_7:
        {
            tracker->helper <<= 8;
            tracker->helper |= data[n];
            if ((tracker->helper == dce_smb_id) || (tracker->helper == dce_smb2_id))
                return true;

            tracker->state = (DCE_States)((int)tracker->state + 1);
            break;
        }

        case STATE_8:
            // no match
            return false;

        default:
            tracker->state = (DCE_States)((int)tracker->state + 1);
            break;
        }
        n++;
    }

    return false;
}

// map between service and curse details
static vector<CurseDetails> curse_map
{
    // name      service        alg            is_tcp
    { "dce_udp", "dcerpc",      dce_udp_curse, false },
    { "dce_tcp", "dcerpc",      dce_tcp_curse, true  },
    { "dce_smb", "netbios-ssn", dce_smb_curse, true  },
};

bool CurseBook::add_curse(const char* key)
{
    for (const CurseDetails& curse : curse_map)
    {
        if (curse.name == key)
        {
            if (curse.is_tcp)
                tcp_curses.push_back(&curse);
            else
                non_tcp_curses.push_back(&curse);
            return true;
        }
    }
    return false;
}

const vector<const CurseDetails*>& CurseBook::get_curses(bool tcp) const
{
    if (tcp)
        return tcp_curses;
    return non_tcp_curses;
}

