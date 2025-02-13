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
// s7commplus_curse.cc author Jared Rittle <jared.rittle@cisco.com>
// Moved from curses.cc

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "s7commplus_curse.h"
#include "curse_book.h"

enum S7commplus_Protocol_Identifier
{
    S7COMMPLUS_PROTOCOL_IDENTIFIER__S7COMM     = 0x32,
    S7COMMPLUS_PROTOCOL_IDENTIFIER__S7COMMPLUS = 0x72,
};

enum S7commplus_Pdu_Type
{
    S7COMMPLUS_PDU_TYPE__CONNECT           = 0x01,
    S7COMMPLUS_PDU_TYPE__DATA              = 0x02,
    S7COMMPLUS_PDU_TYPE__DATA2             = 0x03,
    S7COMMPLUS_PDU_TYPE__KEEPALIVE         = 0xFF,
};

enum S7commplus_Opcode
{
    S7COMMPLUS_OPCODE__REQ                 = 0x31,
    S7COMMPLUS_OPCODE__RES                 = 0x32,
    S7COMMPLUS_OPCODE__NOTIFICATION        = 0x33,
    S7COMMPLUS_OPCODE__RES2                = 0x02,
};

enum S7commplus_Function
{
    S7COMMPLUS_FUNCTION__EXPLORE           = 0x04BB,
    S7COMMPLUS_FUNCTION__CREATEOBJECT      = 0x04CA,
    S7COMMPLUS_FUNCTION__DELETEOBJECT      = 0x04D4,
    S7COMMPLUS_FUNCTION__SETVARIABLE       = 0x04F2,
    S7COMMPLUS_FUNCTION__GETLINK           = 0x0524,
    S7COMMPLUS_FUNCTION__SETMULTIVAR       = 0x0542,
    S7COMMPLUS_FUNCTION__GETMULTIVAR       = 0x054C,
    S7COMMPLUS_FUNCTION__BEGINSEQUENCE     = 0x0556,
    S7COMMPLUS_FUNCTION__ENDSEQUENCE       = 0x0560,
    S7COMMPLUS_FUNCTION__INVOKE            = 0x056B,
    S7COMMPLUS_FUNCTION__GETVARSUBSTR      = 0x0586,
};

bool CurseBook::s7commplus_curse(const uint8_t* data, unsigned len, CurseTracker* tracker)
{
    // peg the tracker to s7commplus
    S7commplusTracker& s7commplus = tracker->s7commplus;

    // if the state is set to S7COMMPLUS_STATE__SEARCH it means we most likely
    // have a split pipelined message coming through and will need to
    // reset the state
    if ( s7commplus.state == S7COMMPLUS_STATE__SEARCH )
    {
        s7commplus.state = s7commplus.last_state;
    }

    uint32_t idx = 0;
    while ( idx < len )
    {
        switch ( s7commplus.state )
        {
            case S7COMMPLUS_STATE__TPKT_VER:
            {
                s7commplus.state = S7COMMPLUS_STATE__TPKT_RES;
                break;
            }

            case S7COMMPLUS_STATE__TPKT_RES:
            {
                s7commplus.state = S7COMMPLUS_STATE__TPKT_LEN1;
                break;
            }

            case S7COMMPLUS_STATE__TPKT_LEN1:
            {
                s7commplus.state = S7COMMPLUS_STATE__TPKT_LEN2;
                break;
            }

            case S7COMMPLUS_STATE__TPKT_LEN2:
            {
                s7commplus.state = S7COMMPLUS_STATE__COTP_LEN;
                break;
            }

            case S7COMMPLUS_STATE__COTP_LEN:
            {
                s7commplus.state = S7COMMPLUS_STATE__COTP_PDU;
                break;
            }

            case S7COMMPLUS_STATE__COTP_PDU:
            {
                // 7 6 5 4 3 2 1 0
                // ---------------
                // . . . . x x x x   Destination Reference
                // x x x x . . . .   PDU Type
                const uint32_t S7COMMPLUS_COTP_PDU_DT_DATA = 0x0F;

                if ( data[idx] >> 0x04 != S7COMMPLUS_COTP_PDU_DT_DATA )
                {
                    s7commplus.state = S7COMMPLUS_STATE__NOT_FOUND;
                    break;
                }

                s7commplus.state = S7COMMPLUS_STATE__COTP_TPDU_NUM;
                break;
            }

            case S7COMMPLUS_STATE__COTP_TPDU_NUM:
            {
                s7commplus.state = S7COMMPLUS_STATE__PROTO_ID;
                break;
            }

            case S7COMMPLUS_STATE__PROTO_ID:
            {
                // there are two possible protocol identifiers - 0x32 and 0x72
                // 0x32 indicates the original s7comm protocol
                //   * the original protocol is not supported within the inspector
                //     so just catching and considering it a no match for now
                // 0x72 indicates the s7commplus protocol
                //   * this is the protocol on which the existing inspector focuses
                if ( data[idx] == S7COMMPLUS_PROTOCOL_IDENTIFIER__S7COMMPLUS )
                {
                    s7commplus.state = S7COMMPLUS_STATE__PDU_TYPE;
                }
                else
                {
                    s7commplus.state = S7COMMPLUS_STATE__NOT_FOUND;
                }
                break;
            }

            case S7COMMPLUS_STATE__PDU_TYPE:
            {
                switch ( data[idx] )
                {
                    case S7COMMPLUS_PDU_TYPE__CONNECT:      // fallthrough intentional
                    case S7COMMPLUS_PDU_TYPE__DATA:         // fallthrough intentional
                    case S7COMMPLUS_PDU_TYPE__DATA2:        // fallthrough intentional
                    case S7COMMPLUS_PDU_TYPE__KEEPALIVE:
                    {
                        s7commplus.state = S7COMMPLUS_STATE__DATALENGTH_1;
                        break;
                    }

                    default:
                    {
                        s7commplus.state = S7COMMPLUS_STATE__NOT_FOUND;
                        break;
                    }
                }

                break;
            }

            case S7COMMPLUS_STATE__DATALENGTH_1:
            {
                s7commplus.state = S7COMMPLUS_STATE__DATALENGTH_2;
                break;
            }

            case S7COMMPLUS_STATE__DATALENGTH_2:
            {
                s7commplus.state = S7COMMPLUS_STATE__OPCODE;
                break;
            }

            case S7COMMPLUS_STATE__OPCODE:
            {
                switch ( data[idx] )
                {
                    case S7COMMPLUS_OPCODE__REQ:               // fallthrough intentional
                    case S7COMMPLUS_OPCODE__RES:               // fallthrough intentional
                    case S7COMMPLUS_OPCODE__NOTIFICATION:      // fallthrough intentional
                    case S7COMMPLUS_OPCODE__RES2:
                    {
                        s7commplus.state = S7COMMPLUS_STATE__RES_1;
                        break;
                    }

                    default:
                    {
                        s7commplus.state = S7COMMPLUS_STATE__NOT_FOUND;
                        break;
                    }
                }

                break;
            }

            case S7COMMPLUS_STATE__RES_1:
            {
                s7commplus.state = S7COMMPLUS_STATE__RES_2;
                break;
            }

            case S7COMMPLUS_STATE__RES_2:
            {
                s7commplus.state = S7COMMPLUS_STATE__FUNCTION_1;
                break;
            }

            case S7COMMPLUS_STATE__FUNCTION_1:
            {
                // make sure the function code is zeroed out before building
                s7commplus.func = 0;

                // get the high byte of the function code
                s7commplus.func = data[idx] << 0x08;

                // move on to the low byte
                s7commplus.state = S7COMMPLUS_STATE__FUNCTION_2;
                break;
            }

            case S7COMMPLUS_STATE__FUNCTION_2:
            {
                // get the low byte of the function code
                s7commplus.func |= data[idx];

                switch ( s7commplus.func )
                {
                    case S7COMMPLUS_FUNCTION__EXPLORE:               // fallthrough intentional
                    case S7COMMPLUS_FUNCTION__CREATEOBJECT:          // fallthrough intentional
                    case S7COMMPLUS_FUNCTION__DELETEOBJECT:          // fallthrough intentional
                    case S7COMMPLUS_FUNCTION__SETVARIABLE:           // fallthrough intentional
                    case S7COMMPLUS_FUNCTION__GETLINK:               // fallthrough intentional
                    case S7COMMPLUS_FUNCTION__SETMULTIVAR:           // fallthrough intentional
                    case S7COMMPLUS_FUNCTION__GETMULTIVAR:           // fallthrough intentional
                    case S7COMMPLUS_FUNCTION__BEGINSEQUENCE:         // fallthrough intentional
                    case S7COMMPLUS_FUNCTION__ENDSEQUENCE:           // fallthrough intentional
                    case S7COMMPLUS_FUNCTION__INVOKE:                // fallthrough intentional
                    case S7COMMPLUS_FUNCTION__GETVARSUBSTR:
                    {
                        s7commplus.state = S7COMMPLUS_STATE__FOUND;
                        break;
                    }

                    default:
                    {
                        s7commplus.state = S7COMMPLUS_STATE__NOT_FOUND;
                        break;
                    }
                }

                break;
            }

            case S7COMMPLUS_STATE__FOUND:
            {
                s7commplus.state = S7COMMPLUS_STATE__TPKT_VER;

                return true;
            }

            case S7COMMPLUS_STATE__NOT_FOUND:
            {
                s7commplus.state = S7COMMPLUS_STATE__TPKT_VER;

                return false;
            }

            default:
            {
                s7commplus.state = S7COMMPLUS_STATE__NOT_FOUND;
                assert(false);
                break;
            }
        }

        idx++;
    }

    s7commplus.last_state = s7commplus.state;
    s7commplus.state = S7COMMPLUS_STATE__SEARCH;

    return false;
}
