// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
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
// s7comm_curse.cc author [Your Name] <your.email@example.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "s7comm_curse.h"
#include "curse_book.h"

enum S7comm_Protocol_Identifier
{
    S7COMM_PROTOCOL_IDENTIFIER = 0x32
};

enum S7comm_Message_Type
{
    S7COMM_MESSAGE_TYPE__JOB_REQUEST  = 0x01,
    S7COMM_MESSAGE_TYPE__ACK          = 0x02,
    S7COMM_MESSAGE_TYPE__ACK_DATA     = 0x03,
    S7COMM_MESSAGE_TYPE__USERDATA     = 0x07
};

bool CurseBook::s7comm_curse(const uint8_t* data, unsigned len, CurseTracker* tracker)
{
    S7commTracker& s7comm = tracker->s7comm;

    if (s7comm.state == S7COMM_STATE__SEARCH)
    {
        s7comm.state = s7comm.last_state;
    }

    uint32_t idx = 0;
    while (idx < len)
    {
        switch (s7comm.state)
        {
            case S7COMM_STATE__TPKT_VER:
            {
                s7comm.state = S7COMM_STATE__TPKT_RES;
                break;
            }

            case S7COMM_STATE__TPKT_RES:
            {
                s7comm.state = S7COMM_STATE__TPKT_LEN1;
                break;
            }

            case S7COMM_STATE__TPKT_LEN1:
            {
                s7comm.state = S7COMM_STATE__TPKT_LEN2;
                break;
            }

            case S7COMM_STATE__TPKT_LEN2:
            {
                s7comm.state = S7COMM_STATE__COTP_LEN;
                break;
            }

            case S7COMM_STATE__COTP_LEN:
            {
                s7comm.state = S7COMM_STATE__COTP_PDU;
                break;
            }

            case S7COMM_STATE__COTP_PDU:
            {
                s7comm.state = S7COMM_STATE__COTP_TPDU_NUM;
                break;
            }

            case S7COMM_STATE__COTP_TPDU_NUM:
            {
                s7comm.state = S7COMM_STATE__PROTO_ID;
                break;
            }

            case S7COMM_STATE__PROTO_ID:
            {
                if (data[idx] == S7COMM_PROTOCOL_IDENTIFIER)
                {
                    s7comm.state = S7COMM_STATE__MESSAGE_TYPE;
                }
                else
                {
                    s7comm.state = S7COMM_STATE__NOT_FOUND;
                }
                break;
            }

            case S7COMM_STATE__MESSAGE_TYPE:
            {
                switch (data[idx])
                {
                    case S7COMM_MESSAGE_TYPE__JOB_REQUEST:
                    case S7COMM_MESSAGE_TYPE__ACK:
                    case S7COMM_MESSAGE_TYPE__ACK_DATA:
                    case S7COMM_MESSAGE_TYPE__USERDATA:
                    {
                        s7comm.state = S7COMM_STATE__RESERVED_1;
                        break;
                    }

                    default:
                    {
                        s7comm.state = S7COMM_STATE__NOT_FOUND;
                        break;
                    }
                }
                break;
            }

            case S7COMM_STATE__RESERVED_1:
            {
                s7comm.state = S7COMM_STATE__RESERVED_2;
                break;
            }

            case S7COMM_STATE__RESERVED_2:
            {
                s7comm.state = S7COMM_STATE__PDU_REFERENCE_1;
                break;
            }

            case S7COMM_STATE__PDU_REFERENCE_1:
            {
                s7comm.state = S7COMM_STATE__PDU_REFERENCE_2;
                break;
            }

            case S7COMM_STATE__PDU_REFERENCE_2:
            {
                s7comm.state = S7COMM_STATE__PARAMETER_LENGTH_1;
                break;
            }

            case S7COMM_STATE__PARAMETER_LENGTH_1:
            {
                s7comm.state = S7COMM_STATE__PARAMETER_LENGTH_2;
                break;
            }

            case S7COMM_STATE__PARAMETER_LENGTH_2:
            {
                s7comm.state = S7COMM_STATE__DATA_LENGTH_1;
                break;
            }

            case S7COMM_STATE__DATA_LENGTH_1:
            {
                s7comm.state = S7COMM_STATE__DATA_LENGTH_2;
                break;
            }

            case S7COMM_STATE__DATA_LENGTH_2:
            {
                if (data[idx] == S7COMM_MESSAGE_TYPE__ACK_DATA)
                {
                    s7comm.state = S7COMM_STATE__OPTIONAL_ERROR_CLASS;
                }
                else
                {
                    s7comm.state = S7COMM_STATE__FOUND;
                }
                break;
            }

            case S7COMM_STATE__OPTIONAL_ERROR_CLASS:
            {
                s7comm.state = S7COMM_STATE__OPTIONAL_ERROR_CODE;
                break;
            }

            case S7COMM_STATE__OPTIONAL_ERROR_CODE:
            {
                s7comm.state = S7COMM_STATE__FOUND;
                break;
            }

            case S7COMM_STATE__FOUND:
            {
                s7comm.state = S7COMM_STATE__TPKT_VER;
                return true;
            }

            case S7COMM_STATE__NOT_FOUND:
            {
                s7comm.state = S7COMM_STATE__TPKT_VER;
                return false;
            }

            default:
            {
                s7comm.state = S7COMM_STATE__NOT_FOUND;
                assert(false);
                break;
            }
        }

        idx++;
    }

    s7comm.last_state = s7comm.state;
    s7comm.state = S7COMM_STATE__SEARCH;

    return false;
}
