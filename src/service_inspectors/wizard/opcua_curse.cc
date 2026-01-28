//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// opcua_curse.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "opcua_curse.h"
#include "curse_book.h"

#include <assert.h>
#include <unordered_map>

static constexpr uint32_t make_opcua_msg_key(char, char, char, char);

static const std::unordered_map<uint32_t, OpcuaMsgType> opcua_known_msgs = {
    {make_opcua_msg_key('H','E','L','F'), OPCUA_MSG__HEL},
    {make_opcua_msg_key('A','C','K','F'), OPCUA_MSG__ACK},
    {make_opcua_msg_key('E','R','R','F'), OPCUA_MSG__ERR},
    {make_opcua_msg_key('R','H','E','F'), OPCUA_MSG__RHE},
    {make_opcua_msg_key('O','P','N','F'), OPCUA_MSG__OPN},
    {make_opcua_msg_key('M','S','G','C'), OPCUA_MSG__MSG},
    {make_opcua_msg_key('M','S','G','F'), OPCUA_MSG__MSG},
    {make_opcua_msg_key('M','S','G','A'), OPCUA_MSG__MSG},
    {make_opcua_msg_key('C','L','O','F'), OPCUA_MSG__CLO}
};

void OpcuaTracker::reset()
{
    raw_msg_type[0] = '_';
    raw_msg_type[1] = '_';
    raw_msg_type[2] = '_';
    is_final = '_';
    msg_type = OPCUA_MSG__UNDEFINED;
    state = OPCUA_STATE__MSG_TYPE_1;
}

static bool verify_message_data_size( unsigned len, uint32_t idx, uint32_t msg_min_size )
{
    return len - idx >= msg_min_size;
}

static constexpr uint32_t make_opcua_msg_key(char c1, char c2, char c3, char c4)
{
    return (static_cast<uint32_t>(static_cast<uint8_t>(c1)) << 24) | 
           (static_cast<uint32_t>(static_cast<uint8_t>(c2)) << 16) | 
           (static_cast<uint32_t>(static_cast<uint8_t>(c3)) << 8) | 
           static_cast<uint32_t>(static_cast<uint8_t>(c4));
}

bool CurseBook::opcua_curse( const uint8_t* data, unsigned len, CurseTracker* tracker )
{
    OpcuaTracker& opcua = tracker->opcua;

    if ( opcua.state == OPCUA_STATE__SEARCH )
    {
        opcua.state = opcua.last_state;
    }

    uint32_t idx = 0;
    while ( idx < len )
    {
        switch ( opcua.state )
        {
        case OPCUA_STATE__MSG_TYPE_1:
        {
            switch ( data[idx] )
            {
            case 'H': // fallthrough intentional
            case 'A': // fallthrough intentional
            case 'E': // fallthrough intentional
            case 'R': // fallthrough intentional
            case 'O': // fallthrough intentional
            case 'M': // fallthrough intentional
            case 'C':
            {
                opcua.raw_msg_type[0] = data[idx];
                opcua.state = OPCUA_STATE__MSG_TYPE_2;
                break;
            }

            default:
            {
                opcua.state = OPCUA_STATE__NOT_FOUND;
                break;
            }
            }

            break;
        }

        case OPCUA_STATE__MSG_TYPE_2:
        {
            switch ( data[idx] )
            {
            case 'E': // fallthrough intentional
            case 'C': // fallthrough intentional
            case 'R': // fallthrough intentional
            case 'H': // fallthrough intentional
            case 'P': // fallthrough intentional
            case 'S': // fallthrough intentional
            case 'L':
            {
                opcua.raw_msg_type[1] = data[idx];
                opcua.state = OPCUA_STATE__MSG_TYPE_3;
                break;
            }

            default:
            {
                opcua.state = OPCUA_STATE__NOT_FOUND;
                break;
            }
            }

            break;
        }

        case OPCUA_STATE__MSG_TYPE_3:
        {
            opcua.raw_msg_type[2] = data[idx];
            opcua.state = OPCUA_STATE__IS_FINAL;
            break;
        }

        case OPCUA_STATE__IS_FINAL:
        {
            opcua.state = OPCUA_STATE__MSG_SIZE_1;
            opcua.is_final = data[idx];

            auto it = opcua_known_msgs.find(
                make_opcua_msg_key(opcua.raw_msg_type[0], opcua.raw_msg_type[1], opcua.raw_msg_type[2], opcua.is_final)
            );

            if ( it != opcua_known_msgs.end() )
                opcua.msg_type = it->second;
            else
                opcua.state = OPCUA_STATE__NOT_FOUND;

            break;
        }

        case OPCUA_STATE__MSG_SIZE_1:
        {
            opcua.state = OPCUA_STATE__MSG_SIZE_2;
            break;
        }

        case OPCUA_STATE__MSG_SIZE_2:
        {
            opcua.state = OPCUA_STATE__MSG_SIZE_3;
            break;
        }

        case OPCUA_STATE__MSG_SIZE_3:
        {
            opcua.state = OPCUA_STATE__MSG_SIZE_4;
            break;
        }

        case OPCUA_STATE__MSG_SIZE_4:
        {
            switch ( opcua.msg_type )
            {
            case OPCUA_MSG__HEL:
            {
                opcua.state = OPCUA_STATE__CONN_PROTO_HEL;
                break;
            }

            case OPCUA_MSG__ACK:
            {
                opcua.state = OPCUA_STATE__CONN_PROTO_ACK;
                break;
            }

            case OPCUA_MSG__ERR:
            {
                opcua.state = OPCUA_STATE__CONN_PROTO_ERR;
                break;
            }

            case OPCUA_MSG__RHE:
            {
                opcua.state = OPCUA_STATE__CONN_PROTO_RHE;
                break;
            }

            case OPCUA_MSG__OPN: // fallthrough intentional
            case OPCUA_MSG__MSG: // fallthrough intentional
            case OPCUA_MSG__CLO:
            {
                opcua.state = OPCUA_STATE__SECURE_CHANNEL_ID_1;
                break;
            }

            default:
            {
                opcua.state = OPCUA_STATE__NOT_FOUND;
                break;
            }
            }

            break;
        }

        case OPCUA_STATE__CONN_PROTO_HEL:
        {
            if ( verify_message_data_size(len, idx, CONN_PROTO_HEL_MIN_SIZE) )
            {
                opcua.state = OPCUA_STATE__FOUND;
                break;
            }

            opcua.state = OPCUA_STATE__NOT_FOUND;
            break;
        }

        case OPCUA_STATE__CONN_PROTO_ACK:
        {
            if ( verify_message_data_size(len, idx, CONN_PROTO_ACK_MIN_SIZE) )
            {
                opcua.state = OPCUA_STATE__FOUND;
                break;
            }

            opcua.state = OPCUA_STATE__NOT_FOUND;
            break;
        }

        case OPCUA_STATE__CONN_PROTO_ERR:
        {
            if ( verify_message_data_size(len, idx, CONN_PROTO_ERR_MIN_SIZE) )
            {
                opcua.state = OPCUA_STATE__FOUND;
                break;
            }

            opcua.state = OPCUA_STATE__NOT_FOUND;
            break;
        }

        case OPCUA_STATE__CONN_PROTO_RHE:
        {
            if ( verify_message_data_size(len, idx, CONN_PROTO_RHE_MIN_SIZE) )
            {
                opcua.state = OPCUA_STATE__FOUND;
                break;
            }

            opcua.state = OPCUA_STATE__NOT_FOUND;
            break;
        }

        case OPCUA_STATE__SECURE_CHANNEL_ID_1:
        {
            opcua.state = OPCUA_STATE__SECURE_CHANNEL_ID_2;
            break;
        }

        case OPCUA_STATE__SECURE_CHANNEL_ID_2:
        {
            opcua.state = OPCUA_STATE__SECURE_CHANNEL_ID_3;
            break;
        }

        case OPCUA_STATE__SECURE_CHANNEL_ID_3:
        {
            opcua.state = OPCUA_STATE__SECURE_CHANNEL_ID_4;
            break;
        }

        case OPCUA_STATE__SECURE_CHANNEL_ID_4:
        {
            switch ( opcua.msg_type )
            {
            case OPCUA_MSG__OPN:
            {
                opcua.state = OPCUA_STATE__SECURE_CONV_OPN;
                break;
            }

            case OPCUA_MSG__MSG:
            {
                opcua.state = OPCUA_STATE__SECURE_CONV_MSG;
                break;
            }

            case OPCUA_MSG__CLO:
            {
                opcua.state = OPCUA_STATE__SECURE_CONV_CLO;
                break;
            }

            default:
            {
                opcua.state = OPCUA_STATE__NOT_FOUND;
                break;
            }
            }
            break;
        }

        case OPCUA_STATE__SECURE_CONV_OPN:
        {
            if ( verify_message_data_size(len, idx, SECURE_CONV_SECURITY_HDR_OPN_MIN_SIZE + SECURE_CONV_SEQUENCE_HDR_MIN_SIZE + MESSAGE_TYPE_ID_MIN_SIZE) )
            {
                opcua.state = OPCUA_STATE__FOUND;
                break;
            }

            opcua.state = OPCUA_STATE__NOT_FOUND;
            break;
        }

        case OPCUA_STATE__SECURE_CONV_MSG:
        {
            if ( verify_message_data_size(len, idx, SECURE_CONV_SECURITY_HDR_MSG_MIN_SIZE + SECURE_CONV_SEQUENCE_HDR_MIN_SIZE + MESSAGE_TYPE_ID_MIN_SIZE) )
            {
                opcua.state = OPCUA_STATE__FOUND;
                break;
            }

            opcua.state = OPCUA_STATE__NOT_FOUND;
            break;
        }

        case OPCUA_STATE__SECURE_CONV_CLO:
        {
            if ( verify_message_data_size(len, idx, SECURE_CONV_SECURITY_HDR_MSG_MIN_SIZE + SECURE_CONV_SEQUENCE_HDR_MIN_SIZE + MESSAGE_TYPE_ID_MIN_SIZE) )
            {
                opcua.state = OPCUA_STATE__FOUND;
                break;
            }

            opcua.state = OPCUA_STATE__NOT_FOUND;
            break;
        }

        case OPCUA_STATE__FOUND:
        {
            opcua.reset();
            return true;
        }

        case OPCUA_STATE__NOT_FOUND:
        {
            opcua.reset();
            return false;
        }

        default:
        {
            opcua.state = OPCUA_STATE__NOT_FOUND;
            assert( false );
            break;
        }
        }

        idx++;
    }

    opcua.last_state = opcua.state;
    opcua.state = OPCUA_STATE__SEARCH;

    return false;
}

