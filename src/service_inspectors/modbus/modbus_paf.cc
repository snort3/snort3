//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// modbus_paf.cc author Ryan Jordan
// Protocol-Aware Flushing (PAF) code for the Modbus inspector.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "modbus_paf.h"

#include "detection/detection_engine.h"

#include "modbus.h"
#include "modbus_module.h"

using namespace snort;

#define MODBUS_MIN_HDR_LEN              2     // Enough for Unit ID + Function
#define MODBUS_MAX_HDR_LEN              254   // Max PDU size is 260, 6 bytes already seen
#define MODBUS_INVALID_CLIENT_FUNC_CODE 0x80  // Invalid function code for client requests
#define MODBUS_INVALID_FUNC_CODE        0x00  // Invalid function code

ModbusSplitter::ModbusSplitter(bool b) : StreamSplitter(b)
{
    state = MODBUS_PAF_STATE__TRANS_ID_1;
    modbus_length = 0;
    bytes_seen = 0;
}

void ModbusSplitter::reset()
{
    state = MODBUS_PAF_STATE__TRANS_ID_1;
    modbus_length = 0;
}

// Modbus/TCP PAF:
// Statefully inspects Modbus traffic from the start of a session,
// Reads up until the length octet is found, then sets a flush point.

StreamSplitter::Status ModbusSplitter::scan(
    Packet* p, const uint8_t* data, uint32_t len, uint32_t /*flags*/, uint32_t* fp)
{
    uint32_t bytes_processed = 0;
    bool isInvalid = false; 
    /* Process this packet 1 byte at a time */
    /* Special case: when packet length equals the minimum Modbus frame size,
       we need to check the SET_FLUSH state even after processing all bytes
       to ensure proper fallback execution */
    while (bytes_processed < len || state == MODBUS_PAF_STATE__SET_FLUSH)
    {
        switch (state)
        {
        /* Skip the Transaction & Protocol IDs */
        case MODBUS_PAF_STATE__TRANS_ID_1:
        case MODBUS_PAF_STATE__TRANS_ID_2:
        case MODBUS_PAF_STATE__PROTO_ID_1:
        case MODBUS_PAF_STATE__PROTO_ID_2:
            state = (modbus_paf_state_t)(((int)state) + 1);
            break;

        /* Read length 1 byte at a time, in case a TCP segment is sent
         * with only 5 bytes from the MBAP header */
        case MODBUS_PAF_STATE__LENGTH_1:
            modbus_length |= *(data + bytes_processed) << 8;
            state = (modbus_paf_state_t)(((int)state) + 1);
            break;

        case MODBUS_PAF_STATE__LENGTH_2:
            modbus_length |= *(data + bytes_processed);
            if ((modbus_length < MODBUS_MIN_HDR_LEN) ||
                (modbus_length > MODBUS_MAX_HDR_LEN))
            {
                DetectionEngine::queue_event(GID_MODBUS, MODBUS_BAD_LENGTH);
                state = MODBUS_PAF_STATE__INVALID;
            }
            else
            {
                state = (modbus_paf_state_t)(((int)state) + 1);
            }
            break;
        case MODBUS_PAF_STATE__UNIT_ID:
            state = (modbus_paf_state_t)(((int)state) + 1);
            break;
        case MODBUS_PAF_STATE__FUNC_CODE:
            isInvalid = *(data + bytes_processed) == MODBUS_INVALID_FUNC_CODE ||
                (p->is_from_client() && *(data + bytes_processed) >= MODBUS_INVALID_CLIENT_FUNC_CODE);
            state = isInvalid? MODBUS_PAF_STATE__INVALID: MODBUS_PAF_STATE__SET_FLUSH;
            break;
        case MODBUS_PAF_STATE__INVALID:
            reset();
            bytes_seen += len;
            return bytes_seen >= MODBUS_MAX_OCTETS ? StreamSplitter::ABORT : StreamSplitter::SEARCH;
        case MODBUS_PAF_STATE__SET_FLUSH:
            // Length - The length field is a byte count of the following fields, including the Unit
            // identifier and data fields. so we subtract 2 to account for the Unit ID and Function Code.
            *fp = modbus_length + bytes_processed - 2;
            bytes_seen = 0;
            reset();
            modbus_stats.frames++;
            return StreamSplitter::FLUSH;
        }

        bytes_processed++;
    }

    bytes_seen += len;
    return StreamSplitter::SEARCH;
}

