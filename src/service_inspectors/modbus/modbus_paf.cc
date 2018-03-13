//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// Protocol-Aware Flushing (PAF) code for the Modbus preprocessor.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "modbus_paf.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"

#include "modbus.h"
#include "modbus_module.h"

using namespace snort;

#define MODBUS_MIN_HDR_LEN 2        // Enough for Unit ID + Function
#define MODBUS_MAX_HDR_LEN 254      // Max PDU size is 260, 6 bytes already seen

ModbusSplitter::ModbusSplitter(bool b) : StreamSplitter(b)
{
    state = MODBUS_PAF_STATE__TRANS_ID_1;
    modbus_length = 0;
}

// Modbus/TCP PAF:
// Statefully inspects Modbus traffic from the start of a session,
// Reads up until the length octet is found, then sets a flush point.

StreamSplitter::Status ModbusSplitter::scan(
    Flow*, const uint8_t* data, uint32_t len, uint32_t /*flags*/, uint32_t* fp)
{
    uint32_t bytes_processed = 0;

    /* Process this packet 1 byte at a time */
    while (bytes_processed < len)
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
            state = (modbus_paf_state_t)(((int)state) + 1);
            break;

        case MODBUS_PAF_STATE__SET_FLUSH:
            if ((modbus_length < MODBUS_MIN_HDR_LEN) ||
                (modbus_length > MODBUS_MAX_HDR_LEN))
            {
                DetectionEngine::queue_event(GID_MODBUS, MODBUS_BAD_LENGTH);
            }

            *fp = modbus_length + bytes_processed;
            state = MODBUS_PAF_STATE__TRANS_ID_1;
            modbus_length = 0;
            modbus_stats.frames++;
            return StreamSplitter::FLUSH;
        }

        bytes_processed++;
    }

    return StreamSplitter::SEARCH;
}

