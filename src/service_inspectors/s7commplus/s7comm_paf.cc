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

// s7comm_paf.cc author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>
// Protocol-Aware Flushing (PAF) code for the S7commplus inspector.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "s7comm_paf.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"

#include "s7comm.h"
#include "s7comm_decode.h"
#include "s7comm_module.h"

using namespace snort;

#define S7COMMPLUS_MIN_HDR_LEN 4        // Enough for Unit ID + Function

S7commplusSplitter::S7commplusSplitter(bool b) : StreamSplitter(b)
{
    state = S7COMMPLUS_PAF_STATE__TPKT_VER;
    tpkt_length = 0;
}

// S7comm/TCP PAF:
// Statefully inspects S7comm traffic from the start of a session,
// Reads up until the length octet is found, then sets a flush point.

StreamSplitter::Status S7commplusSplitter::scan(
    Packet*, const uint8_t* data, uint32_t len, uint32_t /*flags*/, uint32_t* fp)
{
    uint32_t bytes_processed = 0;

    /* Process this packet 1 byte at a time */
    while (bytes_processed < len)
    {
        switch (state)
        {
        /* Skip the Transaction & Protocol IDs */
        case S7COMMPLUS_PAF_STATE__TPKT_VER:
        case S7COMMPLUS_PAF_STATE__TPKT_RESERVED:
        case S7COMMPLUS_PAF_STATE__COTP_LEN:
        case S7COMMPLUS_PAF_STATE__COTP_PDU_TYPE:
            state = (s7commplus_paf_state_t)(((int)state) + 1);     //Set the state to next PAF
                                                                    // state
            break;

        /* Read length 1 byte at a time, in case a TCP segment is sent
         * with xxx bytes from the S7CPAP header */
        case S7COMMPLUS_PAF_STATE__TPKT_LEN_1:
            tpkt_length |= ( *(data + bytes_processed) << 8 );
            state = S7COMMPLUS_PAF_STATE__TPKT_LEN_2;
            break;

        case S7COMMPLUS_PAF_STATE__TPKT_LEN_2:
            tpkt_length |= *(data + bytes_processed);
            state = S7COMMPLUS_PAF_STATE__COTP_LEN;
            break;

        case S7COMMPLUS_PAF_STATE__SET_FLUSH:
            if ((tpkt_length < TPKT_MIN_HDR_LEN))
            {
                DetectionEngine::queue_event(GID_S7COMMPLUS, S7COMMPLUS_BAD_LENGTH);
            }

            *fp = tpkt_length;      // flush point at the end of payload
            state = S7COMMPLUS_PAF_STATE__TPKT_VER;
            tpkt_length = 0;
            return StreamSplitter::FLUSH;
        }

        bytes_processed++;
    }

    return StreamSplitter::SEARCH;
}

