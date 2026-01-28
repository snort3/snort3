//--------------------------------------------------------------------------
// Copyright (C) 2018-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "s7comm.h"
#include "s7comm_decode.h"
#include "s7comm_module.h"

using namespace snort;


static std::vector<uint8_t> cotp_invalid_codes { 0x00, 0x03, 0x09, 0x0A };

S7commplusSplitter::S7commplusSplitter(bool b) : StreamSplitter(b)
{
    state = S7COMMPLUS_PAF_STATE__TPKT_VER;
    tpkt_length = 0;
}

// S7comm/TCP PAF:
// Statefully inspects S7comm traffic from the start of a session,
// Processes network packets byte-by-byte to validate and parse encapsulation protocol headers.
// Sets flush point at successful find of S7COMMPLUS protocol ID inside TPKT and COTP encapsulation.

StreamSplitter::Status S7commplusSplitter::scan(
    Packet*, const uint8_t* data, uint32_t len, uint32_t /*flags*/, uint32_t* fp)
{
    uint32_t bytes_processed = 0;
    uint8_t* processed_data = const_cast<uint8_t*>(data);

    /* Process this packet 1 byte at a time */
    while (bytes_processed < len)
    {
        switch (state)
        {
        case S7COMMPLUS_PAF_STATE__TPKT_VER:
        {
            uint8_t tpkt_version = *processed_data;
            if ( tpkt_version != TPKT_SUPPORTED_VERSION)
            {
                reset_state();
                return StreamSplitter::ABORT;
            }

            ++state;
            break;
        }
        case S7COMMPLUS_PAF_STATE__TPKT_RESERVED:
        {
            uint8_t tpkt_reserved_bytes = *processed_data;
            if (tpkt_reserved_bytes != 0)
            {
                reset_state();
                return StreamSplitter::ABORT;
            }

            ++state;
            break;
        }
        case S7COMMPLUS_PAF_STATE__TPKT_LEN_1:
        {
            tpkt_length = *(processed_data) << 8;
            ++state;
            break;
        }
        case S7COMMPLUS_PAF_STATE__TPKT_LEN_2:
        {
            tpkt_length |= *(processed_data);
            if (tpkt_length < TPKT_MIN_PACKET_LEN)
            {
                reset_state();
                return StreamSplitter::ABORT;
            }

            ++state;
            break;
        }
        case S7COMMPLUS_PAF_STATE__COTP_LEN:
        {
            uint8_t cotp_length = *(processed_data);
            if (cotp_length < COTP_MIN_PACKET_LEN)
            {
                reset_state();
                return StreamSplitter::ABORT;
            }
            
            ++state;
            break;
        }
        case S7COMMPLUS_PAF_STATE__COTP_PDU_TYPE:
        {
            uint8_t cotp_tpdu_and_flags = *(processed_data);
            uint8_t cotp_tpdu = cotp_tpdu_and_flags >> 4;
            uint8_t flags = cotp_tpdu_and_flags & 0x0F; // get lower 4 bits

            if ( (std::any_of(cotp_invalid_codes.begin(), cotp_invalid_codes.end(),
                [&cotp_tpdu](uint8_t code) { return cotp_tpdu == code; })) or flags)
            {
                reset_state();
                return StreamSplitter::ABORT;
            }

            if (cotp_tpdu == COTP_CONNECTION_REQUEST_TPDU)
            {
                state = S7COMMPLUS_PAF_STATE__COTP_CR_DST_REF_1;
            }
            else if ( cotp_tpdu == COTP_DATA_TRANSFER_TPDU )
            {
                state = S7COMMPLUS_PAF_STATE__COTP_DT_TPDU_NUM_EOT;
            }
            else
            {
                *fp = tpkt_length;
                reset_state();
                return StreamSplitter::FLUSH;
            }

            break;
        }
        case S7COMMPLUS_PAF_STATE__COTP_CR_DST_REF_1:
        case S7COMMPLUS_PAF_STATE__COTP_CR_DST_REF_2:
        case S7COMMPLUS_PAF_STATE__COTP_CR_SRC_REF_1:
        case S7COMMPLUS_PAF_STATE__COTP_CR_SRC_REF_2:
            ++state;
            break;
        
        case S7COMMPLUS_PAF_STATE__COTP_CR_CLASS_OPTIONS:
        {
            uint8_t cotp_cr_class_options = *processed_data;

            if (!cotp_cr_class_options or (cotp_cr_class_options == 0x10)) // Class 0 or 1
            {
                *fp = tpkt_length;
                reset_state();
                return StreamSplitter::FLUSH;
            }
            else
            {
                reset_state();
                return StreamSplitter::ABORT;
            }
        }
        case S7COMMPLUS_PAF_STATE__COTP_DT_TPDU_NUM_EOT:
        {
            auto dst_ref_last_packet = *processed_data;
            if (dst_ref_last_packet & 0x80) // 1st bit indicates that data is finished
                ++state;
            else
            {
                //COTP fragment, flush and wait for data
                *fp = tpkt_length;
                reset_state();
                return StreamSplitter::FLUSH;
            }
            break;
        }
        case S7COMMPLUS_PAF_STATE__S7_PROTOCOL_ID:
        {
            uint8_t s7_protocol_id = *processed_data;
            if (s7_protocol_id != S7COMMPLUS_PROTOCOL_ID)
            {
                reset_state();
                return StreamSplitter::ABORT;
            }

            *fp = tpkt_length;
            reset_state();
            return StreamSplitter::FLUSH;
        }
        default:
            assert(false);
            reset_state();
            return StreamSplitter::ABORT;
        }

        bytes_processed++;
        processed_data++;
    }

    return StreamSplitter::SEARCH;
}

void S7commplusSplitter::reset_state()
{
    tpkt_length = 0;
    state = S7COMMPLUS_PAF_STATE__TPKT_VER;
}
