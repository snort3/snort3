//--------------------------------------------------------------------------
// Copyright (C) 2015-2026 Cisco and/or its affiliates. All rights reserved.
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

// dnp3_paf.cc author Rashmi Pitre <rrp@cisco.com>
// based on work by Ryan Jordan

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dnp3_paf.h"

#include "dnp3.h"

using namespace snort;

/* Function: dnp3_paf()

   Purpose: DNP3 PAF callback.
            Statefully inspects DNP3 traffic from the start of a session,
            Reads up until the length octet is found, then sets a flush point.
            The flushed PDU is a DNP3 Link Layer frame, the inspector
            handles reassembly of frames into Application Layer messages.

*/

#define DNP3_DATA_FUNC_CODE__ACK 0
#define DNP3_DATA_FUNC_CODE__NACK 1
#define DNP3_DATA_FUNC_CODE__LINK_STATUS 11

#define DNP3_CTRL_FUNC_CODE__RESET_LINK_STATES 0
#define DNP3_CTRL_FUNC_CODE__TEST_LINK_STATES 2
#define DNP3_CTRL_FUNC_CODE__REQUEST_LINK_STATUS 9

static StreamSplitter::Status dnp3_paf(dnp3_paf_data* pafdata, const uint8_t* data,
    uint32_t len, uint32_t* fp, const uint8_t& zero_payload_packet_limit)
{
    uint32_t bytes_processed = 0;
    bool zero_length_packet = false;

    /* Process this packet 1 byte at a time */
    while (bytes_processed < len)
    {
        uint16_t user_data = 0;
        uint16_t num_crcs = 0;
        uint8_t data_byte = 0;
        bool is_primary = false;
        uint8_t function_code = 0;

        switch (pafdata->paf_state)
        {
        /* Check the Start bytes. If they are not \x05\x64, don't advance state.
           Could be out of sync, junk data between frames, mid-stream pickup, etc. */
        case DNP3_PAF_STATE__START_1:
            if (((uint8_t)*(data + bytes_processed)) == DNP3_START_BYTE_1)
            {
                if (pafdata->junk_pending)
                {
                    // flush the junk prefix, leaving this possible start byte queued
                    *fp = bytes_processed;
                    pafdata->junk_pending = false;
                    pafdata->paf_state = DNP3_PAF_STATE__START_1;
                    return StreamSplitter::FLUSH;
                }
                pafdata->paf_state = (dnp3_paf_state)(((int)pafdata->paf_state) + 1);
            }
            else
            {
                pafdata->junk_bytes++;
                pafdata->junk_pending = true;
            }
            break;

        case DNP3_PAF_STATE__START_2:
            if (((uint8_t)*(data + bytes_processed)) == DNP3_START_BYTE_2)
                pafdata->paf_state = (dnp3_paf_state)(((int)pafdata->paf_state) + 1);
            else if (((uint8_t)*(data + bytes_processed)) == DNP3_START_BYTE_1)
            {
                if (++pafdata->junk_bytes > DNP3_MAX_OCTETS)
                    return StreamSplitter::ABORT;
                *fp = bytes_processed;
                pafdata->junk_pending = false;
                pafdata->paf_state = DNP3_PAF_STATE__START_1;
                return StreamSplitter::FLUSH;
            }
            else
            {
                pafdata->paf_state = DNP3_PAF_STATE__START_1;
                pafdata->junk_bytes += 2;
                pafdata->junk_pending = true;
            }
            break;

        /* Read the length. */
        case DNP3_PAF_STATE__LENGTH:
            pafdata->dnp3_length = (uint8_t)*(data + bytes_processed);

            /* DNP3 length only counts non-CRC octets following the
               length field itself. Each CRC is two octets. One follows
               the headers, a CRC is inserted for every 16 octets of user data,
               plus a CRC for the last bit of user data (< 16 octets) */

            if (pafdata->dnp3_length < DNP3_HEADER_REMAINDER_LEN)
            {
                pafdata->paf_state = DNP3_PAF_STATE__START_1;
                pafdata->junk_bytes += 3;
                pafdata->junk_pending = true;
                break;
            }
            if (pafdata->dnp3_length == DNP3_HEADER_REMAINDER_LEN)
                zero_length_packet = true;

            user_data = pafdata->dnp3_length - DNP3_HEADER_REMAINDER_LEN;
            num_crcs = 1 + (user_data/DNP3_CHUNK_SIZE) + ((user_data % DNP3_CHUNK_SIZE) ? 1 : 0);
            pafdata->real_length = pafdata->dnp3_length + (DNP3_CRC_SIZE*num_crcs);

            pafdata->paf_state = (dnp3_paf_state)(((int)pafdata->paf_state) + 1);
            break;

        case DNP3_PAF_STATE__CONTROL:
            data_byte = *(data + bytes_processed);
            is_primary = (data_byte & 0x40) == 0x40;
            function_code = data_byte & 0x0F;

            if (!is_primary)
            {
                switch (function_code)
                {
                    case DNP3_DATA_FUNC_CODE__ACK:
                    case DNP3_DATA_FUNC_CODE__NACK:
                    case DNP3_DATA_FUNC_CODE__LINK_STATUS:
                        pafdata->paf_state = DNP3_PAF_STATE__SET_FLUSH;
                        pafdata->zero_length_packets = 0;
                        break;
                    default:
                        if (zero_length_packet)
                            pafdata->zero_length_packets++;
                        else
                            pafdata->zero_length_packets = 0;

                        if (pafdata->zero_length_packets > zero_payload_packet_limit)
                            return StreamSplitter::ABORT;
                        else
                            pafdata->paf_state = DNP3_PAF_STATE__SET_FLUSH;
                        break;
                }
            }
            else
            {
                switch (function_code)
                {
                    case DNP3_CTRL_FUNC_CODE__RESET_LINK_STATES:
                    case DNP3_CTRL_FUNC_CODE__TEST_LINK_STATES:
                    case DNP3_CTRL_FUNC_CODE__REQUEST_LINK_STATUS:
                        pafdata->paf_state = DNP3_PAF_STATE__SET_FLUSH;
                        pafdata->zero_length_packets = 0;
                        break;
                    default:
                        if (zero_length_packet)
                            pafdata->zero_length_packets++;
                        else
                            pafdata->zero_length_packets = 0;

                        if (pafdata->zero_length_packets > zero_payload_packet_limit)
                            return StreamSplitter::ABORT;
                        else
                            pafdata->paf_state = DNP3_PAF_STATE__SET_FLUSH;
                        break;
                }
            }
            
            break;

        /* Set the flush point. */
        case DNP3_PAF_STATE__SET_FLUSH:
            *fp = ( pafdata->real_length -1 ) + bytes_processed;
            pafdata->paf_state = DNP3_PAF_STATE__START_1;
            pafdata->junk_bytes = 0;
            pafdata->junk_pending = false;
            return StreamSplitter::FLUSH;
        }

        if (pafdata->junk_bytes > DNP3_MAX_OCTETS)
            return StreamSplitter::ABORT;

        bytes_processed++;
    }

    return StreamSplitter::SEARCH;
}

Dnp3Splitter::Dnp3Splitter(bool c2s, uint8_t zero_payload_packet_limit) : StreamSplitter(c2s)
{
    state.paf_state = DNP3_PAF_STATE__START_1;
    state.dnp3_length = 0;
    state.real_length = 0;
    state.zero_length_packets = 0;
    state.junk_bytes = 0;
    state.junk_pending = false;
    this->zero_payload_packet_limit = zero_payload_packet_limit;
}

StreamSplitter::Status Dnp3Splitter::scan(
    Packet*, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t* fp)
{
    dnp3_paf_data* pfdata = &state;
    return dnp3_paf(pfdata, data, len, fp, zero_payload_packet_limit);
}

