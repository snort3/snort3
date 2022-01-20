//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

// cip_paf.cc author RA/Cisco

/* Description: Protocol-Aware Flushing (PAF) code for the CIP inspector. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cip_paf.h"
#include "cip_parsing.h"              // For ENIP constants

// PAF will skip over the ENIP Command and Length fields.
static const uint16_t ENIP_PAF_FIELD_SIZE = 4;

using namespace snort;

/* Function: CIPPaf()

   Purpose: CIP PAF callback.
            Statefully inspects CIP traffic from the start of a session.
            Reads up until the length octet is found, then sets a flush point.
            The flushed PDU is a ENIP frame.
*/

static StreamSplitter::Status cip_paf(cip_paf_data* pafdata, const uint8_t* data,
    uint32_t len, uint32_t* fp)
{
    uint32_t bytes_processed = 0;

    /* Process this packet 1 byte at a time */
    while (bytes_processed < len)
    {
        switch (pafdata->paf_state)
        {
        case CIP_PAF_STATE__COMMAND_1:
            // Skip ENIP command.
            pafdata->paf_state = CIP_PAF_STATE__COMMAND_2;
            break;

        case CIP_PAF_STATE__COMMAND_2:
            // Skip ENIP command.
            pafdata->paf_state = CIP_PAF_STATE__LENGTH_1;
            break;

        case CIP_PAF_STATE__LENGTH_1:
            pafdata->enip_length = *(data + bytes_processed);
            pafdata->paf_state = CIP_PAF_STATE__LENGTH_2;
            break;

        case CIP_PAF_STATE__LENGTH_2:
            pafdata->enip_length |= (*(data + bytes_processed) << 8);
            pafdata->paf_state = CIP_PAF_STATE__SET_FLUSH;
            break;

        case CIP_PAF_STATE__SET_FLUSH:
            *fp = bytes_processed +
                pafdata->enip_length + (ENIP_HEADER_SIZE - ENIP_PAF_FIELD_SIZE);

            pafdata->paf_state = CIP_PAF_STATE__COMMAND_1;
            return StreamSplitter::FLUSH;

        default:
            // Will not happen.
            break;
        }

        bytes_processed++;
    }

    return StreamSplitter::SEARCH;
}

CipSplitter::CipSplitter(bool c2s) : StreamSplitter(c2s)
{
    state.paf_state = CIP_PAF_STATE__COMMAND_1;
    state.enip_length = 0;
}

StreamSplitter::Status CipSplitter::scan(
    Packet*, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t* fp)
{
    cip_paf_data* pfdata = &state;
    return cip_paf(pfdata, data, len, fp);
}

