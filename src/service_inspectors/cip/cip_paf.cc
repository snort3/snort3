//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "protocols/packet.h"

#include "cip.h"
#include "cip_definitions.h"
#include "cip_module.h"
#include "cip_parsing.h"              // For ENIP constants

// PAF will skip over the ENIP Command and Length fields.
static const uint16_t ENIP_PAF_FIELD_SIZE = 4;

// ENIP Header + Interface Handle + Timeout
// that SendRRData and SendUnitData require.
static const uint32_t ENIP_MIN_USEFUL_PDU_SIZE = ENIP_HEADER_SIZE + 6;

using namespace snort;

inline uint16_t get_cip_small_pdus_limit(const Packet* p)
{
    if ( !p or !p->flow or !p->flow->gadget )
        return CIP_DEFAULT_SMALL_PDUS_LIMIT;

    const CipProtoConf* config = static_cast<const Cip*>(p->flow->gadget)->get_config();

    if (!config)
        return CIP_DEFAULT_SMALL_PDUS_LIMIT;

    return config->small_pdus_limit;
}

static inline void reset_states(cip_paf_data* pafdata)
{
    pafdata->paf_state = CIP_PAF_STATE__COMMAND_1;
    pafdata->enip_length = 0;
}

static StreamSplitter::Status flush_frame(const Packet* p, cip_paf_data* pafdata,
    uint32_t total_length, uint32_t* fp)
{
    const uint16_t small_pdus_limit = get_cip_small_pdus_limit(p);

    if (small_pdus_limit != 0)
    {
        if (total_length < ENIP_MIN_USEFUL_PDU_SIZE)
        {
            if (++pafdata->consecutive_small_pdus > small_pdus_limit)
            {
                ++cip_stats.small_pdu_aborts;
                pafdata->consecutive_small_pdus = 0;
                pafdata->bytes_seen = 0;
                reset_states(pafdata);
                return StreamSplitter::ABORT;
            }
        }
        else
            pafdata->consecutive_small_pdus = 0;
    }

    pafdata->bytes_seen = 0;
    *fp = total_length;
    pafdata->paf_state = CIP_PAF_STATE__COMMAND_1;
    return StreamSplitter::FLUSH;
}

/* Function: CIPPaf()

   Purpose: CIP PAF callback.
            Statefully inspects CIP traffic from the start of a session.
            Reads up until the length octet is found, then sets a flush point.
            The flushed PDU is a ENIP frame.
*/

static StreamSplitter::Status cip_paf(const Packet* p, cip_paf_data* pafdata,
    const uint8_t* data, uint32_t len, uint32_t* fp)
{
    uint32_t bytes_processed = 0;
    uint16_t command = 0;
    uint32_t total_length = 0;

    /* Process this packet 1 byte at a time */
    while (bytes_processed < len)
    {
        switch (pafdata->paf_state)
        {
        case CIP_PAF_STATE__COMMAND_1:
            command = *(data + bytes_processed);
            pafdata->paf_state = CIP_PAF_STATE__COMMAND_2;
            break;

        case CIP_PAF_STATE__COMMAND_2:
            command |= (*(data + bytes_processed) << 8);
            if (!enip_command_valid(command))
            {
                pafdata->bytes_seen += len;
                pafdata->paf_state = CIP_PAF_STATE__INVALID;
            } else
            {
                pafdata->bytes_seen = 0;
                pafdata->paf_state = CIP_PAF_STATE__LENGTH_1;
            }
            break;

        case CIP_PAF_STATE__LENGTH_1:
            pafdata->enip_length = *(data + bytes_processed);
            pafdata->paf_state = CIP_PAF_STATE__LENGTH_2;
            break;

        case CIP_PAF_STATE__LENGTH_2:
            pafdata->enip_length |= (*(data + bytes_processed) << 8);
            pafdata->paf_state = CIP_PAF_STATE__SET_FLUSH;
            break;

        case CIP_PAF_STATE__INVALID:
            if (pafdata->bytes_seen > CIP_MAX_OCTETS)
            {
                pafdata->bytes_seen = 0;
                reset_states(pafdata);
                return StreamSplitter::ABORT;
            }
            pafdata->paf_state = CIP_PAF_STATE__COMMAND_1;
            pafdata->enip_length = 0;
            return StreamSplitter::SEARCH;

        case CIP_PAF_STATE__SET_FLUSH:
            total_length = bytes_processed +
                pafdata->enip_length + (ENIP_HEADER_SIZE - ENIP_PAF_FIELD_SIZE);

            if (total_length > len)
            {
                pafdata->bytes_seen += len;
                pafdata->paf_state = CIP_PAF_STATE__INVALID;
            } else
                return flush_frame(p, pafdata, total_length, fp);
        break;
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
    state.bytes_seen = 0;
    state.consecutive_small_pdus = 0;
}

StreamSplitter::Status CipSplitter::scan(
    Packet* p, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t* fp)
{
    cip_paf_data* pfdata = &state;
    return cip_paf(p, pfdata, data, len, fp);
}
