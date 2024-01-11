//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb_paf.cc author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb_module.h"
#include "dce_smb_paf.h"
#include "dce_smb.h"
#include "trace/trace_api.h"
#include "utils/util.h"

namespace
{
inline void DCE2_SMB_PAF_SHIFT(uint64_t& x64, const uint8_t& x8)
{
    x64 <<= 8;
    x64 |= (uint64_t)x8;
}
}

using namespace snort;

/*********************************************************************
 * Function: DCE2_PafSmbIsValidNetbiosHdr()
 *
 * Purpose: Validates that the NetBIOS header is valid.  If in
 *          junk states, header type must be Session Message.
 *
 *********************************************************************/
static inline bool DCE2_PafSmbIsValidNetbiosHdr(uint32_t nb_hdr, bool junk, const SmbNtHdr* nt_hdr,
    uint32_t* nb_len)
{
    uint8_t type = (uint8_t)(nb_hdr >> 24);
    uint8_t bit = (uint8_t)((nb_hdr & 0x00ff0000) >> 16);
    uint32_t smb_id = nt_hdr ? SmbId(nt_hdr) : 0;
    uint32_t nbs_hdr = 0;

    if (junk)
    {
        if (type != NBSS_SESSION_TYPE__MESSAGE)
            return false;
    }
    else
    {
        switch (type)
        {
        case NBSS_SESSION_TYPE__MESSAGE:
        case NBSS_SESSION_TYPE__REQUEST:
        case NBSS_SESSION_TYPE__POS_RESPONSE:
        case NBSS_SESSION_TYPE__NEG_RESPONSE:
        case NBSS_SESSION_TYPE__RETARGET_RESPONSE:
        case NBSS_SESSION_TYPE__KEEP_ALIVE:
            break;
        default:
            return false;
        }
    }
    //The bit should be checked only for SMB1, because the length in NetBIOS header should not
    // exceed 0x1FFFF.
    //See [MS-SMB] 2.1 Transport. There is no such limit for SMB2 or SMB3
    if (smb_id == DCE2_SMB_ID)
    {
        if ((bit != 0x00) and (bit != 0x01))
            return false;
    }
    nbs_hdr = htonl(nb_hdr);

    if (smb_id == DCE2_SMB2_ID)
        *nb_len = NbssLen2((const NbssHdr*)&nbs_hdr);
    else
        *nb_len = NbssLen((const NbssHdr*)&nbs_hdr);

    return true;
}

/*********************************************************************
 * Function: DCE2_SmbPaf()
 *
 * Purpose: The DCE/RPC over SMB PAF callback.
 *          Inspects a byte at a time changing state and shifting
 *          bytes onto the 64bit nb_hdr member.  At state 3
 *          determines if NetBIOS header is valid and if so sets
 *          flush point.  If not valid goes to states 4-7 where
 *          there is the possibility that junk data was inserted
 *          before request/response.  Needs to validate SMB ID at
 *          this point.  At state 7 determines if NetBIOS header
 *          is valid and that the SMB ID is present.  Stays in
 *          state 7 until this is the case.
 *
 *********************************************************************/
static StreamSplitter::Status dce2_smb_paf(DCE2_PafSmbData* ss, Flow* flow, const uint8_t* data,
    uint32_t len, uint32_t, uint32_t* fp)
{
    uint32_t n = 0;
    StreamSplitter::Status ps = StreamSplitter::SEARCH;
    const SmbNtHdr* nt_hdr = nullptr;
    uint32_t nb_len = 0;

    DCE2_SsnData* sd = get_dce2_session_data(flow);

    if ( dce2_paf_abort(sd) )
    {
        return StreamSplitter::ABORT;
    }

    while (n < len)
    {
        switch (ss->paf_state)
        {
        case DCE2_PAF_SMB_STATES__0:
            ss->nb_hdr = (uint64_t)data[n];
            ss->paf_state = (DCE2_PafSmbStates)(((int)ss->paf_state) + 1);
            break;
        case DCE2_PAF_SMB_STATES__3:
            DCE2_SMB_PAF_SHIFT(ss->nb_hdr, data[n]);
            //(data + n + 1) points to the SMB header protocol identifier
            //(0xFF,'SMB' or 0xFE,'SMB'), which follows the NetBIOS header
            if (len >= DCE2_SMB_ID_SIZE + n + 1) // NetBIOS header and 4 bytes SMB header
                nt_hdr = (const SmbNtHdr*)(data + n + 1);
            if (DCE2_PafSmbIsValidNetbiosHdr((uint32_t)ss->nb_hdr, false, nt_hdr, &nb_len))
            {
                *fp = (nb_len + sizeof(NbssHdr) + n) - ss->paf_state;
                ss->paf_state = DCE2_PAF_SMB_STATES__0;
                return StreamSplitter::FLUSH;
            }

            ss->paf_state = (DCE2_PafSmbStates)(((int)ss->paf_state) + 1);
            break;
        case DCE2_PAF_SMB_STATES__7:
            DCE2_SMB_PAF_SHIFT(ss->nb_hdr, data[n]);

            //(data + n - sizeof(DCE2_SMB_ID) + 1) points to the smb_idf field
            //in SmbNtHdr (0xFF,'SMB' or 0xFE,'SMB'), which follows the NetBIOS header
            nt_hdr = (const SmbNtHdr*)(data + n - DCE2_SMB_ID_SIZE + 1);
            //ss->nb_hdr is the value to 4 bytes of NetBIOS header + 4 bytes of
            //SMB header protocol identifier . Right shift by 32 bits to get the value of NetBIOS
            // header
            if (!DCE2_PafSmbIsValidNetbiosHdr((uint32_t)(ss->nb_hdr >> 32), true, nt_hdr, &nb_len))
            {
                break;
            }
            if (((uint32_t)ss->nb_hdr != DCE2_SMB_ID)
                && ((uint32_t)ss->nb_hdr != DCE2_SMB2_ID))
            {
                break;
            }

            *fp = (nb_len + sizeof(NbssHdr) + n) - ss->paf_state;
            ss->paf_state = DCE2_PAF_SMB_STATES__0;

            return StreamSplitter::FLUSH;
        default:
            DCE2_SMB_PAF_SHIFT(ss->nb_hdr, data[n]);
            ss->paf_state = (DCE2_PafSmbStates)(((int)ss->paf_state) + 1);
            break;
        }

        n++;
    }

    return ps;
}

Dce2SmbSplitter::Dce2SmbSplitter(bool c2s) :   StreamSplitter(c2s)
{
    state.paf_state = DCE2_PAF_SMB_STATES__0;
    state.nb_hdr = 0;
}

StreamSplitter::Status Dce2SmbSplitter::scan(
    Packet* pkt, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    DCE2_PafSmbData* pfdata = &state;
    StreamSplitter::Status ps = dce2_smb_paf(pfdata, pkt->flow, data, len, flags, fp);
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, pkt,
        "Dce2SmbSplitter scan with length %u, status %d and fp %u\n", len, ps, *fp);
    return ps;
}

