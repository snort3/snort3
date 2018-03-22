//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "dce_smb_paf.h"

#include "dce_smb.h"

using namespace snort;

/*********************************************************************
 * Function: DCE2_PafSmbIsValidNetbiosHdr()
 *
 * Purpose: Validates that the NetBIOS header is valid.  If in
 *          junk states, header type must be Session Message.
 *
 *********************************************************************/
static inline bool DCE2_PafSmbIsValidNetbiosHdr(uint32_t nb_hdr, bool junk)
{
    uint8_t type = (uint8_t)(nb_hdr >> 24);
    uint8_t bit = (uint8_t)((nb_hdr & 0x00ff0000) >> 16);

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

    if ((bit != 0x00) && (bit != 0x01))
        return false;

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
    uint32_t nb_hdr;
    uint32_t nb_len;
    DCE2_SmbSsnData* sd = get_dce2_smb_session_data(flow);

    if (dce2_paf_abort(flow, (DCE2_SsnData*)sd))
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
            if (DCE2_PafSmbIsValidNetbiosHdr((uint32_t)ss->nb_hdr, false))
            {
                nb_hdr = htonl((uint32_t)ss->nb_hdr);
                nb_len = NbssLen((const NbssHdr*)&nb_hdr);
                *fp = (nb_len + sizeof(NbssHdr) + n) - ss->paf_state;
                ss->paf_state = DCE2_PAF_SMB_STATES__0;
                return StreamSplitter::FLUSH;
            }
          
            ss->paf_state = (DCE2_PafSmbStates)(((int)ss->paf_state) + 1);
            break;
        case DCE2_PAF_SMB_STATES__7:
            DCE2_SMB_PAF_SHIFT(ss->nb_hdr, data[n]);

            if (!DCE2_PafSmbIsValidNetbiosHdr((uint32_t)(ss->nb_hdr >> 32), true))
            {
                break;
            }
            if (((uint32_t)ss->nb_hdr != DCE2_SMB_ID)
                && ((uint32_t)ss->nb_hdr != DCE2_SMB2_ID))
            {
                break;
            }

            nb_hdr = htonl((uint32_t)(ss->nb_hdr >> 32));
            nb_len = NbssLen((const NbssHdr*)&nb_hdr);
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

Dce2SmbSplitter::Dce2SmbSplitter(bool c2s) : StreamSplitter(c2s)
{
    state.paf_state = DCE2_PAF_SMB_STATES__0;
    state.nb_hdr = 0;
}

StreamSplitter::Status Dce2SmbSplitter::scan(
    Flow* flow, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    DCE2_PafSmbData* pfdata = &state;
    return dce2_smb_paf(pfdata, flow, data, len, flags, fp);
}

