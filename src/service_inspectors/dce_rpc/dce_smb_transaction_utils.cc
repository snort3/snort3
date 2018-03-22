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

// dce_smb_transaction_utils.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

// Smb transaction commands utils

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb_transaction_utils.h"

#define TRANS_NM_PIPE_0       (0)
#define TRANS_NM_PIPE_1       (TRANS_NM_PIPE_0+7)
#define TRANS_NM_PIPE_2       (TRANS_NM_PIPE_1+1)
#define TRANS_NM_PIPE_3       (TRANS_NM_PIPE_2+1)
#define TRANS_NM_PIPE_4       (TRANS_NM_PIPE_3+5)
#define TRANS_NM_PIPE_5       (TRANS_NM_PIPE_4+5)
#define TRANS_NM_PIPE_6       (TRANS_NM_PIPE_5+1)
#define TRANS_NM_PIPE_7       (TRANS_NM_PIPE_6+5)
#define TRANS_NM_PIPE_8       (TRANS_NM_PIPE_7+3)
#define TRANS_NM_PIPE_9       (TRANS_NM_PIPE_8+6)
#define TRANS_NM_PIPE_FS      (TRANS_NM_PIPE_9+1)
#define TRANS_NM_PIPE_DONE    (TRANS_NM_PIPE_FS+1)

static const DCE2_SmbFsm dce2_samba_pipe_fsm[] =
{
    // Normal sequence
    { '\\', TRANS_NM_PIPE_0+1, TRANS_NM_PIPE_FS },
    { 'P', TRANS_NM_PIPE_0+2, TRANS_NM_PIPE_FS },
    { 'I', TRANS_NM_PIPE_0+3, TRANS_NM_PIPE_FS },
    { 'P', TRANS_NM_PIPE_0+4, TRANS_NM_PIPE_FS },
    { 'E', TRANS_NM_PIPE_0+5, TRANS_NM_PIPE_FS },
    { '\\', TRANS_NM_PIPE_0+6, TRANS_NM_PIPE_1 },
    { '\0', TRANS_NM_PIPE_DONE, TRANS_NM_PIPE_2 },

    // Win98
    { '\0', TRANS_NM_PIPE_DONE, TRANS_NM_PIPE_FS },

    { 'W', TRANS_NM_PIPE_2+1, TRANS_NM_PIPE_5 },

    { 'K', TRANS_NM_PIPE_3+1, TRANS_NM_PIPE_4 },
    { 'S', TRANS_NM_PIPE_3+2, TRANS_NM_PIPE_FS },
    { 'S', TRANS_NM_PIPE_3+3, TRANS_NM_PIPE_FS },
    { 'V', TRANS_NM_PIPE_3+4, TRANS_NM_PIPE_FS },
    { 'C', TRANS_NM_PIPE_9, TRANS_NM_PIPE_FS },

    { 'I', TRANS_NM_PIPE_4+1, TRANS_NM_PIPE_FS },
    { 'N', TRANS_NM_PIPE_4+2, TRANS_NM_PIPE_FS },
    { 'R', TRANS_NM_PIPE_4+3, TRANS_NM_PIPE_FS },
    { 'E', TRANS_NM_PIPE_4+4, TRANS_NM_PIPE_FS },
    { 'G', TRANS_NM_PIPE_9, TRANS_NM_PIPE_FS },

    { 'S', TRANS_NM_PIPE_5+1, TRANS_NM_PIPE_8 },

    { 'R', TRANS_NM_PIPE_6+1, TRANS_NM_PIPE_5 },
    { 'V', TRANS_NM_PIPE_6+2, TRANS_NM_PIPE_FS },
    { 'S', TRANS_NM_PIPE_6+3, TRANS_NM_PIPE_FS },
    { 'V', TRANS_NM_PIPE_6+4, TRANS_NM_PIPE_FS },
    { 'C', TRANS_NM_PIPE_9, TRANS_NM_PIPE_FS },

    { 'A', TRANS_NM_PIPE_7+1, TRANS_NM_PIPE_FS },
    { 'M', TRANS_NM_PIPE_7+2, TRANS_NM_PIPE_FS },
    { 'R', TRANS_NM_PIPE_9, TRANS_NM_PIPE_FS },

    { 'L', TRANS_NM_PIPE_8+1, TRANS_NM_PIPE_FS },
    { 'S', TRANS_NM_PIPE_8+2, TRANS_NM_PIPE_FS },
    { 'A', TRANS_NM_PIPE_8+3, TRANS_NM_PIPE_FS },
    { 'R', TRANS_NM_PIPE_8+4, TRANS_NM_PIPE_FS },
    { 'P', TRANS_NM_PIPE_8+5, TRANS_NM_PIPE_FS },
    { 'C', TRANS_NM_PIPE_9, TRANS_NM_PIPE_FS },

    { '\0', TRANS_NM_PIPE_DONE, TRANS_NM_PIPE_FS },

    { 0, TRANS_NM_PIPE_FS, TRANS_NM_PIPE_FS }
};

/*********************************************************************
 * Private functions
 ********************************************************************/

/********************************************************************
 * Function: DCE2_SmbCheckTransDataParams()
 *
 * Purpose:
 *  Ensures that the data size reported in an SMB command is kosher.
 *  Note the 32 bit values are because of the NtTransact command
 *  though it's currently not checked.
 *
 * Arguments:
 *  const uint8_t *   - pointer to start of SMB header where offset is
 *                      taken from.
 *  const uint8_t *   - current pointer - should be right after command
 *                      structure.
 *  const uint32_t    - remaining data left in PDU from current pointer.
 *  const uint16_t    - the byte count
 *  const uint32_t    - reported data count
 *  const uint32_t    - reported data offset
 *  const uint32_t    - reported parameter count
 *  const uint32_t    - reported parameter offset
 *
 * Returns:
 *  DCE2_Ret -  DCE2_RET__ERROR if data should not be processed
 *              DCE2_RET__SUCCESS if data can be processed
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbCheckTransDataParams(
    const uint8_t* smb_hdr_ptr, const uint8_t* nb_ptr, const uint32_t nb_len,
    const uint16_t bcc, const uint32_t dcnt, const uint32_t doff,
    const uint32_t pcnt, const uint32_t poff)
{
    const uint8_t* doffset = smb_hdr_ptr + doff;
    const uint8_t* poffset = smb_hdr_ptr + poff;
    const uint8_t* nb_end = nb_ptr + nb_len;

    if (bcc < ((uint64_t)dcnt + pcnt))
        dce_alert(GID_DCE2, DCE2_SMB_BCC_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);

    // Check data offset out of bounds
    if ((doffset > nb_end) || (doffset < smb_hdr_ptr))
    {
        // Beyond data left or wrap
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
        return DCE2_RET__ERROR;
    }

    // Check data offset in bounds but backwards
    // Only check if the data count is non-zero
    if ((dcnt != 0) && (doffset < nb_ptr))
    {
        // Not necessarily and error if the offset puts the data
        // before or in the command structure.
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
    }

    if (dcnt > (nb_end - doffset))            // beyond data left
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
        return DCE2_RET__ERROR;
    }

    // Check parameter offset out of bounds
    if ((poffset > nb_end) || (poffset < smb_hdr_ptr))
    {
        // Beyond data left or wrap
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
        return DCE2_RET__ERROR;
    }

    // Check parameter offset in bounds but backwards
    // Only check if the parameter count is non-zero
    if ((pcnt != 0) && (poffset < nb_ptr))
    {
        // Not necessarily and error if the offset puts the data
        // before or in the command structure.
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
    }

    if (pcnt > (nb_end - poffset))            // beyond data left
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbCheckTotalCount()
 *
 * Purpose:
 *  Validates the advertised total data/param count.  Makes sure the
 *  current count isn't greater than total count, that the
 *  displacement + count isn't greater than the total data count and
 *  that the total data count isn't zero.  Mainly relevant to Write Raw,
 *  Transaction and Transaction Secondary commands.
 *
 * Arguments:
 *  const uint32_t    - total data count
 *  const uint32_t    - data count/size
 *  const uint32_t    - data displacement
 *
 * Returns:
 *  DCE2_Ret - DCE2_RET__SUCCESS if all is ok
 *             DCE2_RET__ERROR if any of the checks fail.
 *
 ********************************************************************/
DCE2_Ret DCE2_SmbCheckTotalCount(const uint32_t tcnt, const uint32_t cnt, const uint32_t
    disp)
{
    DCE2_Ret ret = DCE2_RET__SUCCESS;

    if (cnt > tcnt)
    {
        dce_alert(GID_DCE2, DCE2_SMB_TDCNT_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
        ret = DCE2_RET__ERROR;
    }

    if (((uint64_t)disp + cnt) > tcnt)
    {
        dce_alert(GID_DCE2, DCE2_SMB_DSENT_GT_TDCNT, (dce2CommonStats*)&dce2_smb_stats);
        ret = DCE2_RET__ERROR;
    }

    return ret;
}

// Validates Name for Samba Transaction requests
DCE2_Ret DCE2_SmbTransactionGetName(const uint8_t* nb_ptr,
    uint32_t nb_len, uint16_t bcc, bool unicode)
{
    if ((nb_len == 0) || (bcc == 0))
        return DCE2_RET__ERROR;

    if (bcc < nb_len)
        nb_len = bcc;

    if (unicode)
        DCE2_MOVE(nb_ptr, nb_len, 1);  // One byte pad for unicode

    uint8_t increment = unicode ? 2 : 1;
    int state = TRANS_NM_PIPE_0;
    while ((nb_len >= increment) && (state < TRANS_NM_PIPE_FS))
    {
        if (dce2_samba_pipe_fsm[state].input == toupper((int)nb_ptr[0]))
        {
            if (unicode && (nb_ptr[1] != 0))
                break;
            state = dce2_samba_pipe_fsm[state].next_state;
            DCE2_MOVE(nb_ptr, nb_len, increment);
        }
        else
        {
            state = dce2_samba_pipe_fsm[state].fail_state;
        }
    }

    switch (state)
    {
    case TRANS_NM_PIPE_DONE:
        break;
    case TRANS_NM_PIPE_FS:
    default:
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbValidateTransactionSent()
 *
 * Purpose:
 *  Checks that amount sent plus current amount is not greater than
 *  the total count expected.
 *
 * Arguments:
 *  const uint32_t    - amount of data sent so far
 *  const uint32_t    - reported total data count
 *  const uint32_t    - reported data count
 *  const uint32_t    - amount of parameters sent so far
 *  const uint32_t    - reported total parameter count
 *  const uint32_t    - reported parameter count
 *
 * Returns:
 *  DCE2_Ret -  DCE2_RET__ERROR if data should not be processed
 *              DCE2_RET__SUCCESS if data can be processed
 *
 ********************************************************************/
DCE2_Ret DCE2_SmbValidateTransactionSent(
    uint32_t dsent, uint32_t dcnt, uint32_t tdcnt,
    uint32_t psent, uint32_t pcnt, uint32_t tpcnt)
{
    if (((dsent + dcnt) > tdcnt) || ((psent + pcnt) > tpcnt))
    {
        if ((dsent + dcnt) > tdcnt)
        {
            dce_alert(GID_DCE2, DCE2_SMB_DSENT_GT_TDCNT, (dce2CommonStats*)&dce2_smb_stats);
        }

        if ((psent + pcnt) > tpcnt)
        {
            dce_alert(GID_DCE2, DCE2_SMB_DSENT_GT_TDCNT, (dce2CommonStats*)&dce2_smb_stats);
        }

        // Samba throws out entire transaction and Windows seems to hang in
        // limbo forever and never responds, so stop looking
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbValidateTransactionFields()
 *
 * Purpose:
 *  Wrapper that calls DCE2_SmbCheckTotalCount() for total parameter
 *  count and total data count and DCE2_SmbCheckTransDataParams()
 *
 * Arguments:
 *  const uint8_t *   - pointer to start of SMB header where offset is
 *                      taken from.
 *  const uint8_t *   - current pointer - should be right after command
 *                      structure.
 *  const uint32_t    - remaining data left in PDU from current pointer.
 *  const uint16_t    - the byte count
 *  const uint32_t    - reported total data count
 *  const uint32_t    - reported total parameter count
 *  const uint32_t    - reported data count
 *  const uint32_t    - reported data offset
 *  const uint32_t    - reported data displacement
 *  const uint32_t    - reported parameter count
 *  const uint32_t    - reported parameter offset
 *  const uint32_t    - reported parameter displacement
 *
 * Returns:
 *  DCE2_Ret -  DCE2_RET__ERROR if data should not be processed
 *              DCE2_RET__SUCCESS if data can be processed
 *
 ********************************************************************/
DCE2_Ret DCE2_SmbValidateTransactionFields(
    const uint8_t* smb_hdr_ptr,
    const uint8_t* nb_ptr, const uint32_t nb_len, const uint16_t bcc,
    const uint32_t tdcnt, const uint32_t tpcnt,
    const uint32_t dcnt, const uint32_t doff, const uint32_t ddisp,
    const uint32_t pcnt, const uint32_t poff, const uint32_t pdisp)
{
    if (DCE2_SmbCheckTotalCount(tdcnt, dcnt, ddisp) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    if (DCE2_SmbCheckTotalCount(tpcnt, pcnt, pdisp) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    if (DCE2_SmbCheckTransDataParams(smb_hdr_ptr,
        nb_ptr, nb_len, bcc, dcnt, doff, pcnt, poff) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    return DCE2_RET__SUCCESS;
}

DCE2_Ret DCE2_SmbBufferTransactionData(DCE2_SmbTransactionTracker* ttracker,
    const uint8_t* data_ptr, uint16_t dcnt, uint16_t ddisp)
{
    snort::Profile profile(dce2_smb_pstat_smb_req);

    if (ttracker->dbuf == nullptr)
    {
        /* Buf size should be the total data count we need */
        ttracker->dbuf = DCE2_BufferNew(ttracker->tdcnt, 0);
    }

    if (DCE2_BufferAddData(ttracker->dbuf, data_ptr, dcnt, ddisp,
        DCE2_BUFFER_MIN_ADD_FLAG__IGNORE) != DCE2_RET__SUCCESS)
    {
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

DCE2_Ret DCE2_SmbBufferTransactionParameters(DCE2_SmbTransactionTracker* ttracker,
    const uint8_t* param_ptr, uint16_t pcnt, uint16_t pdisp)
{
    snort::Profile profile(dce2_smb_pstat_smb_req);

    if (ttracker->pbuf == nullptr)
    {
        /* Buf size should be the total data count we need */
        ttracker->pbuf = DCE2_BufferNew(ttracker->tpcnt, 0);
    }

    if (DCE2_BufferAddData(ttracker->pbuf, param_ptr, pcnt, pdisp,
        DCE2_BUFFER_MIN_ADD_FLAG__IGNORE) != DCE2_RET__SUCCESS)
    {
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}
