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

// smb_message.cc author Rashmi Pitre <rrp@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb.h"

#include "detection/detect.h"
#include "file_api/file_service.h"
#include "protocols/packet.h"
#include "utils/util.h"
#include "packet_io/active.h"

#include "dce_smb.h"
#include "dce_smb_commands.h"
#include "dce_smb_module.h"
#include "dce_smb_paf.h"
#include "dce_smb_transaction.h"
#include "dce_smb_utils.h"
#include "dce_smb2.h"

using namespace snort;

/********************************************************************
 * Global variables
 ********************************************************************/
typedef DCE2_Ret (* DCE2_SmbComFunc)(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);

static DCE2_SmbComFunc smb_com_funcs[SMB_MAX_NUM_COMS];
static uint8_t smb_wcts[SMB_MAX_NUM_COMS][2][32];
static uint16_t smb_bccs[SMB_MAX_NUM_COMS][2][2];
static DCE2_SmbComFunc smb_chain_funcs[DCE2_POLICY__MAX][SMB_ANDX_COM__MAX][SMB_MAX_NUM_COMS];
static bool smb_deprecated_coms[SMB_MAX_NUM_COMS];
static bool smb_unusual_coms[SMB_MAX_NUM_COMS];
static SmbAndXCom smb_chain_map[SMB_MAX_NUM_COMS];

/********************************************************************
 * Function: DCE2_SmbIsRawData()
 *
 * Purpose:
 *  To determine if the current state is such that a raw read or
 *  write is expected.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - Pointer to SMB session data.
 *
 * Returns:
 *  bool -  True if expecting raw data.
 *          False if not.
 *
 ********************************************************************/
static inline bool DCE2_SmbIsRawData(DCE2_SmbSsnData* ssd)
{
    return (ssd->pdu_state == DCE2_SMB_PDU_STATE__RAW_DATA);
}

/********************************************************************
 * Function: DCE2_SmbCheckAndXOffset()
 *
 * Purpose:
 *  Validates that the AndXOffset is within bounds of the remaining
 *  data we have to work with.
 *
 * Arguments:
 *  uint8_t * - pointer to where the offset would take us.
 *  uint8_t * - pointer to bound offset
 *  uint8_t * - length of data where offset should be within
 *
 * Returns:
 *  DCE2_RET__SUCCESS - Offset is okay.
 *  DCE2_RET__ERROR   - Offset is bad.
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_SmbCheckAndXOffset(const uint8_t* off_ptr, const uint8_t* start_bound,
    const uint32_t length)
{
    /* Offset should not point within data we just looked at or be equal to
     * or beyond the length of the NBSS length left */
    if ((off_ptr < start_bound) ||
        (off_ptr > (start_bound + length)))
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);

        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbGetIgnorePtr()
 *
 * Returns a pointer to the bytes we are ignoring on client or
 * server side.  Bytes are ignored if they are associated with
 * data we are not interested in.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - Pointer to SMB session data.
 *
 * Returns:
 *  uint32_t *
 *      Pointer to the client or server ignore bytes.
 *
 ********************************************************************/
static inline uint32_t* DCE2_SmbGetIgnorePtr(DCE2_SmbSsnData* ssd)
{
    if (DCE2_SsnFromServer(ssd->sd.wire_pkt))
        return &ssd->srv_ignore_bytes;
    return &ssd->cli_ignore_bytes;
}

/********************************************************************
 * Function: DCE2_SmbGetDataState()
 *
 * Returns a pointer to the data state of client or server
 *
 * Arguments:
 *  DCE2_SmbSsnData * - Pointer to SMB session data.
 *
 * Returns:
 *  DCE2_SmbDataState *
 *      Pointer to the client or server data state.
 *
 ********************************************************************/
static inline DCE2_SmbDataState* DCE2_SmbGetDataState(DCE2_SmbSsnData* ssd)
{
    if (DCE2_SsnFromServer(ssd->sd.wire_pkt))
        return &ssd->srv_data_state;
    return &ssd->cli_data_state;
}

/********************************************************************
 * Function: DCE2_SmbSetValidWordCount()
 *
 * Purpose:
 *  Initializes global data for valid word counts for supported
 *  SMB command requests and responses.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the valid word count
 *
 * Returns: None
 *
 ********************************************************************/
static inline void DCE2_SmbSetValidWordCount(uint8_t com,
    uint8_t resp, uint8_t wct)
{
    smb_wcts[com][resp][wct/8] |= (1 << (wct % 8));
}

/********************************************************************
 * Function: DCE2_SmbIsValidWordCount()
 *
 * Purpose:
 *  Checks if a word count is valid for a given command request
 *  or response.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the word count to validate
 *
 * Returns:
 *  bool - true if valid, false if not valid.
 *
 ********************************************************************/
static inline bool DCE2_SmbIsValidWordCount(uint8_t com,
    uint8_t resp, uint8_t wct)
{
    return (smb_wcts[com][resp][wct/8] & (1 << (wct % 8))) ? true : false;
}

/********************************************************************
 * Function: DCE2_SmbSetValidByteCount()
 *
 * Purpose:
 *  Initializes global data for valid byte counts as a range for
 *  supported SMB command requests and responses.
 *  Since a byte count is 2 bytes, a 4 byte type is used to store
 *  the range.  The maximum is in the most significant 2 bytes and
 *  the minimum in the least significant 2 bytes.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the minimum word count that is valid
 *  uint8_t - the maximum word count that is valid
 *
 * Returns: None
 *
 ********************************************************************/
static inline void DCE2_SmbSetValidByteCount(uint8_t com,
    uint8_t resp, uint16_t min, uint16_t max)
{
    smb_bccs[com][resp][0] = min;
    smb_bccs[com][resp][1] = max;
}

/********************************************************************
 * Function: DCE2_SmbIsValidByteCount()
 *
 * Purpose:
 *  Checks if a byte count is valid for a given command request
 *  or response.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *  uint8_t - the byte count to validate
 *
 * Returns:
 *  bool - true if valid, false if not valid.
 *
 ********************************************************************/
static inline bool DCE2_SmbIsValidByteCount(uint8_t com,
    uint8_t resp, uint16_t bcc)
{
    return ((bcc < smb_bccs[com][resp][0])
           || (bcc > smb_bccs[com][resp][1])) ? false : true;
}

// This function is obviously deficient.  Need to do a lot more
// testing, research and reading MS-CIFS, MS-SMB and MS-ERREF.
static bool SmbError(const SmbNtHdr* hdr)
{
    if (SmbStatusNtCodes(hdr))
    {
        /* Nt status codes are being used.  First 2 bits indicate
         * severity. */
        switch (SmbNtStatusSeverity(hdr))
        {
        case SMB_NT_STATUS_SEVERITY__SUCCESS:
        case SMB_NT_STATUS_SEVERITY__INFORMATIONAL:
        case SMB_NT_STATUS_SEVERITY__WARNING:
            return false;
        case SMB_NT_STATUS_SEVERITY__ERROR:
        default:
            break;
        }
    }
    else
    {
        switch (SmbStatusClass(hdr))
        {
        case SMB_ERROR_CLASS__SUCCESS:
            return false;
        case SMB_ERROR_CLASS__ERRDOS:
            if (SmbStatusCode(hdr) == SMB_ERRDOS__MORE_DATA)
                return false;
            break;
        case SMB_ERROR_CLASS__ERRSRV:
        case SMB_ERROR_CLASS__ERRHRD:
        case SMB_ERROR_CLASS__ERRCMD:
        default:
            break;
        }
    }

    return true;
}

static bool SmbBrokenPipe(const SmbNtHdr* hdr)
{
    if (SmbStatusNtCodes(hdr))
    {
        uint32_t nt_status = SmbNtStatus(hdr);
        if ((nt_status == SMB_NT_STATUS__PIPE_BROKEN)
            || (nt_status == SMB_NT_STATUS__PIPE_DISCONNECTED))
            return true;
    }
    else
    {
        if (SmbStatusClass(hdr) == SMB_ERROR_CLASS__ERRDOS)
        {
            uint16_t smb_status = SmbStatusCode(hdr);
            if ((smb_status == SMB_ERRDOS__BAD_PIPE)
                || (smb_status == SMB_ERRDOS__PIPE_NOT_CONNECTED))
                return true;
        }
    }

    return false;
}

/********************************************************************
 * Function: DCE2_IgnoreJunkData()
 *
 * Purpose:
 *   An evasion technique can be to put a bunch of junk data before
 *   the actual SMB request and it seems the MS implementation has
 *   no problem with it and seems to just ignore the data.  This
 *   function attempts to move past all the junk to get to the
 *   actual NetBIOS message request.
 *
 * Arguments:
 *   const uint8_t *  - pointer to the current position in the data
 *      being inspected
 *   uint16_t  -  the amount of data left to look at
 *   uint32_t  -  the amount of data to ignore if there doesn't seem
 *      to be any junk data.  Just use the length as if the bad
 *      NetBIOS header was good.
 *
 * Returns:
 *    uint32_t - the amount of bytes to ignore as junk.
 *
 ********************************************************************/
static uint32_t DCE2_IgnoreJunkData(const uint8_t* data_ptr, uint16_t data_len,
    uint32_t assumed_nb_len)
{
    const uint8_t* tmp_ptr = data_ptr;
    uint32_t ignore_bytes = 0;

    /* Try to find \xffSMB and go back 8 bytes to beginning
     * of what should be a Netbios header with type Session
     * Message (\x00) - do appropriate buffer checks to make
     * sure the index is in bounds. Ignore all intervening
     * bytes */

    while ((tmp_ptr + sizeof(uint32_t)) <= (data_ptr + data_len))
    {
        if ((SmbId((const SmbNtHdr*)tmp_ptr) == DCE2_SMB_ID)
            || (SmbId((const SmbNtHdr*)tmp_ptr) == DCE2_SMB2_ID))
        {
            break;
        }

        tmp_ptr++;
    }

    if ((tmp_ptr + sizeof(uint32_t)) > (data_ptr + data_len))
    {
        ignore_bytes = data_len;
    }
    else
    {
        if ((tmp_ptr - sizeof(NbssHdr)) > data_ptr)
            ignore_bytes = (tmp_ptr - data_ptr) - sizeof(NbssHdr);
        else  /* Just ignore whatever the bad NB header had as a length */
            ignore_bytes = assumed_nb_len;
    }

    return ignore_bytes;
}

/********************************************************************
 * Function: DCE2_SmbHdrChecks()
 *
 * Checks some relevant fields in the header to make sure they're
 * sane.
 * Side effects are potential alerts for anomalous behavior.
 *
 * Arguments:
 *  DCE2_SmbSsnData *
 *      Pointer to the session data structure.
 *  SmbNtHdr *
 *      Pointer to the header struct laid over the packet data.
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__IGNORE if we should continue processing, but
 *          ignore data because of the error.
 *      DCE2_RET__SUCCESS if we should continue processing.
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbHdrChecks(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr)
{
    Packet* p = ssd->sd.wire_pkt;
    bool is_seg_buf = DCE2_SmbIsSegBuffer(ssd, (const uint8_t*)smb_hdr);

    if ((DCE2_SsnFromServer(p) && (SmbType(smb_hdr) == SMB_TYPE__REQUEST)) ||
        (DCE2_SsnFromClient(p) && (SmbType(smb_hdr) == SMB_TYPE__RESPONSE)))
    {
        if (is_seg_buf)
            DCE2_SmbSegAlert(ssd, DCE2_SMB_BAD_TYPE);
        else
            dce_alert(GID_DCE2, DCE2_SMB_BAD_TYPE, (dce2CommonStats*)&dce2_smb_stats);

        // Continue looking at traffic.  Neither Windows nor Samba seem
        // to care, or even look at this flag
    }

    if ((SmbId(smb_hdr) != DCE2_SMB_ID)
        && (SmbId(smb_hdr) != DCE2_SMB2_ID))
    {
        if (is_seg_buf)
            DCE2_SmbSegAlert(ssd, DCE2_SMB_BAD_ID);
        else
            dce_alert(GID_DCE2, DCE2_SMB_BAD_ID, (dce2CommonStats*)&dce2_smb_stats);

        return DCE2_RET__IGNORE;
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbGetMinByteCount()
 *
 * Purpose:
 *  Returns the minimum byte count for the given command request
 *  or response.
 *
 * Arguments:
 *  uint8_t - the SMB command code
 *  uint8_t - SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
 *
 * Returns:
 *  uint16_t - the minimum byte count
 *
 ********************************************************************/
static inline uint16_t DCE2_SmbGetMinByteCount(uint8_t com, uint8_t resp)
{
    return smb_bccs[com][resp][0];
}

static DCE2_SmbRequestTracker* DCE2_SmbFindRequestTracker(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr)
{
    uint16_t uid = SmbUid(smb_hdr);
    uint16_t tid = SmbTid(smb_hdr);
    uint16_t pid = SmbPid(smb_hdr);
    uint16_t mid = SmbMid(smb_hdr);

    Profile profile(dce2_smb_pstat_smb_req);

    DCE2_SmbRequestTracker* tmp_rtracker = &ssd->rtracker;
    int smb_com = SmbCom(smb_hdr);
    switch (smb_com)
    {
    case SMB_COM_TRANSACTION_SECONDARY:
        smb_com = SMB_COM_TRANSACTION;
        break;
    case SMB_COM_TRANSACTION2_SECONDARY:
        smb_com = SMB_COM_TRANSACTION2;
        break;
    case SMB_COM_NT_TRANSACT_SECONDARY:
        smb_com = SMB_COM_NT_TRANSACT;
        break;
    case SMB_COM_WRITE_COMPLETE:
        smb_com = SMB_COM_WRITE_RAW;
        break;
    default:
        break;
    }

    DCE2_SmbRequestTracker* first_rtracker = nullptr;
    DCE2_SmbRequestTracker* win_rtracker = nullptr;
    DCE2_SmbRequestTracker* first_mid_rtracker = nullptr;
    DCE2_SmbRequestTracker* ret_rtracker = nullptr;
    while (tmp_rtracker != nullptr)
    {
        if ((tmp_rtracker->mid == (int)mid) && (tmp_rtracker->smb_com == smb_com))
        {
            // This is the normal case except for SessionSetupAndX and
            // TreeConnect/TreeConnectAndX which will fall into the
            // default case below.
            if ((tmp_rtracker->pid == pid) && (tmp_rtracker->uid == uid)
                && (tmp_rtracker->tid == tid))
            {
                ret_rtracker = tmp_rtracker;
            }
            else
            {
                switch (smb_com)
                {
                case SMB_COM_TRANSACTION:
                case SMB_COM_TRANSACTION2:
                case SMB_COM_NT_TRANSACT:
                case SMB_COM_TRANSACTION_SECONDARY:
                case SMB_COM_TRANSACTION2_SECONDARY:
                case SMB_COM_NT_TRANSACT_SECONDARY:
                    // These should conform to above
                    break;
                default:
                    if (tmp_rtracker->pid == pid)
                        ret_rtracker = tmp_rtracker;
                    break;
                }
            }

            if (ret_rtracker != nullptr)
            {
                return ret_rtracker;
            }

            // Take the first one where the PIDs also match
            // in the case of the Transacts above
            if ((tmp_rtracker->pid == pid) && (win_rtracker == nullptr))
                win_rtracker = tmp_rtracker;

            // Set this to the first matching request in the queue
            // where the Mid matches.  Don't set for Windows if from
            // client since PID/MID are necessary
            if (((DCE2_SmbType(ssd) == SMB_TYPE__RESPONSE)
                || !DCE2_SsnIsWindowsPolicy(&ssd->sd))
                && first_mid_rtracker == nullptr)
            {
                first_mid_rtracker = tmp_rtracker;
            }
        }

        // Set the first one we see for early Samba versions
        if ((first_rtracker == nullptr) && (tmp_rtracker->mid != DCE2_SENTINEL)
            && (tmp_rtracker->smb_com == smb_com))
            first_rtracker = tmp_rtracker;

        // Look at the next request in the queue
        if (tmp_rtracker == &ssd->rtracker)
            tmp_rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueFirst(ssd->rtrackers);
        else
            tmp_rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueNext(ssd->rtrackers);
    }

    DCE2_Policy policy = DCE2_SsnGetPolicy(&ssd->sd);
    switch (policy)
    {
    case DCE2_POLICY__SAMBA_3_0_20:
    case DCE2_POLICY__SAMBA_3_0_22:
        ret_rtracker = first_rtracker;
        break;
    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
        ret_rtracker = first_mid_rtracker;
        break;
    case DCE2_POLICY__WIN2000:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
        if (win_rtracker != nullptr)
            ret_rtracker = win_rtracker;
        else
            ret_rtracker = first_mid_rtracker;
        break;
    default:
        assert(false);
        break;
    }

    return ret_rtracker;
}

/********************************************************************
 * Function: DCE2_SmbCheckCommand()
 *
 * Purpose:
 *  Checks basic validity of an SMB command.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - pointer to session data structure
 *  SmbNtHdr *        - pointer to the SMB header structure
 *  uint8_t           - the SMB command code, i.e. SMB_COM_*
 *  uint8_t *         - current pointer to data, i.e. the command
 *  uint32_t          - the remaining length
 *  DCE2_SmbComInfo & -
 *      Populated structure for command processing
 *
 * Returns: None
 *
 ********************************************************************/
static void DCE2_SmbCheckCommand(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr, const uint8_t smb_com,
    const uint8_t* nb_ptr, uint32_t nb_len, DCE2_SmbComInfo& com_info)
{
    // Check for server error response
    if (com_info.smb_type == SMB_TYPE__RESPONSE)
    {
        const SmbEmptyCom* ec = (const SmbEmptyCom*)nb_ptr;

        // Verify there is enough data to do checks
        if (nb_len < sizeof(SmbEmptyCom))
        {
            dce_alert(GID_DCE2, DCE2_SMB_NB_LT_COM, (dce2CommonStats*)&dce2_smb_stats);
            com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
            return;
        }

        // If word and byte counts are zero and there is an error
        // the server didn't accept client request
        if ((SmbEmptyComWct(ec) == 0)
            && (SmbEmptyComBcc(ec) == 0) && SmbError(smb_hdr))
        {
            // If broken pipe, clean up data associated with open named pipe
            if (SmbBrokenPipe(smb_hdr))
            {
                DCE2_SmbRemoveFileTracker(ssd, ssd->cur_rtracker->ftracker);
            }

            com_info.cmd_error |= DCE2_SMB_COM_ERROR__STATUS_ERROR;
            return;
        }
    }

    // Set the header size to the minimum size the command can be
    // without the byte count to make sure there is enough data to
    // get the word count.
    SmbAndXCom andx_com = smb_chain_map[smb_com];
    int chk_com_size;
    if (andx_com == SMB_ANDX_COM__NONE)
        chk_com_size = sizeof(SmbCommon);
    else
        chk_com_size = sizeof(SmbAndXCommon);

    // Verify there is enough data to do checks
    if (nb_len < (uint32_t)chk_com_size)
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_COM, (dce2CommonStats*)&dce2_smb_stats);
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
        return;
    }

    const SmbCommon* sc = (const SmbCommon*)nb_ptr;
    com_info.word_count = SmbWct(sc);

    // Make sure the word count is a valid one for the command.  If not
    // testing shows an error will be returned.  And command structures
    // won't lie on data correctly and out of bounds data accesses are possible.
    if (!DCE2_SmbIsValidWordCount(smb_com, (uint8_t)com_info.smb_type, com_info.word_count))
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_WCT, (dce2CommonStats*)&dce2_smb_stats);
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__INVALID_WORD_COUNT;
        return;
    }

    // This gets the size of the SMB command from word count through byte count
    // using the advertised value in the word count field.
    com_info.cmd_size = (uint16_t)SMB_COM_SIZE(com_info.word_count);
    if (nb_len < com_info.cmd_size)
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_COM, (dce2CommonStats*)&dce2_smb_stats);
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
        return;
    }

    uint16_t smb_bcc = SmbBcc(nb_ptr, com_info.cmd_size);

    // SMB_COM_NT_CREATE_ANDX is a special case.  Who know what's going
    // on with the word count (see MS-CIFS and MS-SMB).  A 42 word count
    // command seems to actually have 50 words, so who knows where the
    // byte count is.  Just set to zero since it's not needed.
    if ((smb_com == SMB_COM_NT_CREATE_ANDX)
        && (com_info.smb_type == SMB_TYPE__RESPONSE))
        smb_bcc = 0;

    // If byte count is deemed invalid, alert but continue processing
    switch (smb_com)
    {
    // Interim responses
    case SMB_COM_TRANSACTION:
    case SMB_COM_TRANSACTION2:
    case SMB_COM_NT_TRANSACT:
        // If word count is 0, byte count must be 0
        if ((com_info.word_count == 0) && (com_info.smb_type == SMB_TYPE__RESPONSE))
        {
            if (smb_bcc != 0)
            {
                dce_alert(GID_DCE2, DCE2_SMB_BAD_BCC, (dce2CommonStats*)&dce2_smb_stats);
                com_info.cmd_error |= DCE2_SMB_COM_ERROR__INVALID_BYTE_COUNT;
            }
            break;
        }
    // Fall through
    default:
        if (!DCE2_SmbIsValidByteCount(smb_com, (uint8_t)com_info.smb_type, smb_bcc))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_BCC, (dce2CommonStats*)&dce2_smb_stats);
            com_info.cmd_error |= DCE2_SMB_COM_ERROR__INVALID_BYTE_COUNT;
        }
        break;
    }

    // Move just past byte count field which is the end of the command
    nb_len -= com_info.cmd_size;

    // Validate that there is enough data to be able to process the command
    if (nb_len < DCE2_SmbGetMinByteCount(smb_com, (uint8_t)com_info.smb_type))
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_BCC, (dce2CommonStats*)&dce2_smb_stats);
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
    }

    // The byte count seems to be ignored by Windows and current Samba (3.5.4)
    // as long as it is less than the amount of data left.  If more, an error
    // is returned.
    // !!!WARNING!!! the byte count should probably never be used.
    if (smb_bcc > nb_len)
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_BCC, (dce2CommonStats*)&dce2_smb_stats);
        // Large byte count doesn't seem to matter for early Samba
        switch (DCE2_SsnGetPolicy(&ssd->sd))
        {
        case DCE2_POLICY__SAMBA_3_0_20:
        case DCE2_POLICY__SAMBA_3_0_22:
        case DCE2_POLICY__SAMBA_3_0_37:
            break;
        default:
            com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
            break;
        }
    }
    else if ((smb_bcc == 0) && (SmbCom(smb_hdr) == SMB_COM_TRANSACTION)
        && (DCE2_SmbType(ssd) == SMB_TYPE__REQUEST)
        && (DCE2_SsnGetPolicy(&ssd->sd) == DCE2_POLICY__SAMBA))
    {
        // Current Samba errors on a zero byte count Transaction because it
        // uses it to get the Name string and if zero Name will be NULL and
        // it won't process it.
        com_info.cmd_error |= DCE2_SMB_COM_ERROR__BAD_LENGTH;
    }

    com_info.byte_count = smb_bcc;
}

/********************************************************************
 * Function: DCE2_SmbProcessCommand()
 *
 * Purpose:
 *  This is the main function for handling SMB commands and command
 *  chaining.
 *  It does an initial check of the command to determine validity
 *  and gets basic information about the command.  Then it calls the
 *  specific command function (setup in DCE2_SmbInitGlobals).
 *  If there is command chaining, it will do the chaining foo to
 *  get to the next command.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - pointer to session data structure
 *  SmbNtHdr *        - pointer to the SMB header structure
 *  uint8_t *         - current pointer to data, i.e. the command
 *  uint32_t          - the remaining length
 *
 * Returns: None
 *
 ********************************************************************/
static void DCE2_SmbProcessCommand(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint8_t smb_com = SmbCom(smb_hdr);
    DCE2_Ret status = DCE2_RET__ERROR;
    bool sess_chain = false;
    bool tree_chain = false;
    bool open_chain = false;
    int num_chained = 0;

    while (nb_len > 0)
    {
        if (ssd->block_pdus && (DCE2_SmbType(ssd) == SMB_TYPE__REQUEST))
        {
            Active::drop_packet(ssd->sd.wire_pkt);
            status = DCE2_RET__IGNORE;
            break;
        }
        // Break out if command not supported
        if (smb_com_funcs[smb_com] == nullptr)
            break;

        if (smb_deprecated_coms[smb_com])
        {
            dce_alert(GID_DCE2, DCE2_SMB_DEPR_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
        }

        if (smb_unusual_coms[smb_com])
        {
            dce_alert(GID_DCE2, DCE2_SMB_UNUSUAL_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
        }

        DCE2_SmbComInfo com_info;
        com_info.smb_type = DCE2_SmbType(ssd);
        com_info.cmd_error = DCE2_SMB_COM_ERROR__COMMAND_OK;
        com_info.word_count = 0;
        com_info.smb_com = smb_com;
        com_info.cmd_size = 0;
        com_info.byte_count = 0;
        DCE2_SmbCheckCommand(ssd, smb_hdr, smb_com, nb_ptr, nb_len, com_info);
        trace_logf(dce_smb, "Processing command: %s (0x%02X)\n",
            get_smb_com_string(smb_com), smb_com);

        // Note that even if the command shouldn't be processed, some of
        // the command functions need to know and do cleanup or some other
        // processing.
        status = smb_com_funcs[smb_com](ssd, smb_hdr,
                &com_info, nb_ptr, nb_len);

        if (status != DCE2_RET__SUCCESS)
            break;

        // This command is not chainable
        SmbAndXCom andx_com = smb_chain_map[smb_com];
        if (andx_com == SMB_ANDX_COM__NONE)
            break;

        /**********************************************************
         * AndX Chaining
         **********************************************************/
        const SmbAndXCommon* andx_ptr = (const SmbAndXCommon*)nb_ptr;
        uint8_t smb_com2 = SmbAndXCom2(andx_ptr);
        if (smb_com2 == SMB_COM_NO_ANDX_COMMAND)
            break;

        trace_logf(dce_smb, "Chained SMB command: %s\n",
            get_smb_com_string(smb_com2));

        num_chained++;
        if (DCE2_ScSmbMaxChain((dce2SmbProtoConf*)ssd->sd.config) &&
            (num_chained >= DCE2_ScSmbMaxChain((dce2SmbProtoConf*)ssd->sd.config)))
        {
            dce_alert(GID_DCE2, DCE2_SMB_EXCESSIVE_CHAINING, (dce2CommonStats*)&dce2_smb_stats);
        }

        // Multiple SessionSetupAndX, TreeConnectAndX, OpenAndX and NtCreateAndX
        // are only allowed by Samba.
        if (smb_com == SMB_COM_SESSION_SETUP_ANDX)
            sess_chain = true;

        // Check for multiple chained SessionSetupAndX
        if ((smb_com2 == SMB_COM_SESSION_SETUP_ANDX) && sess_chain)
        {
            // There is only one place to return a uid.
            dce_alert(GID_DCE2, DCE2_SMB_MULT_CHAIN_SS, (dce2CommonStats*)&dce2_smb_stats);
            // FIXIT-L Should we continue processing?
            break;
        }

        // Check for chained SessionSetupAndX => .? => LogoffAndX
        if ((smb_com2 == SMB_COM_LOGOFF_ANDX) && sess_chain)
        {
            // This essentially deletes the uid created by the login
            // and doesn't make any sense.
            dce_alert(GID_DCE2, DCE2_SMB_CHAIN_SS_LOGOFF, (dce2CommonStats*)&dce2_smb_stats);
        }

        if (smb_com == SMB_COM_TREE_CONNECT_ANDX)
            tree_chain = true;

        // Check for multiple chained TreeConnects
        if (((smb_com2 == SMB_COM_TREE_CONNECT_ANDX)
            || (smb_com2 == SMB_COM_TREE_CONNECT)) && tree_chain)
        {
            // There is only one place to return a tid.
            dce_alert(GID_DCE2, DCE2_SMB_MULT_CHAIN_TC, (dce2CommonStats*)&dce2_smb_stats);
            // FIXIT-L Should we continue processing?
            break;
        }

        // Check for chained TreeConnectAndX => .? => TreeDisconnect
        if ((smb_com2 == SMB_COM_TREE_DISCONNECT) && tree_chain)
        {
            // This essentially deletes the tid created by the tree connect
            // and doesn't make any sense.
            dce_alert(GID_DCE2, DCE2_SMB_CHAIN_TC_TDIS, (dce2CommonStats*)&dce2_smb_stats);
        }

        if ((smb_com == SMB_COM_OPEN_ANDX) || (smb_com == SMB_COM_NT_CREATE_ANDX))
            open_chain = true;

        // Check for chained OpenAndX/NtCreateAndX => .? => Close
        if ((smb_com2 == SMB_COM_CLOSE) && open_chain)
        {
            // This essentially deletes the fid created by the open command
            // and doesn't make any sense.
            dce_alert(GID_DCE2, DCE2_SMB_CHAIN_OPEN_CLOSE, (dce2CommonStats*)&dce2_smb_stats);
        }

        // Check that policy allows for such chaining
        DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
        if (smb_chain_funcs[policy][andx_com][smb_com2] == nullptr)
            break;

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(&com_info));

        // FIXIT-L Need to test out of order chaining
        const uint8_t* off2_ptr = (const uint8_t*)smb_hdr + SmbAndXOff2(andx_ptr);
        if (DCE2_SmbCheckAndXOffset(off2_ptr, nb_ptr, nb_len) != DCE2_RET__SUCCESS)
            break;

        DCE2_MOVE(nb_ptr, nb_len, (off2_ptr - nb_ptr));

        // FIXIT-L Need to test more.
        switch (smb_com)
        {
        case SMB_COM_SESSION_SETUP_ANDX:
        case SMB_COM_TREE_CONNECT_ANDX:
        case SMB_COM_OPEN_ANDX:
        case SMB_COM_NT_CREATE_ANDX:
            switch (smb_com2)
            {
            case SMB_COM_WRITE:
            case SMB_COM_WRITE_ANDX:
            case SMB_COM_TRANSACTION:
            case SMB_COM_READ_ANDX:
                if (DCE2_SsnFromClient(ssd->sd.wire_pkt) && open_chain)
                {
                    DCE2_SmbQueueTmpFileTracker(ssd, ssd->cur_rtracker,
                        SmbUid(smb_hdr), SmbTid(smb_hdr));
                }
                break;
            default:
                break;
            }
            break;
        default:
            break;
        }

        smb_com = smb_com2;
    }

    int smb_type = DCE2_SmbType(ssd);
    if (smb_type == SMB_TYPE__RESPONSE)
    {
        switch (smb_com)
        {
        case SMB_COM_TRANSACTION:
        case SMB_COM_TRANSACTION2:
        case SMB_COM_NT_TRANSACT:
        case SMB_COM_TRANSACTION_SECONDARY:
        case SMB_COM_TRANSACTION2_SECONDARY:
        case SMB_COM_NT_TRANSACT_SECONDARY:
            // This case means there was an error with the initial response
            // so the tracker isn't yet officially in response mode
            if (ssd->cur_rtracker->ttracker.smb_type == SMB_TYPE__REQUEST)
            {
                // Samba throws out entire transaction and Windows just this request
                if (DCE2_SsnIsServerSambaPolicy(&ssd->sd) && (status != DCE2_RET__SUCCESS))
                    break;

                if (!DCE2_SmbIsTransactionComplete(&ssd->cur_rtracker->ttracker))
                    return;
            }
            else
            {
                if ((status == DCE2_RET__SUCCESS)
                    && !DCE2_SmbIsTransactionComplete(&ssd->cur_rtracker->ttracker))
                    return;
            }
            break;
        case SMB_COM_WRITE_RAW:
            if ((status == DCE2_RET__SUCCESS)
                && (ssd->cur_rtracker->writeraw_remaining != 0))
                return;
            break;
        default:
            break;
        }
    }
    else if (status != DCE2_RET__IGNORE)
    {
        switch (smb_com)
        {
        case SMB_COM_TRANSACTION:
        case SMB_COM_TRANSACTION_SECONDARY:
            if (DCE2_SsnIsWindowsPolicy(&ssd->sd))
            {
                if (!ssd->cur_rtracker->ttracker.one_way
                    || !DCE2_SmbIsTransactionComplete(&ssd->cur_rtracker->ttracker))
                    return;

                // Remove the request tracker if transaction is one-way and
                // all data and parameters have been sent
                break;
            }
        default:
            // Anything else, keep the request tracker
            return;
        }
    }

    DCE2_SmbRemoveRequestTracker(ssd, ssd->cur_rtracker);
    ssd->cur_rtracker = nullptr;
}

/********************************************************************
 * Function: DCE2_SmbInspect()
 *
 * Purpose:
 *  Determines whether the SMB command is something the preprocessor
 *  needs to inspect.
 *  This function returns a DCE2_SmbRequestTracker which tracks command
 *  requests / responses.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - the session data structure.
 *  const SmbNtHdr *  - pointer to the SMB header.
 *
 * Returns:
 *  DCE2_SmbRequestTracker * - nullptr if it's not something we want to or can
 *                     inspect.
 *                     Otherwise an initialized structure if request
 *                     and the found structure if response.
 *
 ********************************************************************/
static DCE2_SmbRequestTracker* DCE2_SmbInspect(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr)
{
    int smb_com = SmbCom(smb_hdr);

    trace_logf(dce_smb, "SMB command: %s (0x%02X)\n",
        get_smb_com_string(smb_com), smb_com);

    if (smb_com_funcs[smb_com] == nullptr)
    {
        return nullptr;
    }

    // See if this is something we need to inspect
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    DCE2_SmbRequestTracker* rtracker = nullptr;
    if (DCE2_SmbType(ssd) == SMB_TYPE__REQUEST)
    {
        switch (smb_com)
        {
        case SMB_COM_NEGOTIATE:
            if (ssd->ssn_state_flags & DCE2_SMB_SSN_STATE__NEGOTIATED)
            {
                dce_alert(GID_DCE2, DCE2_SMB_MULTIPLE_NEGOTIATIONS,
                    (dce2CommonStats*)&dce2_smb_stats);
                return nullptr;
            }
            break;
        case SMB_COM_SESSION_SETUP_ANDX:
            break;
        case SMB_COM_TREE_CONNECT:
        case SMB_COM_TREE_CONNECT_ANDX:
        case SMB_COM_RENAME:
        case SMB_COM_LOGOFF_ANDX:
            if (DCE2_SmbFindUid(ssd, SmbUid(smb_hdr)) != DCE2_RET__SUCCESS)
                return nullptr;
            break;
        default:
            if (DCE2_SmbFindTid(ssd, SmbTid(smb_hdr)) != DCE2_RET__SUCCESS)
                return nullptr;

            if (DCE2_SmbIsTidIPC(ssd, SmbTid(smb_hdr)))
            {
                switch (smb_com)
                {
                case SMB_COM_OPEN:
                case SMB_COM_CREATE:
                case SMB_COM_CREATE_NEW:
                case SMB_COM_WRITE_AND_CLOSE:
                case SMB_COM_WRITE_AND_UNLOCK:
                case SMB_COM_READ:
                    // Samba doesn't allow these commands under an IPC tree
                    switch (policy)
                    {
                    case DCE2_POLICY__SAMBA:
                    case DCE2_POLICY__SAMBA_3_0_37:
                    case DCE2_POLICY__SAMBA_3_0_22:
                    case DCE2_POLICY__SAMBA_3_0_20:
                        return nullptr;
                    default:
                        break;
                    }
                    break;
                case SMB_COM_READ_RAW:
                case SMB_COM_WRITE_RAW:
                    // Samba and Windows Vista on don't allow these commands
                    // under an IPC tree, whether or not the raw read/write
                    // flag is set in the Negotiate capabilities.
                    // Windows RSTs the connection and Samba FINs it.
                    switch (policy)
                    {
                    case DCE2_POLICY__WINVISTA:
                    case DCE2_POLICY__WIN2008:
                    case DCE2_POLICY__WIN7:
                    case DCE2_POLICY__SAMBA:
                    case DCE2_POLICY__SAMBA_3_0_37:
                    case DCE2_POLICY__SAMBA_3_0_22:
                    case DCE2_POLICY__SAMBA_3_0_20:
                        return nullptr;
                    default:
                        break;
                    }
                    break;
                case SMB_COM_LOCK_AND_READ:
                    // The lock will fail so the read won't happen
                    return nullptr;
                default:
                    break;
                }
            }
            else      // Not IPC
            {
                switch (smb_com)
                {
                // These commands are only used for IPC
                case SMB_COM_TRANSACTION:
                case SMB_COM_TRANSACTION_SECONDARY:
                    return nullptr;
                case SMB_COM_READ_RAW:
                case SMB_COM_WRITE_RAW:
                    // Windows Vista on don't seem to support these
                    // commands, whether or not the raw read/write
                    // flag is set in the Negotiate capabilities.
                    // Windows RSTs the connection.
                    switch (policy)
                    {
                    case DCE2_POLICY__WINVISTA:
                    case DCE2_POLICY__WIN2008:
                    case DCE2_POLICY__WIN7:
                        return nullptr;
                    default:
                        break;
                    }
                    break;
                default:
                    break;
                }
            }
            break;
        }

        switch (smb_com)
        {
        case SMB_COM_TRANSACTION_SECONDARY:
        case SMB_COM_TRANSACTION2_SECONDARY:
        case SMB_COM_NT_TRANSACT_SECONDARY:
            rtracker = DCE2_SmbFindRequestTracker(ssd, smb_hdr);
            break;
        case SMB_COM_TRANSACTION:
        case SMB_COM_TRANSACTION2:
        case SMB_COM_NT_TRANSACT:
            // If there is already and existing request tracker
            // and the transaction is not complete, server will
            // return an error.
            rtracker = DCE2_SmbFindRequestTracker(ssd, smb_hdr);
            if (rtracker != nullptr)
                break;
        // Fall through
        default:
            rtracker = DCE2_SmbNewRequestTracker(ssd, smb_hdr);
            break;
        }
    }
    else
    {
        rtracker = DCE2_SmbFindRequestTracker(ssd, smb_hdr);
    }

    return rtracker;
}

static void DCE2_SmbProcessRawData(DCE2_SmbSsnData* ssd, const uint8_t* nb_ptr, uint32_t nb_len)
{
    DCE2_SmbFileTracker* ftracker = ssd->cur_rtracker->ftracker;
    bool remove_rtracker = false;

    if (ftracker == nullptr)
    {
        DCE2_SmbRemoveRequestTracker(ssd, ssd->cur_rtracker);
        ssd->cur_rtracker = nullptr;
        return;
    }

    if (DCE2_SsnFromClient(ssd->sd.wire_pkt))
    {
        if (nb_len > ssd->cur_rtracker->writeraw_remaining)
        {
            dce_alert(GID_DCE2, DCE2_SMB_TDCNT_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);

            // If this happens, Windows never responds regardless of
            // WriteThrough flag, so get rid of request tracker
            remove_rtracker = true;
        }
        else if (!ssd->cur_rtracker->writeraw_writethrough)
        {
            // If WriteThrough flag was not set on initial request, a
            // SMB_COM_WRITE_COMPLETE will not be sent so need to get
            // rid of request tracker.
            remove_rtracker = true;
        }
        else
        {
            ssd->cur_rtracker->writeraw_writethrough = false;
            ssd->cur_rtracker->writeraw_remaining = 0;
        }
    }
    else
    {
        remove_rtracker = true;
    }

    // Only one raw read/write allowed
    ssd->pdu_state = DCE2_SMB_PDU_STATE__COMMAND;

    if (ftracker->is_ipc)
    {
        // Maximum possible fragment length is 16 bit
        if (nb_len > UINT16_MAX)
            nb_len = UINT16_MAX;

        DCE2_CoProcess(&ssd->sd, ftracker->fp_co_tracker, nb_ptr, (uint16_t)nb_len);
    }
    else
    {
        bool upload = DCE2_SsnFromClient(ssd->sd.wire_pkt) ? true : false;
        DCE2_SmbProcessFileData(ssd, ftracker, nb_ptr, nb_len, upload);
    }

    if (remove_rtracker)
    {
        DCE2_SmbRemoveRequestTracker(ssd, ssd->cur_rtracker);
        ssd->cur_rtracker = nullptr;
    }
}

static void DCE2_SmbDataFree(DCE2_SmbSsnData* ssd)
{
    if (ssd == nullptr)
        return;

    // FIXIT This tries to account for the situation where we never knew the file
    // size and the TCP session was shutdown before an SMB_COM_CLOSE on the file.
    // Possibly need to add callback to fileAPI since it may have already
    // released it's resources.
    //DCE2_SmbFinishFileAPI(ssd);

    if (ssd->uids != nullptr)
    {
        DCE2_ListDestroy(ssd->uids);
        ssd->uids = nullptr;
    }

    if (ssd->tids != nullptr)
    {
        DCE2_ListDestroy(ssd->tids);
        ssd->tids = nullptr;
    }

    DCE2_SmbCleanFileTracker(&ssd->ftracker);
    if (ssd->ftrackers != nullptr)
    {
        DCE2_ListDestroy(ssd->ftrackers);
        ssd->ftrackers = nullptr;
    }

    DCE2_SmbCleanRequestTracker(&ssd->rtracker);
    if (ssd->rtrackers != nullptr)
    {
        DCE2_QueueDestroy(ssd->rtrackers);
        ssd->rtrackers = nullptr;
    }

    if (ssd->cli_seg != nullptr)
    {
        DCE2_BufferDestroy(ssd->cli_seg);
        ssd->cli_seg = nullptr;
    }

    if (ssd->srv_seg != nullptr)
    {
        DCE2_BufferDestroy(ssd->srv_seg);
        ssd->srv_seg = nullptr;
    }

    if (ssd->smb2_requests != nullptr)
    {
        DCE2_Smb2CleanRequests(ssd->smb2_requests);
        ssd->smb2_requests = nullptr;
    }
}

Dce2SmbFlowData::Dce2SmbFlowData() : FlowData(inspector_id)
{
    dce2_smb_stats.concurrent_sessions++;
    if (dce2_smb_stats.max_concurrent_sessions < dce2_smb_stats.concurrent_sessions)
        dce2_smb_stats.max_concurrent_sessions = dce2_smb_stats.concurrent_sessions;
}

Dce2SmbFlowData::~Dce2SmbFlowData()
{
    DCE2_SmbDataFree(&dce2_smb_session);
    assert(dce2_smb_stats.concurrent_sessions > 0);
    dce2_smb_stats.concurrent_sessions--;
}

unsigned Dce2SmbFlowData::inspector_id = 0;

DCE2_SmbSsnData* get_dce2_smb_session_data(Flow* flow)
{
    Dce2SmbFlowData* fd = (Dce2SmbFlowData*)flow->get_flow_data(Dce2SmbFlowData::inspector_id);
    return fd ? &fd->dce2_smb_session : nullptr;
}

static DCE2_SmbSsnData* set_new_dce2_smb_session(Packet* p)
{
    Dce2SmbFlowData* fd = new Dce2SmbFlowData;
    memset(&fd->dce2_smb_session,0,sizeof(DCE2_SmbSsnData));
    p->flow->set_flow_data(fd);
    return(&fd->dce2_smb_session);
}

static DCE2_SmbSsnData* dce2_create_new_smb_session(Packet* p, dce2SmbProtoConf* config)
{
    Profile profile(dce2_smb_pstat_new_session);

    DCE2_SmbSsnData* dce2_smb_sess = set_new_dce2_smb_session(p);
    if ( dce2_smb_sess )
    {
        dce2_smb_sess->dialect_index = DCE2_SENTINEL;
        dce2_smb_sess->max_outstanding_requests = 10;  // Until Negotiate/SessionSetupAndX
        dce2_smb_sess->cli_data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
        dce2_smb_sess->srv_data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
        dce2_smb_sess->pdu_state = DCE2_SMB_PDU_STATE__COMMAND;
        dce2_smb_sess->uid = DCE2_SENTINEL;
        dce2_smb_sess->tid = DCE2_SENTINEL;
        dce2_smb_sess->ftracker.fid_v1 = DCE2_SENTINEL;
        dce2_smb_sess->rtracker.mid = DCE2_SENTINEL;
        dce2_smb_sess->max_file_depth = snort::FileService::get_max_file_depth();

        DCE2_ResetRopts(&dce2_smb_sess->sd, p);

        dce2_smb_stats.smb_sessions++;

        dce2_smb_sess->sd.trans = DCE2_TRANS_TYPE__SMB;
        dce2_smb_sess->sd.server_policy = config->common.policy;
        dce2_smb_sess->sd.client_policy = DCE2_POLICY__WINXP;
        dce2_smb_sess->sd.wire_pkt = p;
        dce2_smb_sess->sd.config = (void*)config;
    }

    return dce2_smb_sess;
}

/********************************************************************
 * Function: DCE2_NbssHdrChecks()
 *
 * Purpose:
 *  Does validation of the NetBIOS header.  SMB will only run over
 *  the Session Message type.  On port 139, there is always an
 *  initial Session Request / Session Positive/Negative response
 *  followed by the normal SMB conversation, i.e. Negotiate,
 *  SessionSetupAndX, etc.
 *  Side effects are potential alerts for anomalous behavior.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - the session data structure.
 *  const NbssHdr *   - pointer to the NetBIOS Session Service
 *                      header structure.  Size is already validated.
 *
 * Returns:
 *  DCE2_Ret  -  DCE2_RET__SUCCESS if all goes well and processing
 *               should continue.
 *               DCE2_RET__IGNORE if it's not something we need to
 *               look at.
 *               DCE2_RET__ERROR if an invalid NetBIOS Session
 *               Service type is found.
 *
 ********************************************************************/
static DCE2_Ret DCE2_NbssHdrChecks(DCE2_SmbSsnData* ssd, const NbssHdr* nb_hdr)
{
    Packet* p = ssd->sd.wire_pkt;
    bool is_seg_buf = DCE2_SmbIsSegBuffer(ssd, (const uint8_t*)nb_hdr);

    switch (NbssType(nb_hdr))
    {
    case NBSS_SESSION_TYPE__MESSAGE:
        /* Only want to look at session messages */
        if (!DCE2_SmbIsRawData(ssd))
        {
            uint32_t nb_len = NbssLen(nb_hdr);

            if (nb_len == 0)
                return DCE2_RET__IGNORE;

            if (nb_len < sizeof(SmbNtHdr))
            {
                if (is_seg_buf)
                    DCE2_SmbSegAlert(ssd, DCE2_SMB_NB_LT_SMBHDR);
                else
                    dce_alert(GID_DCE2, DCE2_SMB_NB_LT_SMBHDR, (dce2CommonStats*)&dce2_smb_stats);

                return DCE2_RET__IGNORE;
            }
        }

        return DCE2_RET__SUCCESS;

    case NBSS_SESSION_TYPE__REQUEST:
        if (DCE2_SsnFromServer(p))
        {
            if (is_seg_buf)
                DCE2_SmbSegAlert(ssd, DCE2_SMB_BAD_NBSS_TYPE);
            else
                dce_alert(GID_DCE2, DCE2_SMB_BAD_NBSS_TYPE, (dce2CommonStats*)&dce2_smb_stats);
        }

        break;

    case NBSS_SESSION_TYPE__POS_RESPONSE:
    case NBSS_SESSION_TYPE__NEG_RESPONSE:
    case NBSS_SESSION_TYPE__RETARGET_RESPONSE:
        if (DCE2_SsnFromClient(p))
        {
            if (is_seg_buf)
                DCE2_SmbSegAlert(ssd, DCE2_SMB_BAD_NBSS_TYPE);
            else
                dce_alert(GID_DCE2, DCE2_SMB_BAD_NBSS_TYPE, (dce2CommonStats*)&dce2_smb_stats);
        }

        break;

    case NBSS_SESSION_TYPE__KEEP_ALIVE:
        break;

    default:
        if (is_seg_buf)
            DCE2_SmbSegAlert(ssd, DCE2_SMB_BAD_NBSS_TYPE);
        else
            dce_alert(GID_DCE2, DCE2_SMB_BAD_NBSS_TYPE, (dce2CommonStats*)&dce2_smb_stats);

        return DCE2_RET__ERROR;
    }

    return DCE2_RET__IGNORE;
}

// This is the main entry point for SMB1 processing.
static void DCE2_Smb1Process(DCE2_SmbSsnData* ssd)
{
    dce2_smb_stats.smb_pkts++;

    const Packet* p = ssd->sd.wire_pkt;
    const uint8_t* data_ptr = p->data;
    uint16_t data_len = p->dsize;
    DCE2_Buffer** seg_buf = DCE2_SmbGetSegBuffer(ssd);

    /* Have to account for segmentation.  Even though stream will give
     * us larger chunks, we might end up in the middle of something */
    while (data_len > 0)
    {
        // We are ignoring an entire PDU or junk data so state should be NETBIOS_HEADER
        // Note that it could be TCP segmented so ignore_bytes could be greater than
        // the amount of data we have
        uint32_t* ignore_bytes = DCE2_SmbGetIgnorePtr(ssd);
        if (*ignore_bytes)
        {
            if (data_len <= *ignore_bytes)
            {
                *ignore_bytes -= data_len;
                return;
            }
            else
            {
                /* ignore bytes is less than UINT16_MAX */
                DCE2_MOVE(data_ptr, data_len, (uint16_t)*ignore_bytes);
                *ignore_bytes = 0;
            }
        }

        DCE2_SmbDataState* data_state = DCE2_SmbGetDataState(ssd);
        DCE2_SmbRequestTracker* rtracker = nullptr;
        switch (*data_state)
        {
        // This state is to verify it's a NetBIOS Session Message packet
        // and to get the length of the SMB PDU.  Also does the SMB junk
        // data check.  If it's not a Session Message the data isn't
        // processed since it won't be carrying SMB.
        case DCE2_SMB_DATA_STATE__NETBIOS_HEADER:
        {
            uint32_t data_need = sizeof(NbssHdr);

            // See if there is enough data to process the NetBIOS header
            if (data_len < data_need)
            {
                if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr,
                    data_len, sizeof(NbssHdr)) != DCE2_RET__SUCCESS)
                {
                    DCE2_BufferEmpty(*seg_buf);
                }

                return;
            }

            // Set the NetBIOS header structure
            const NbssHdr* nb_hdr;
            if (DCE2_BufferIsEmpty(*seg_buf))
            {
                nb_hdr = (const NbssHdr*)data_ptr;
            }
            else
            {
                // If data already buffered add the remainder for the
                // size of the NetBIOS header
                if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr,
                    data_need, sizeof(NbssHdr)) != DCE2_RET__SUCCESS)
                {
                    DCE2_BufferEmpty(*seg_buf);
                    return;
                }

                nb_hdr = (const NbssHdr*)DCE2_BufferData(*seg_buf);
            }

            uint32_t nb_len = NbssLen(nb_hdr);
            DCE2_Ret status = DCE2_NbssHdrChecks(ssd, nb_hdr);
            if (status != DCE2_RET__SUCCESS)
            {
                if (status == DCE2_RET__IGNORE)
                {
                    // Valid NetBIOS header type so ignoring NetBIOS length bytes
                    *ignore_bytes = data_need + nb_len;
                }
                else      // nb_ret == DCE2_RET__ERROR, i.e. invalid NetBIOS type
                {
                    // Trying to find \\xffSMB to determine how many bytes to ignore
                    *ignore_bytes = DCE2_IgnoreJunkData(data_ptr, data_len, data_need + nb_len);
                }

                DCE2_BufferEmpty(*seg_buf);
                dce2_smb_stats.smb_ignored_bytes += *ignore_bytes;
                continue;
            }

            if (!DCE2_BufferIsEmpty(*seg_buf))
                DCE2_MOVE(data_ptr, data_len, (uint16_t)data_need);

            switch (ssd->pdu_state)
            {
            case DCE2_SMB_PDU_STATE__COMMAND:
                *data_state = DCE2_SMB_DATA_STATE__SMB_HEADER;
                break;
            case DCE2_SMB_PDU_STATE__RAW_DATA:
                *data_state = DCE2_SMB_DATA_STATE__NETBIOS_PDU;
                // Continue here because of fall through below
                continue;
            default:
                return;
            }
        }

        // Fall through
        // This is the normal progression without segmentation.

        // This state is to do validation checks on the SMB header and
        // more importantly verify it's data that needs to be inspected.
        // If the TID in the SMB header is not referring to the IPC share
        // there won't be any DCE/RPC traffic associated with it.
        case DCE2_SMB_DATA_STATE__SMB_HEADER:
        {
            uint32_t data_need = (sizeof(NbssHdr) + sizeof(SmbNtHdr)) - DCE2_BufferLength(
                *seg_buf);

            // See if there is enough data to process the SMB header
            if (data_len < data_need)
            {
                if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr, data_len,
                    sizeof(NbssHdr) + sizeof(SmbNtHdr)) != DCE2_RET__SUCCESS)
                {
                    DCE2_BufferEmpty(*seg_buf);
                    *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
                }

                return;
            }

            // Set the SMB header structure
            const SmbNtHdr* smb_hdr;
            if (DCE2_BufferIsEmpty(*seg_buf))
            {
                smb_hdr = (const SmbNtHdr*)(data_ptr + sizeof(NbssHdr));
            }
            else
            {
                if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr, data_need,
                    sizeof(NbssHdr) + sizeof(SmbNtHdr)) != DCE2_RET__SUCCESS)
                {
                    DCE2_BufferEmpty(*seg_buf);
                    *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
                    return;
                }

                smb_hdr = (const SmbNtHdr*)(DCE2_BufferData(*seg_buf) + sizeof(NbssHdr));
            }

            if (SmbId(smb_hdr) == DCE2_SMB2_ID)
            {
                ssd->sd.flags |= DCE2_SSN_FLAG__SMB2;
                if (!DCE2_GcIsLegacyMode((dce2SmbProtoConf*)ssd->sd.config))
                {
                    DCE2_Smb2InitFileTracker(&(ssd->ftracker), false, 0);
                    DCE2_Smb2Process(ssd);
                }
                return;
            }

            // See if this is something we need to inspect
            rtracker = DCE2_SmbInspect(ssd, smb_hdr);
            if (rtracker == nullptr)
            {
                trace_log(dce_smb, "Not inspecting SMB packet.\n");

                if (DCE2_BufferIsEmpty(*seg_buf))
                {
                    *ignore_bytes = sizeof(NbssHdr) + NbssLen((const NbssHdr*)data_ptr);
                }
                else
                {
                    *ignore_bytes = (NbssLen((NbssHdr*)DCE2_BufferData(*seg_buf))
                        - sizeof(SmbNtHdr)) + data_need;
                    DCE2_BufferEmpty(*seg_buf);
                }

                *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
                dce2_smb_stats.smb_ignored_bytes += *ignore_bytes;
                continue;
            }

            // Check the SMB header for anomalies
            if (DCE2_SmbHdrChecks(ssd, smb_hdr) != DCE2_RET__SUCCESS)
            {
                if (DCE2_BufferIsEmpty(*seg_buf))
                {
                    *ignore_bytes = sizeof(NbssHdr) + NbssLen((const NbssHdr*)data_ptr);
                }
                else
                {
                    *ignore_bytes = (NbssLen((NbssHdr*)DCE2_BufferData(*seg_buf))
                        - sizeof(SmbNtHdr)) + data_need;
                    DCE2_BufferEmpty(*seg_buf);
                }

                *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;

                dce2_smb_stats.smb_ignored_bytes += *ignore_bytes;
                continue;
            }

            if (!DCE2_BufferIsEmpty(*seg_buf))
                DCE2_MOVE(data_ptr, data_len, (uint16_t)data_need);

            *data_state = DCE2_SMB_DATA_STATE__NETBIOS_PDU;
        }

        // Fall through

        // This state ensures that we have the entire PDU before continuing
        // to process.
        case DCE2_SMB_DATA_STATE__NETBIOS_PDU:
        {
            uint32_t nb_len;
            uint32_t data_need;

            if (DCE2_BufferIsEmpty(*seg_buf))
            {
                nb_len = NbssLen((const NbssHdr*)data_ptr);
                data_need = sizeof(NbssHdr) + nb_len;
            }
            else
            {
                nb_len = NbssLen((NbssHdr*)DCE2_BufferData(*seg_buf));
                data_need = (sizeof(NbssHdr) + nb_len) - DCE2_BufferLength(*seg_buf);
            }

            /* It's something we want to inspect so make sure we have the full NBSS packet */
            if (data_len < data_need)
            {
                if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr, data_len,
                    sizeof(NbssHdr) + nb_len) != DCE2_RET__SUCCESS)
                {
                    DCE2_BufferEmpty(*seg_buf);
                    *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
                }

                return;
            }

            // data_len >= data_need which means data_need <= UINT16_MAX
            // So casts below of data_need to uint16_t are okay.

            *data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;

            const uint8_t* nb_ptr;
            if (DCE2_BufferIsEmpty(*seg_buf))
            {
                nb_ptr = data_ptr;
                nb_len = data_need;
                DCE2_MOVE(data_ptr, data_len, (uint16_t)data_need);
            }
            else
            {
                if (DCE2_SmbHandleSegmentation(seg_buf, data_ptr, data_need,
                    sizeof(NbssHdr) + nb_len) != DCE2_RET__SUCCESS)
                {
                    DCE2_BufferEmpty(*seg_buf);
                    DCE2_MOVE(data_ptr, data_len, (uint16_t)data_need);
                    continue;
                }

                DCE2_MOVE(data_ptr, data_len, (uint16_t)data_need);

                nb_ptr = DCE2_BufferData(*seg_buf);
                nb_len = DCE2_BufferLength(*seg_buf);

                // Get reassembled packet
                Packet* rpkt = DCE2_SmbGetRpkt(ssd, &nb_ptr, &nb_len,
                    DCE2_RPKT_TYPE__SMB_SEG);
                if (rpkt == nullptr)
                {
                    DCE2_BufferEmpty(*seg_buf);
                    continue;
                }

                nb_ptr = DCE2_BufferData(*seg_buf);
                nb_len = DCE2_BufferLength(*seg_buf);

                if (DCE2_SsnFromClient(ssd->sd.wire_pkt))
                    dce2_smb_stats.smb_cli_seg_reassembled++;
                else
                    dce2_smb_stats.smb_srv_seg_reassembled++;
            }

            switch (ssd->pdu_state)
            {
            case DCE2_SMB_PDU_STATE__COMMAND:
            {
                const SmbNtHdr* smb_hdr = (const SmbNtHdr*)(nb_ptr + sizeof(NbssHdr));
                DCE2_MOVE(nb_ptr, nb_len, (sizeof(NbssHdr) + sizeof(SmbNtHdr)));
                ssd->cur_rtracker = (rtracker != nullptr)
                    ? rtracker : DCE2_SmbFindRequestTracker(ssd, smb_hdr);
                if (ssd->cur_rtracker != nullptr)
                    DCE2_SmbProcessCommand(ssd, smb_hdr, nb_ptr, nb_len);
                break;
            }

            case DCE2_SMB_PDU_STATE__RAW_DATA:
                DCE2_MOVE(nb_ptr, nb_len, sizeof(NbssHdr));
                if (ssd->cur_rtracker != nullptr)
                    DCE2_SmbProcessRawData(ssd, nb_ptr, nb_len);
                // Only one raw read or write
                ssd->pdu_state = DCE2_SMB_PDU_STATE__COMMAND;
                break;
            default:
                return;
            }

            if (!DCE2_BufferIsEmpty(*seg_buf))
            {
                DCE2_BufferDestroy(*seg_buf);
                *seg_buf = nullptr;
            }

            break;
        }

        default:
            return;
        }
    }
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

/********************************************************************
 * Function: DCE2_SmbInitGlobals()
 *
 * Purpose:
 *  Initializes global variables for SMB processing.
 *  Sets up the functions and valid word and byte counts for SMB
 *  commands.
 *  Sets up AndX chain mappings and valid command chaining for
 *  supported policies.
 *
 * Arguments: None
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_SmbInitGlobals()
{
    memset(&smb_wcts, 0, sizeof(smb_wcts));
    memset(&smb_bccs, 0, sizeof(smb_bccs));

    // Sets up the function to call for the command and valid word and byte
    // counts for the command.  Ensuring valid word and byte counts is very
    // important to processing the command as it will assume the command is
    // legitimate and can access data that is actually there.  Note that
    // commands with multiple word counts indicate a different command
    // structure, however most, if not all just have an extended version
    // of the structure for which the extended part isn't used.  If the
    // extended part of a command structure needs to be used, be sure to
    // check the word count in the command function before accessing data
    // in the extended version of the command structure.
    for (int com = 0; com < SMB_MAX_NUM_COMS; com++)
    {
        switch (com)
        {
        case SMB_COM_OPEN:
            smb_com_funcs[com] = DCE2_SmbOpen;

            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 2);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 7);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_CREATE:
            smb_com_funcs[com] = DCE2_SmbCreate;

            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 3);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_CLOSE:
            smb_com_funcs[com] = DCE2_SmbClose;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 3);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_RENAME:
            smb_com_funcs[com] = DCE2_SmbRename;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 1);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 4, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_READ:
            smb_com_funcs[com] = DCE2_SmbRead;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 5);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 5);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 3, UINT16_MAX);
            break;
        case SMB_COM_WRITE:
            smb_com_funcs[com] = DCE2_SmbWrite;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 5);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 3, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_CREATE_NEW:
            smb_com_funcs[com] = DCE2_SmbCreateNew;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 3);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_LOCK_AND_READ:
            smb_com_funcs[com] = DCE2_SmbLockAndRead;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 5);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 5);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 3, UINT16_MAX);
            break;
        case SMB_COM_WRITE_AND_UNLOCK:
            smb_com_funcs[com] = DCE2_SmbWriteAndUnlock;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 5);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 3, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_READ_RAW:
            smb_com_funcs[com] = DCE2_SmbReadRaw;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 8);
            // With optional OffsetHigh
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 10);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            // Response is raw data, i.e. without SMB
            break;
        case SMB_COM_WRITE_RAW:
            smb_com_funcs[com] = DCE2_SmbWriteRaw;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
            // With optional OffsetHigh
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 14);
            // Interim server response
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_WRITE_COMPLETE:
            // Final server response to SMB_COM_WRITE_RAW
            smb_com_funcs[com] = DCE2_SmbWriteComplete;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_TRANSACTION:
            smb_com_funcs[com] = DCE2_SmbTransaction;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            // Word count depends on setup count
            //for (i = 14; i < 256; i++)
            //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__REQUEST, i);
            // In reality, all subcommands of SMB_COM_TRANSACTION requests
            // have a setup count of 2 words.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 16);

            // \PIPE\LANMAN
            // Not something the preprocessor is looking at as it
            // doesn't carry DCE/RPC but don't want to false positive
            // on the preprocessor event.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 14);

            // Word count depends on setup count
            //for (i = 10; i < 256; i++)
            //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__RESPONSE, i);
            // In reality, all subcommands of SMB_COM_TRANSACTION responses
            // have a setup count of 0 words.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 10);

            // Interim server response
            // When client sends an incomplete transaction and needs to
            // send TransactionSecondary requests to complete request.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            // Exception will be made for Interim responses when
            // byte count is checked.
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_TRANSACTION_SECONDARY:
            smb_com_funcs[com] = DCE2_SmbTransactionSecondary;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 8);
            // Response is an SMB_COM_TRANSACTION

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            break;
        case SMB_COM_WRITE_AND_CLOSE:
            smb_com_funcs[com] = DCE2_SmbWriteAndClose;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 6);
            // For some reason MS-CIFS specifies a version of this command
            // with 6 extra words (12 bytes) of reserved, i.e. useless data.
            // Maybe had intentions of extending and defining the data at
            // some point, but there is no documentation that I could find
            // that does.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 1, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_OPEN_ANDX:
            smb_com_funcs[com] = DCE2_SmbOpenAndX;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 15);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 15);
            // Extended response
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 19);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            // MS-SMB says that Windows 2000, XP and Vista set this to
            // some arbitrary value that is ignored on receipt.
            //DCE2_SmbSetValidByteCount(com, SMB_TYPE__RESPONSE, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_READ_ANDX:
            smb_com_funcs[com] = DCE2_SmbReadAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 10);
            // With optional OffsetHigh
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 12);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_WRITE_ANDX:
            smb_com_funcs[com] = DCE2_SmbWriteAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
            // With optional OffsetHigh
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 14);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 6);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 1, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_TRANSACTION2:
            smb_com_funcs[com] = DCE2_SmbTransaction2;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            // Word count depends on setup count
            //for (i = 14; i < 256; i++)
            //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__REQUEST, i);
            // In reality, all subcommands of SMB_COM_TRANSACTION2
            // requests have a setup count of 1 word.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 15);

            // Word count depends on setup count
            //for (i = 10; i < 256; i++)
            //    DCE2_SmbSetValidWordCount(com, SMB_TYPE__RESPONSE, i);
            // In reality, all subcommands of SMB_COM_TRANSACTION2
            // responses have a setup count of 0 or 1 word.
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 10);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 11);

            // Interim server response
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            // Exception will be made for Interim responses when
            // byte count is checked.
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_TRANSACTION2_SECONDARY:
            smb_com_funcs[com] = DCE2_SmbTransaction2Secondary;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 9);
            // Response is an SMB_COM_TRANSACTION2

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            break;
        case SMB_COM_TREE_CONNECT:
            smb_com_funcs[com] = DCE2_SmbTreeConnect;
            smb_deprecated_coms[com] = true;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 0);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 2);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 6, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_TREE_DISCONNECT:
            smb_com_funcs[com] = DCE2_SmbTreeDisconnect;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 0);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_NEGOTIATE:
            smb_com_funcs[com] = DCE2_SmbNegotiate;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 0);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 1);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 13);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 17);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            // This can vary depending on dialect so just set wide.
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_SESSION_SETUP_ANDX:
            smb_com_funcs[com] = DCE2_SmbSessionSetupAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 10);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 12);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 13);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 3);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 4);

            // These can vary so just set wide.
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_LOGOFF_ANDX:
            smb_com_funcs[com] = DCE2_SmbLogoffAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 2);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 2);
            // Windows responds to a LogoffAndX => SessionSetupAndX with just a
            // LogoffAndX and with the word count field containing 3, but only
            // has 2 words
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 3);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            break;
        case SMB_COM_TREE_CONNECT_ANDX:
            smb_com_funcs[com] = DCE2_SmbTreeConnectAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 4);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 2);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 3);
            // Extended response
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 7);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 3, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 2, UINT16_MAX);
            break;
        case SMB_COM_NT_TRANSACT:
            smb_com_funcs[com] = DCE2_SmbNtTransact;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            // Word count depends on setup count
            // In reality, all subcommands of SMB_COM_NT_TRANSACT
            // requests have a setup count of 0 or 4 words.
            //for (i = 19; i < 256; i++)
            //    DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, i);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 19);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 23);

            // Word count depends on setup count
            // In reality, all subcommands of SMB_COM_NT_TRANSACT
            // responses have a setup count of 0 or 1 word.
            //for (i = 18; i < 256; i++)
            //    DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, i);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 18);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 19);

            // Interim server response
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 0);

            // Exception will be made for Interim responses when
            // byte count is checked.
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        case SMB_COM_NT_TRANSACT_SECONDARY:
            smb_com_funcs[com] = DCE2_SmbNtTransactSecondary;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 18);
            // Response is an SMB_COM_NT_TRANSACT

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            break;
        case SMB_COM_NT_CREATE_ANDX:
            smb_com_funcs[com] = DCE2_SmbNtCreateAndX;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;

            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, 24);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 34);
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 26);
            // Extended response - though there are actually 50 words
            DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, 42);

            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 2, UINT16_MAX);
            // MS-SMB indicates that this field should be 0 but may be
            // sent uninitialized so basically ignore it.
            //DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, 0);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        default:
            smb_com_funcs[com] = nullptr;
            smb_deprecated_coms[com] = false;
            smb_unusual_coms[com] = false;
            // Just set to all valid since the specific command won't
            // be processed.  Don't want to false positive on these.
            for (int i = 0; i < 256; i++)
            {
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__REQUEST, (uint8_t)i);
                DCE2_SmbSetValidWordCount((uint8_t)com, SMB_TYPE__RESPONSE, (uint8_t)i);
            }
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__REQUEST, 0, UINT16_MAX);
            DCE2_SmbSetValidByteCount((uint8_t)com, SMB_TYPE__RESPONSE, 0, UINT16_MAX);
            break;
        }
    }

    // Maps commands for use in quickly determining if a command
    // is chainable and what command it is.
    for (int com = 0; com < SMB_MAX_NUM_COMS; com++)
    {
        switch (com)
        {
        case SMB_COM_SESSION_SETUP_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__SESSION_SETUP_ANDX;
            break;
        case SMB_COM_LOGOFF_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__LOGOFF_ANDX;
            break;
        case SMB_COM_TREE_CONNECT_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__TREE_CONNECT_ANDX;
            break;
        case SMB_COM_OPEN_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__OPEN_ANDX;
            break;
        case SMB_COM_NT_CREATE_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__NT_CREATE_ANDX;
            break;
        case SMB_COM_WRITE_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__WRITE_ANDX;
            break;
        case SMB_COM_READ_ANDX:
            smb_chain_map[com] = SMB_ANDX_COM__READ_ANDX;
            break;
        default:
            smb_chain_map[com] = SMB_ANDX_COM__NONE;
            break;
        }
    }

    // Sets up the valid command chaining combinations per policy
    for (int policy = 0; policy < DCE2_POLICY__MAX; policy++)
    {
        for (int andx = SMB_ANDX_COM__NONE; andx < SMB_ANDX_COM__MAX; andx++)
        {
            /* com is the chained command or com2 */
            for (int com = 0; com < SMB_MAX_NUM_COMS; com++)
            {
                DCE2_SmbComFunc com_func = nullptr;

                switch (policy)
                {
                case DCE2_POLICY__WIN2000:
                case DCE2_POLICY__WINXP:
                case DCE2_POLICY__WINVISTA:
                case DCE2_POLICY__WIN2003:
                case DCE2_POLICY__WIN2008:
                case DCE2_POLICY__WIN7:
                    switch (andx)
                    {
                    case SMB_ANDX_COM__SESSION_SETUP_ANDX:
                        switch (com)
                        {
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_OPEN:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_CREATE:
                        case SMB_COM_CREATE_NEW:
                            com_func = smb_com_funcs[com];
                            break;
                        case SMB_COM_TRANSACTION:
                            if (policy == DCE2_POLICY__WIN2000)
                                com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__LOGOFF_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_TREE_CONNECT_ANDX:               // Only for responses
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__TREE_CONNECT_ANDX:
                        switch (com)
                        {
                        case SMB_COM_OPEN:
                        case SMB_COM_CREATE:
                        case SMB_COM_CREATE_NEW:
                            com_func = smb_com_funcs[com];
                            break;
                        case SMB_COM_TRANSACTION:
                            if (policy == DCE2_POLICY__WIN2000)
                                com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__OPEN_ANDX:
                        break;
                    case SMB_ANDX_COM__NT_CREATE_ANDX:
                        switch (com)
                        {
                        case SMB_COM_READ_ANDX:              // Only for normal files
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__WRITE_ANDX:
                        switch (com)
                        {
                        case SMB_COM_CLOSE:
                        case SMB_COM_WRITE_ANDX:
                        case SMB_COM_READ:
                        case SMB_COM_READ_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__READ_ANDX:
                        break;
                    default:
                        break;
                    }
                    break;
                case DCE2_POLICY__SAMBA:
                case DCE2_POLICY__SAMBA_3_0_37:
                case DCE2_POLICY__SAMBA_3_0_22:
                case DCE2_POLICY__SAMBA_3_0_20:
                    switch (andx)
                    {
                    case SMB_ANDX_COM__SESSION_SETUP_ANDX:
                        switch (com)
                        {
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_CONNECT:
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_CLOSE:
                        case SMB_COM_READ_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        case SMB_COM_WRITE:
                            if ((policy == DCE2_POLICY__SAMBA_3_0_22)
                                || (policy == DCE2_POLICY__SAMBA_3_0_20))
                                com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__LOGOFF_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__TREE_CONNECT_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_CLOSE:
                        case SMB_COM_WRITE:
                        case SMB_COM_READ_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__OPEN_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_CONNECT:
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_CLOSE:
                        case SMB_COM_WRITE:
                        case SMB_COM_READ_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__NT_CREATE_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_TREE_CONNECT:
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_WRITE:
                        case SMB_COM_READ_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                        case SMB_COM_CLOSE:
                            if ((policy == DCE2_POLICY__SAMBA)
                                || (policy == DCE2_POLICY__SAMBA_3_0_37))
                                com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__WRITE_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_CONNECT:
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_CLOSE:
                        case SMB_COM_WRITE:
                        case SMB_COM_READ_ANDX:
                        case SMB_COM_WRITE_ANDX:
                            com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    case SMB_ANDX_COM__READ_ANDX:
                        switch (com)
                        {
                        case SMB_COM_SESSION_SETUP_ANDX:
                        case SMB_COM_WRITE:
                            com_func = smb_com_funcs[com];
                            break;
                        case SMB_COM_LOGOFF_ANDX:
                        case SMB_COM_TREE_CONNECT:
                        case SMB_COM_TREE_CONNECT_ANDX:
                        case SMB_COM_TREE_DISCONNECT:
                        case SMB_COM_OPEN_ANDX:
                        case SMB_COM_NT_CREATE_ANDX:
                        case SMB_COM_CLOSE:
                        case SMB_COM_READ_ANDX:
                            if ((policy == DCE2_POLICY__SAMBA)
                                || (policy == DCE2_POLICY__SAMBA_3_0_37))
                                com_func = smb_com_funcs[com];
                            break;
                        default:
                            break;
                        }
                        break;
                    default:
                        break;
                    }
                    break;
                default:
                    break;
                }

                smb_chain_funcs[policy][andx][com] = com_func;
            }
        }
    }
}

DCE2_SmbSsnData* dce2_handle_smb_session(Packet* p, dce2SmbProtoConf* config)
{
    Profile profile(dce2_smb_pstat_session);

    DCE2_SmbSsnData* dce2_smb_sess =  get_dce2_smb_session_data(p->flow);

    if (dce2_smb_sess == nullptr)
    {
        dce2_smb_sess = dce2_create_new_smb_session(p, config);
    }

    return dce2_smb_sess;
}

// This is the main entry point for SMB processing
void DCE2_SmbProcess(DCE2_SmbSsnData* ssd)
{
    if (DCE2_GcIsLegacyMode((dce2SmbProtoConf*)ssd->sd.config))
    {
        DCE2_Smb1Process(ssd);
        return;
    }

    snort::Packet* p = ssd->sd.wire_pkt;
    DCE2_SmbVersion smb_version = DCE2_Smb2Version(p);
    if (smb_version == DCE2_SMB_VERISON_1)
    {
        if ((ssd->sd.flags & DCE2_SSN_FLAG__SMB2))
        {
            ssd->sd.flags &= ~DCE2_SSN_FLAG__SMB2;
            DCE2_SmbCleanFileTracker(&(ssd->ftracker));
            ssd->ftracker.is_smb2 = false;
        }
    }
    else if (smb_version == DCE2_SMB_VERISON_2)
    {
        if (!(ssd->sd.flags & DCE2_SSN_FLAG__SMB2))
        {
            DCE2_SmbCleanFileTracker(&(ssd->ftracker));
            DCE2_Smb2InitFileTracker(&(ssd->ftracker), false, 0);
            ssd->sd.flags |= DCE2_SSN_FLAG__SMB2;
        }
    }

    if (ssd->sd.flags & DCE2_SSN_FLAG__SMB2)
        DCE2_Smb2Process(ssd);
    else
        DCE2_Smb1Process(ssd);
}

