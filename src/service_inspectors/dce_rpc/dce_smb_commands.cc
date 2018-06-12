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

// dce_smb_commands.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

// Smb commands processing

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb_commands.h"

#include "utils/util.h"

#include "dce_smb_module.h"
#include "dce_smb_transaction_utils.h"

using namespace snort;

#define SMB_DIALECT_NT_LM_012       "NT LM 0.12"  // NT LAN Manager

#define SERVICE_0     (0)                // IPC start
#define SERVICE_1     (SERVICE_0+4)      // DISK start
#define SERVICE_FS    (SERVICE_1+3)      // Failure
#define SERVICE_IPC   (SERVICE_FS+1)     // IPC service
#define SERVICE_DISK  (SERVICE_FS+2)     // DISK service

#define SHARE_0     (0)
#define SHARE_FS    (SHARE_0+5)
#define SHARE_IPC   (SHARE_FS+1)

#define OS_0          (0)   // "Windows" start
#define OS_1    (OS_0+ 8)   // Windows 2000 and XP server
#define OS_2    (OS_1+ 4)   // Windows 2000 and XP client
#define OS_3    (OS_2+ 5)   // "Server", 2003, 2008R2, 2008
#define OS_4    (OS_3+20)   // Windows Vista
#define OS_5    (OS_4 +5)   // Windows 7
#define OS_6    (OS_5 +1)   // Windows NT
#define OS_7    (OS_6 +2)   // Windows 98
#define OS_FS   (OS_7+ 3)   // Failure state
#define OS_WIN2000    (OS_FS+1)
#define OS_WINXP      (OS_FS+2)
#define OS_WIN2003    (OS_FS+3)
#define OS_WINVISTA   (OS_FS+4)
#define OS_WIN2008    (OS_FS+5)
#define OS_WIN7       (OS_FS+6)

static const DCE2_SmbFsm dce2_smb_service_fsm[] =
{
    // IPC
    { 'I',  SERVICE_0+1, SERVICE_1 },
    { 'P',  SERVICE_0+2, SERVICE_FS },
    { 'C',  SERVICE_0+3, SERVICE_FS },
    { '\0', SERVICE_IPC, SERVICE_FS },

    // DISK
    { 'A',  SERVICE_1+1, SERVICE_FS },
    { ':',  SERVICE_1+2, SERVICE_FS },
    { '\0', SERVICE_DISK, SERVICE_FS },

    { 0, SERVICE_FS, SERVICE_FS }
};

static const DCE2_SmbFsm dce2_ipc_share_fsm[] =
{
    { 'I', SHARE_0+1, SHARE_FS },
    { 'P', SHARE_0+2, SHARE_FS },
    { 'C', SHARE_0+3, SHARE_FS },
    { '$', SHARE_0+4, SHARE_FS },
    { '\0', SHARE_IPC, SHARE_FS },

    { 0, SHARE_FS, SHARE_FS }
};

static const DCE2_SmbFsm dce2_smb_os_fsm[] =
{
    // Windows start states
    { 'W', OS_0+1, OS_FS },
    { 'i', OS_0+2, OS_FS },
    { 'n', OS_0+3, OS_FS },
    { 'd', OS_0+4, OS_FS },
    { 'o', OS_0+5, OS_FS },
    { 'w', OS_0+6, OS_FS },
    { 's', OS_0+7, OS_FS },
    { ' ', OS_0+8, OS_FS },

    // Windows 2000 and XP server states
    { '5', OS_1+1, OS_2 },
    { '.', OS_1+2, OS_FS },
    { '1', OS_WINXP, OS_1+3 },    // Windows XP
    { '0', OS_WIN2000, OS_FS },   // Windows 2000

    // Windows 2000 or XP client states
    { '2', OS_2+1, OS_3 },
    { '0', OS_2+2, OS_FS },
    { '0', OS_2+3, OS_FS },
    { '2', OS_WINXP, OS_2+4 },    // Windows XP
    { '0', OS_WIN2000, OS_FS },   // Windows 2000

    // "Server" string states
    { 'S', OS_3+ 1, OS_4 },
    { 'e', OS_3+ 2, OS_FS },
    { 'r', OS_3+ 3, OS_FS },
    { 'v', OS_3+ 4, OS_FS },
    { 'e', OS_3+ 5, OS_FS },
    { 'r', OS_3+ 6, OS_FS },
    { ' ', OS_3+ 7, OS_FS },
    { '2', OS_3+ 8, OS_3+12 },
    { '0', OS_3+ 9, OS_FS },
    { '0', OS_3+10, OS_FS },
    { '3', OS_WIN2003, OS_3+11 },   // Windows Server 2003
    { '8', OS_WIN2008, OS_FS },     // Windows Server 2008R2

    // Windows 2008 has this, 2008 R2 does not
    { '(', OS_3+13, OS_FS },
    { 'R', OS_3+14, OS_FS },
    { ')', OS_3+15, OS_FS },
    { ' ', OS_3+16, OS_FS },
    { '2', OS_3+17, OS_FS },
    { '0', OS_3+18, OS_FS },
    { '0', OS_3+19, OS_FS },
    { '8', OS_WIN2008, OS_FS },

    // Windows Vista states
    { 'V', OS_4+1, OS_5 },
    { 'i', OS_4+2, OS_FS },
    { 's', OS_4+3, OS_FS },
    { 't', OS_4+4, OS_FS },
    { 'a', OS_WINVISTA, OS_FS },

    // Windows 7 state
    { '7', OS_WIN7, OS_6 },

    // Windows NT
    { 'N', OS_6+1, OS_7 },
    { 'T', OS_WIN2000, OS_FS },  // Windows NT, set policy to Windows 2000

    // Windows 98
    { '4', OS_7+1, OS_FS },
    { '.', OS_7+2, OS_FS },
    { '0', OS_WIN2000, OS_FS },  // Windows 98, set policy to Windows 2000

    // Failure state
    { 0, OS_FS, OS_FS }

    // Match states shouldn't be accessed
};

/********************************************************************
 * Private function prototypes
 *******************************************************************/
static inline void DCE2_SmbCheckFmtData(DCE2_SmbSsnData*, const uint32_t,
    const uint16_t, const uint8_t, const uint16_t, const uint16_t);
static DCE2_Ret DCE2_SmbCheckData(DCE2_SmbSsnData*, const uint8_t*,
    const uint8_t*, const uint32_t, const uint16_t, const uint32_t, uint16_t);
static DCE2_Ret DCE2_SmbWriteAndXRawRequest(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);

/*********************************************************************
 * Private functions
 ********************************************************************/

/********************************************************************
 * Function: DCE2_SmbCheckFmtData()
 *
 * Purpose:
 *  Checks the data count in commands with formats, e.g.
 *  SMB_COM_WRITE, SMB_COM_WRITE_AND_CLOSE, SMB_COM_WRITE_AND_UNLOCK.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - SMB session data structure
 *  const uint32_t    - remaining NetBIOS PDU length
 *  const uint16_t    - advertised byte count
 *  const uint8_t     - data format specifier
 *  const uint16_t    - data count reported in command
 *  const uint16_t    - data count reported in format field
 *
 * Returns: None
 *
 ********************************************************************/
static inline void DCE2_SmbCheckFmtData(DCE2_SmbSsnData*,
    const uint32_t nb_len, const uint16_t bcc, const uint8_t fmt,
    const uint16_t com_dcnt, const uint16_t fmt_dcnt)
{
    if (fmt != SMB_FMT__DATA_BLOCK)
        dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
    if (com_dcnt != fmt_dcnt)
        dce_alert(GID_DCE2, DCE2_SMB_DCNT_MISMATCH, (dce2CommonStats*)&dce2_smb_stats);
    if (com_dcnt != (bcc - 3))
        dce_alert(GID_DCE2, DCE2_SMB_INVALID_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
    if (nb_len < com_dcnt)
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
}

/********************************************************************
 * Function: DCE2_SmbCheckData()
 *
 * Purpose:
 *  Ensures that the data size reported in an SMB command is kosher.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - SMB session data structure
 *  const uint8_t *   - pointer to start of SMB header where offset is
 *                      taken from.
 *  const uint8_t *   - current pointer - should be right after command
 *                      structure.
 *  const uint32_t    - remaining data left in PDU from current pointer.
 *  const uint16_t    - the byte count from the SMB command
 *  const uint16_t    - reported data count in SMB command
 *  const uint16_t    - reported data offset in SMB command
 *
 * Returns:
 *  DCE2_Ret -  DCE2_RET__ERROR if data should not be processed
 *              DCE2_RET__SUCCESS if data can be processed
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbCheckData(DCE2_SmbSsnData*,
    const uint8_t* smb_hdr_ptr, const uint8_t* nb_ptr,
    const uint32_t nb_len, const uint16_t bcc,
    const uint32_t dcnt, uint16_t doff)
{
    const uint8_t* offset = smb_hdr_ptr + doff;
    const uint8_t* nb_end = nb_ptr + nb_len;

    // Byte counts don't usually matter, so no error but still alert
    // Don't alert in the case where the data count is larger than what the
    // byte count can handle.  This can happen if CAP_LARGE_READX or
    // CAP_LARGE_WRITEX were negotiated.
    if ((dcnt <= UINT16_MAX) && (bcc < dcnt))
        dce_alert(GID_DCE2, DCE2_SMB_BCC_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);

    if (offset > nb_end)
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
        // Error if offset is beyond data left
        return DCE2_RET__ERROR;
    }

    // Only check if the data count is non-zero
    if ((dcnt != 0) && (offset < nb_ptr))
    {
        // Not necessarily and error if the offset puts the data
        // before or in the command structure.
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
    }

    // Not necessarily an error if the addition of the data count goes
    // beyond the data left

    if (dcnt > (nb_end - offset))           // beyond data left
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_ANDX - raw mode
static DCE2_Ret DCE2_SmbWriteAndXRawRequest(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    // Set this now for possible reassembled packet
    uint16_t fid = SmbWriteAndXReqFid((const SmbWriteAndXReq*)nb_ptr);
    DCE2_SmbFileTracker* ftracker = DCE2_SmbGetFileTracker(ssd, fid);
    ssd->cur_rtracker->ftracker = ftracker;
    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

    // Got request to write in raw mode without having gotten the initial
    // raw mode request or got initial raw mode request and then another
    // without having finished the first.
    bool start_write_raw = SmbWriteAndXReqStartRaw((const SmbWriteAndXReq*)nb_ptr);
    bool continue_write_raw = SmbWriteAndXReqRaw((const SmbWriteAndXReq*)nb_ptr);
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    if ((start_write_raw && (ftracker->fp_writex_raw != nullptr)
        && (ftracker->fp_writex_raw->remaining != 0))
        || (continue_write_raw && ((ftracker->fp_writex_raw == nullptr)
        || (ftracker->fp_writex_raw->remaining == 0))))
    {
        switch (policy)
        {
        case DCE2_POLICY__WIN2000:
        case DCE2_POLICY__WINXP:
        case DCE2_POLICY__WINVISTA:
        case DCE2_POLICY__WIN2003:
        case DCE2_POLICY__WIN2008:
        case DCE2_POLICY__WIN7:
            if (ftracker->fp_writex_raw != nullptr)
            {
                ftracker->fp_writex_raw->remaining = 0;
                DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
            }
            return DCE2_RET__ERROR;
        case DCE2_POLICY__SAMBA:
        case DCE2_POLICY__SAMBA_3_0_37:
        case DCE2_POLICY__SAMBA_3_0_22:
        case DCE2_POLICY__SAMBA_3_0_20:
            // Samba doesn't do anything special here except if the two
            // flags are set it walks past the two "length" bytes.
            // See below.
            break;
        default:
            assert(false);
            break;
        }
    }

    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
    uint16_t doff = SmbWriteAndXReqDataOff((const SmbWriteAndXReq*)nb_ptr);
    uint32_t dcnt = SmbWriteAndXReqDataCnt((const SmbWriteAndXReq*)nb_ptr);
    uint16_t remaining = SmbWriteAndXReqRemaining((const SmbWriteAndXReq*)nb_ptr);

    DCE2_MOVE(nb_ptr, nb_len, com_size);

    if (DCE2_SmbCheckData(ssd, (const uint8_t*)smb_hdr, nb_ptr, nb_len,
        byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    // This may move backwards
    DCE2_MOVE(nb_ptr, nb_len, ((const uint8_t*)smb_hdr + doff) - nb_ptr);

    // If a "raw" write is requested there will be two bytes after the
    // header/pad and before the data which is supposed to represent a
    // length but everyone ignores it.  However we need to move past it.
    // This is the one situation where the remaining field matters and
    // should be equal to the total amount of data to be written.
    if (start_write_raw)
    {
        if (dcnt < 2)
            return DCE2_RET__ERROR;

        // From data size check above, nb_len >= dsize
        dcnt -= 2;
        DCE2_MOVE(nb_ptr, nb_len, 2);
    }

    if (dcnt > nb_len)
        dcnt = nb_len;

    // File tracker already validated
    switch (policy)
    {
    case DCE2_POLICY__WIN2000:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
        if (start_write_raw)
        {
            if (ftracker->fp_writex_raw == nullptr)
            {
                ftracker->fp_writex_raw = (DCE2_SmbWriteAndXRaw*)
                    snort_calloc(sizeof(DCE2_SmbWriteAndXRaw));
                if (ftracker->fp_writex_raw == nullptr)
                    return DCE2_RET__ERROR;

                ftracker->fp_writex_raw->remaining = (int)remaining;
            }
        }

        ftracker->fp_writex_raw->remaining -= (int)dcnt;
        if (ftracker->fp_writex_raw->remaining < 0)
        {
            ftracker->fp_writex_raw->remaining = 0;
            DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
            return DCE2_RET__ERROR;
        }

        // If the "raw" write isn't finished in the first request
        // and haven't allocated a buffer yet.
        if (start_write_raw && (ftracker->fp_writex_raw->remaining != 0)
            && (ftracker->fp_writex_raw->buf == nullptr))
        {
            ftracker->fp_writex_raw->buf =
                DCE2_BufferNew(remaining, 0);
            if (ftracker->fp_writex_raw->buf == nullptr)
            {
                ftracker->fp_writex_raw->remaining = 0;
                return DCE2_RET__ERROR;
            }
        }

        // If data has to be added to buffer, i.e. not a start raw
        // or a start raw and more raw requests to come.
        if (!start_write_raw || (ftracker->fp_writex_raw->remaining != 0))
        {
            if (DCE2_BufferAddData(ftracker->fp_writex_raw->buf, nb_ptr,
                dcnt, DCE2_BufferLength(ftracker->fp_writex_raw->buf),
                DCE2_BUFFER_MIN_ADD_FLAG__IGNORE) != DCE2_RET__SUCCESS)
            {
                ftracker->fp_writex_raw->remaining = 0;
                DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
                return DCE2_RET__ERROR;
            }

            if (ftracker->fp_writex_raw->remaining == 0)
            {
                const uint8_t* data_ptr = DCE2_BufferData(ftracker->fp_writex_raw->buf);
                uint32_t data_len = DCE2_BufferLength(ftracker->fp_writex_raw->buf);
                snort::Packet* rpkt = DCE2_SmbGetRpkt(ssd,
                    &data_ptr, &data_len, DCE2_RPKT_TYPE__SMB_TRANS);

                if (rpkt == nullptr)
                {
                    DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
                    return DCE2_RET__ERROR;
                }

                (void)DCE2_SmbProcessRequestData(ssd, fid, data_ptr, data_len, 0);

                DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
            }
        }
        else
        {
            (void)DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt, 0);
        }

        // Windows doesn't process chained commands to raw WriteAndXs
        // so return error so it exits the loop.
        return DCE2_RET__ERROR;

    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
    case DCE2_POLICY__SAMBA_3_0_22:
    case DCE2_POLICY__SAMBA_3_0_20:
        // All Samba cares about is skipping the 2 byte "length"
        // if both flags are set.
        break;
    default:
        assert(false);
        break;
    }

    return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt, 0);
}

static inline void DCE2_SmbSetFingerprintedClient(DCE2_SmbSsnData* ssd)
{
    ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__FP_CLIENT;
}

static inline bool DCE2_SmbFingerprintedClient(DCE2_SmbSsnData* ssd)
{
    return ssd->ssn_state_flags & DCE2_SMB_SSN_STATE__FP_CLIENT;
}

static inline void DCE2_SmbSetFingerprintedServer(DCE2_SmbSsnData* ssd)
{
    ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__FP_SERVER;
}

static inline bool DCE2_SmbFingerprintedServer(DCE2_SmbSsnData* ssd)
{
    return ssd->ssn_state_flags & DCE2_SMB_SSN_STATE__FP_SERVER;
}

/********************************************************************
 * Functions:
 *   DCE2_SmbOpen()
 *   DCE2_SmbCreate()
 *   DCE2_SmbClose()
 *   DCE2_SmbRename()
 *   DCE2_SmbRead()
 *   DCE2_SmbWrite()
 *   DCE2_SmbCreateNew()
 *   DCE2_SmbLockAndRead()
 *   DCE2_SmbWriteAndUnlock()
 *   DCE2_SmbReadRaw()
 *   DCE2_SmbWriteRaw()
 *   DCE2_SmbWriteComplete()
 *   DCE2_SmbWriteAndClose()
 *   DCE2_SmbOpenAndX()
 *   DCE2_SmbReadAndX()
 *   DCE2_SmbWriteAndX()
 *   DCE2_SmbTreeConnect()
 *   DCE2_SmbTreeDisconnect()
 *   DCE2_SmbNegotiate()
 *   DCE2_SmbSessionSetupAndX()
 *   DCE2_SmbLogoffAndX()
 *   DCE2_SmbTreeConnectAndX()
 *   DCE2_SmbNtCreateAndX()
 *
 * Purpose: Process SMB command
 *
 * Arguments:
 *  DCE2_SmbSsnData *       - SMB session data structure
 *  const SmbNtHdr *        - SMB header structure (packet pointer)
 *  const DCE2_SmbComInfo * - Basic command information structure
 *  uint8_t *               - pointer to start of command (packet pointer)
 *  uint32_t                - remaining NetBIOS length
 *
 * Returns:
 *  DCE2_Ret - DCE2_RET__ERROR if something went wrong and/or processing
 *               should stop
 *             DCE2_RET__SUCCESS if processing should continue
 *
 ********************************************************************/

// SMB_COM_OPEN
DCE2_Ret DCE2_SmbOpen(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbFileTracker* ftracker;

        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid)
            && (SmbFileAttrsDirectory(SmbOpenRespFileAttrs((const SmbOpenResp*)nb_ptr))
            || SmbOpenForWriting(SmbOpenRespAccessMode((const SmbOpenResp*)nb_ptr))))
            return DCE2_RET__SUCCESS;

        ftracker = DCE2_SmbNewFileTracker(ssd, ssd->cur_rtracker->uid,
            ssd->cur_rtracker->tid, SmbOpenRespFid((const SmbOpenResp*)nb_ptr));
        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        DCE2_Update_Ftracker_from_ReqTracker(ftracker, ssd->cur_rtracker);

        if (!ftracker->is_ipc)
        {
            // This command can only be used to open an existing file
            ftracker->ff_file_size = SmbOpenRespFileSize((const SmbOpenResp*)nb_ptr);
        }
    }
    else
    {
        // Have at least 2 bytes of data based on byte count check done earlier

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (!SmbFmtAscii(*nb_ptr))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        ssd->cur_rtracker->file_name =
            DCE2_SmbGetFileName(nb_ptr, nb_len, SmbUnicode(smb_hdr),
            &ssd->cur_rtracker->file_name_size);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_CREATE
DCE2_Ret DCE2_SmbCreate(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbFileTracker* ftracker = DCE2_SmbNewFileTracker(
            ssd, ssd->cur_rtracker->uid, ssd->cur_rtracker->tid,
            SmbCreateRespFid((const SmbCreateResp*)nb_ptr));

        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        DCE2_Update_Ftracker_from_ReqTracker(ftracker, ssd->cur_rtracker);

        // Command creates or opens and truncates file to 0 so assume
        // upload.
        if (!ftracker->is_ipc)
            ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
    }
    else
    {
        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
        {
            uint16_t file_attrs = SmbCreateReqFileAttrs((const SmbCreateReq*)nb_ptr);

            if (SmbAttrDirectory(file_attrs))
                return DCE2_RET__IGNORE;

            if (SmbEvasiveFileAttrs(file_attrs))
                dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                    (dce2CommonStats*)&dce2_smb_stats);
        }

        // Have at least 2 bytes of data based on byte count check done earlier

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (!SmbFmtAscii(*nb_ptr))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        ssd->cur_rtracker->file_name =
            DCE2_SmbGetFileName(nb_ptr, nb_len, SmbUnicode(smb_hdr),
            &ssd->cur_rtracker->file_name_size);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_CLOSE
DCE2_Ret DCE2_SmbClose(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t fid = SmbCloseReqFid((const SmbCloseReq*)nb_ptr);

        // Set this for response
        ssd->cur_rtracker->ftracker = DCE2_SmbGetFileTracker(ssd, fid);

        if ((ssd->fb_ftracker != nullptr) && (ssd->fb_ftracker == ssd->cur_rtracker->ftracker))
        {
            FileVerdict verdict = DCE2_get_file_verdict(ssd);

            if ((verdict == FILE_VERDICT_BLOCK) || (verdict == FILE_VERDICT_REJECT))
                ssd->block_pdus = true;
        }
    }
    else
    {
        DCE2_SmbRemoveFileTracker(ssd, ssd->cur_rtracker->ftracker);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_RENAME
DCE2_Ret DCE2_SmbRename(DCE2_SmbSsnData*, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    // NOTE: This command is only processed for CVE-2006-4696 where the buffer
    // formats are invalid and has no bearing on DCE/RPC processing.

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least 4 bytes of data based on byte count check done earlier

        uint32_t i;

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (!SmbFmtAscii(*nb_ptr))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        if (SmbUnicode(smb_hdr))
        {
            for (i = 0; i < (nb_len - 1); i += 2)
            {
                if (*((const uint16_t*)(nb_ptr + i)) == 0)
                {
                    i += 2;  // move past null terminating bytes
                    break;
                }
            }
        }
        else
        {
            for (i = 0; i < nb_len; i++)
            {
                if (nb_ptr[i] == 0)
                {
                    i++;  // move past null terminating byte
                    break;
                }
            }
        }

        // i <= nb_len
        DCE2_MOVE(nb_ptr, nb_len, i);

        if ((nb_len > 0) && !SmbFmtAscii(*nb_ptr))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }
    }

    // Don't care about tracking response
    return DCE2_RET__ERROR;
}

// SMB_COM_READ
DCE2_Ret DCE2_SmbRead(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        DCE2_SmbFileTracker* ftracker =
            DCE2_SmbGetFileTracker(ssd, SmbReadReqFid((const SmbReadReq*)nb_ptr));

        // Set this for response since response doesn't have the Fid
        ssd->cur_rtracker->ftracker = ftracker;
        if ((ftracker != nullptr) && !ftracker->is_ipc)
            ssd->cur_rtracker->file_offset = SmbReadReqOffset((const SmbReadReq*)nb_ptr);
    }
    else
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t com_dcnt = SmbReadRespCount((const SmbReadResp*)nb_ptr);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t fmt_dcnt = snort::alignedNtohs((const uint16_t*)(nb_ptr + com_size + 1));

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        if (com_dcnt > nb_len)
            return DCE2_RET__ERROR;

        return DCE2_SmbProcessResponseData(ssd, nb_ptr, com_dcnt);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE
DCE2_Ret DCE2_SmbWrite(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t com_dcnt = SmbWriteReqCount((const SmbWriteReq*)nb_ptr);
        uint16_t fmt_dcnt = snort::alignedNtohs((const uint16_t*)(nb_ptr + com_size + 1));
        uint16_t fid = SmbWriteReqFid((const SmbWriteReq*)nb_ptr);
        uint32_t offset = SmbWriteReqOffset((const SmbWriteReq*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        if (com_dcnt == 0)
        {
            dce_alert(GID_DCE2, DCE2_SMB_DCNT_ZERO, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        if (com_dcnt > nb_len)
            com_dcnt = (uint16_t)nb_len;

        return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, com_dcnt, offset);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_CREATE_NEW
DCE2_Ret DCE2_SmbCreateNew(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbFileTracker* ftracker = DCE2_SmbNewFileTracker(
            ssd, ssd->cur_rtracker->uid, ssd->cur_rtracker->tid,
            SmbCreateNewRespFid((const SmbCreateNewResp*)nb_ptr));

        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        DCE2_Update_Ftracker_from_ReqTracker(ftracker, ssd->cur_rtracker);

        // Command creates a new file so assume upload.
        if (!ftracker->is_ipc)
            ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
    }
    else
    {
        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
        {
            uint16_t file_attrs = SmbCreateNewReqFileAttrs((const SmbCreateNewReq*)nb_ptr);

            if (SmbAttrDirectory(file_attrs))
                return DCE2_RET__IGNORE;

            if (SmbEvasiveFileAttrs(file_attrs))
                dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                    (dce2CommonStats*)&dce2_smb_stats);
        }

        // Have at least 2 bytes of data based on byte count check done earlier

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (!SmbFmtAscii(*nb_ptr))
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        ssd->cur_rtracker->file_name =
            DCE2_SmbGetFileName(nb_ptr, nb_len, SmbUnicode(smb_hdr),
            &ssd->cur_rtracker->file_name_size);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_LOCK_AND_READ
DCE2_Ret DCE2_SmbLockAndRead(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        DCE2_SmbFileTracker* ftracker =
            DCE2_SmbFindFileTracker(ssd, ssd->cur_rtracker->uid,
            ssd->cur_rtracker->tid, SmbLockAndReadReqFid((const SmbLockAndReadReq*)nb_ptr));

        // No sense in tracking response
        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        if (!ftracker->is_ipc)
            ssd->cur_rtracker->file_offset = SmbLockAndReadReqOffset((const SmbLockAndReadReq*)nb_ptr);

        // Set this for response
        ssd->cur_rtracker->ftracker = ftracker;
    }
    else
    {
        // Have at least 3 bytes of data based on byte count check done earlier
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t com_dcnt = SmbLockAndReadRespCount((const SmbLockAndReadResp*)nb_ptr);
        uint16_t fmt_dcnt = snort::alignedNtohs((const uint16_t*)(nb_ptr + com_size + 1));

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        if (com_dcnt == 0)
        {
            dce_alert(GID_DCE2, DCE2_SMB_DCNT_ZERO, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        if (com_dcnt > nb_len)
            com_dcnt = (uint16_t)nb_len;

        return DCE2_SmbProcessResponseData(ssd, nb_ptr, com_dcnt);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_AND_UNLOCK
DCE2_Ret DCE2_SmbWriteAndUnlock(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
    {
        if (DCE2_ComInfoIsBadLength(com_info) || DCE2_ComInfoIsInvalidWordCount(com_info))
            return DCE2_RET__ERROR;

        // These are special cases.  The write succeeds but the unlock fails
        // so an error response is returned but the data was actually written.
        if (DCE2_ComInfoIsResponse(com_info) && DCE2_ComInfoIsStatusError(com_info))
        {
            if (DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
            {
                if (!SmbErrorInvalidDeviceRequest(smb_hdr))
                    return DCE2_RET__ERROR;
            }
            else if (!SmbErrorRangeNotLocked(smb_hdr))
            {
                return DCE2_RET__ERROR;
            }
        }
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t com_dcnt = SmbWriteAndUnlockReqCount((const SmbWriteAndUnlockReq*)nb_ptr);
        uint16_t fmt_dcnt = snort::alignedNtohs((const uint16_t*)(nb_ptr + com_size + 1));
        uint16_t fid = SmbWriteAndUnlockReqFid((const SmbWriteAndUnlockReq*)nb_ptr);
        uint32_t offset = SmbWriteAndUnlockReqOffset((const SmbWriteAndUnlockReq*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        if (com_dcnt == 0)
        {
            dce_alert(GID_DCE2, DCE2_SMB_DCNT_ZERO, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        if (com_dcnt > nb_len)
            com_dcnt = (uint16_t)nb_len;

        return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, com_dcnt, offset);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_OPEN_ANDX
DCE2_Ret DCE2_SmbOpenAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        const uint16_t fid = SmbOpenAndXRespFid((const SmbOpenAndXResp*)nb_ptr);
        const uint16_t file_attrs = SmbOpenAndXRespFileAttrs((const SmbOpenAndXResp*)nb_ptr);
        const uint16_t resource_type = SmbOpenAndXRespResourceType((const SmbOpenAndXResp*)nb_ptr);
        DCE2_SmbFileTracker* ftracker = nullptr;

        // Set request tracker's current file tracker in case of chained commands
        switch (SmbAndXCom2((const SmbAndXCommon*)nb_ptr))
        {
        // This is in case in the request a write was chained to an open
        // in which case the write will be to the newly opened file
        case SMB_COM_WRITE:
        case SMB_COM_WRITE_ANDX:
        case SMB_COM_TRANSACTION:
        case SMB_COM_READ_ANDX:
            ftracker = DCE2_SmbDequeueTmpFileTracker(ssd, ssd->cur_rtracker, fid);
            break;
        default:
            break;
        }

        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid)
            && (SmbFileAttrsDirectory(file_attrs)
            || !SmbResourceTypeDisk(resource_type)))
        {
            if (ftracker != nullptr)
                DCE2_SmbRemoveFileTracker(ssd, ftracker);
            return DCE2_RET__SUCCESS;
        }

        if (ftracker == nullptr)
        {
            ftracker = DCE2_SmbNewFileTracker(ssd,
                ssd->cur_rtracker->uid, ssd->cur_rtracker->tid, fid);
            if (ftracker == nullptr)
                return DCE2_RET__ERROR;
        }

        DCE2_Update_Ftracker_from_ReqTracker(ftracker, ssd->cur_rtracker);

        if (!ftracker->is_ipc)
        {
            const uint16_t open_results = SmbOpenAndXRespOpenResults((const SmbOpenAndXResp*)nb_ptr);

            if (SmbOpenResultRead(open_results))
            {
                ftracker->ff_file_size = SmbOpenAndXRespFileSize((const SmbOpenAndXResp*)nb_ptr);
            }
            else
            {
                ftracker->ff_file_size = ssd->cur_rtracker->file_size;
                ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
            }
        }

        ssd->cur_rtracker->ftracker = ftracker;
    }
    else
    {
        uint32_t pad = 0;
        const bool unicode = SmbUnicode(smb_hdr);
        uint8_t null_bytes = unicode ? 2 : 1;

        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
        {
            uint16_t file_attrs = SmbOpenAndXReqFileAttrs((const SmbOpenAndXReq*)nb_ptr);

            if (SmbEvasiveFileAttrs(file_attrs))
                dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                    (dce2CommonStats*)&dce2_smb_stats);
            ssd->cur_rtracker->file_size = SmbOpenAndXReqAllocSize((const SmbOpenAndXReq*)nb_ptr);
        }

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (unicode)
            pad = (nb_ptr - (const uint8_t*)smb_hdr) & 1;

        if (nb_len < (pad + null_bytes))
            return DCE2_RET__ERROR;

        DCE2_MOVE(nb_ptr, nb_len, pad);

        // Samba allows chaining OpenAndX/NtCreateAndX so might have
        // already been set.
        if (ssd->cur_rtracker->file_name == nullptr)
        {
            ssd->cur_rtracker->file_name =
                DCE2_SmbGetFileName(nb_ptr, nb_len, unicode, &ssd->cur_rtracker->file_name_size);
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_READ_ANDX
DCE2_Ret DCE2_SmbReadAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        DCE2_SmbFileTracker* ftracker =
            DCE2_SmbGetFileTracker(ssd, SmbReadAndXReqFid((const SmbReadAndXReq*)nb_ptr));

        // No sense in tracking response
        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        if (!ftracker->is_ipc)
            ssd->cur_rtracker->file_offset = SmbReadAndXReqOffset((const SmbReadAndXExtReq*)nb_ptr);

        // Set this for response
        ssd->cur_rtracker->ftracker = ftracker;
    }
    else
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t doff = SmbReadAndXRespDataOff((const SmbReadAndXResp*)nb_ptr);
        uint32_t dcnt = SmbReadAndXRespDataCnt((const SmbReadAndXResp*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckData(ssd, (const uint8_t*)smb_hdr, nb_ptr, nb_len,
            byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        // This may move backwards
        DCE2_MOVE(nb_ptr, nb_len, ((const uint8_t*)smb_hdr + doff) - nb_ptr);

        if (dcnt > nb_len)
            dcnt = nb_len;

        return DCE2_SmbProcessResponseData(ssd, nb_ptr, dcnt);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_ANDX
DCE2_Ret DCE2_SmbWriteAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
    {
        DCE2_SmbFileTracker* ftracker = ssd->cur_rtracker->ftracker;

        if ((ftracker != nullptr) && ftracker->is_ipc
            && (ftracker->fp_writex_raw != nullptr))
        {
            ftracker->fp_writex_raw->remaining = 0;
            DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
        }

        return DCE2_RET__ERROR;
    }

    if (DCE2_ComInfoIsRequest(com_info)
        && (SmbWriteAndXReqStartRaw((const SmbWriteAndXReq*)nb_ptr)
        || SmbWriteAndXReqRaw((const SmbWriteAndXReq*)nb_ptr)))
    {
        DCE2_SmbFileTracker* ftracker =
            DCE2_SmbGetFileTracker(ssd, SmbWriteAndXReqFid((const SmbWriteAndXReq*)nb_ptr));

        // Raw mode is only applicable to named pipes.
        if ((ftracker != nullptr) && ftracker->is_ipc)
            return DCE2_SmbWriteAndXRawRequest(ssd, smb_hdr, com_info, nb_ptr, nb_len);
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t fid = SmbWriteAndXReqFid((const SmbWriteAndXReq*)nb_ptr);
        uint16_t doff = SmbWriteAndXReqDataOff((const SmbWriteAndXReq*)nb_ptr);
        uint32_t dcnt = SmbWriteAndXReqDataCnt((const SmbWriteAndXReq*)nb_ptr);
        uint64_t offset = SmbWriteAndXReqOffset((const SmbWriteAndXExtReq*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckData(ssd, (const uint8_t*)smb_hdr, nb_ptr, nb_len,
            byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        // This may move backwards
        DCE2_MOVE(nb_ptr, nb_len, ((const uint8_t*)smb_hdr + doff) - nb_ptr);

        if (dcnt > nb_len)
        {
            // Current Samba errors if data count is greater than data left
            if (DCE2_SsnGetPolicy(&ssd->sd) == DCE2_POLICY__SAMBA)
                return DCE2_RET__ERROR;

            // Windows and early Samba just use what's left
            dcnt = nb_len;
        }

        return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt, offset);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_SESSION_SETUP_ANDX
DCE2_Ret DCE2_SmbSessionSetupAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t max_multiplex =
            SmbSessionSetupAndXReqMaxMultiplex((const SmbLm10_SessionSetupAndXReq*)nb_ptr);

        if (max_multiplex < ssd->max_outstanding_requests)
            ssd->max_outstanding_requests = max_multiplex;

        if (!DCE2_SmbFingerprintedClient(ssd) && DCE2_GcSmbFingerprintClient(
            (dce2SmbProtoConf*)ssd->sd.config))
        {
            uint8_t increment = SmbUnicode(smb_hdr) ? 2 : 1;
            uint16_t word_count = DCE2_ComInfoWordCount(com_info);
            uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
            uint32_t i;

            DCE2_SmbSetFingerprintedClient(ssd);

            // OS and Lanman strings won't be in request
            if ((word_count != 13) && (word_count != 12))
                return DCE2_RET__SUCCESS;

            snort::Profile profile(dce2_smb_pstat_smb_fingerprint);

            if (word_count == 13)
            {
                uint16_t oem_pass_len =
                    SmbNt10SessionSetupAndXReqOemPassLen((const SmbNt10_SessionSetupAndXReq*)nb_ptr);
                uint16_t uni_pass_len =
                    SmbNt10SessionSetupAndXReqUnicodePassLen((const SmbNt10_SessionSetupAndXReq*)nb_ptr);

                DCE2_MOVE(nb_ptr, nb_len, com_size);

                if (((uint32_t)oem_pass_len + uni_pass_len) > nb_len)
                {
                    return DCE2_RET__ERROR;
                }

                DCE2_MOVE(nb_ptr, nb_len, (oem_pass_len + uni_pass_len));

                // If unicode there should be a padding byte if the password
                // lengths are even since the command length is odd
                if ((increment == 2) && (nb_len != 0) && !((oem_pass_len + uni_pass_len) & 1))
                    DCE2_MOVE(nb_ptr, nb_len, 1);
            }
            else  // Extended security blob version, word count of 12
            {
                uint16_t blob_len =
                    SmbSessionSetupAndXReqBlobLen((const SmbNt10_SessionSetupAndXExtReq*)nb_ptr);

                DCE2_MOVE(nb_ptr, nb_len, com_size);

                if (blob_len > nb_len)
                {
                    return DCE2_RET__ERROR;
                }

                DCE2_MOVE(nb_ptr, nb_len, blob_len);

                // If unicode there should be a padding byte if the blob
                // length is even since the command length is odd
                if ((increment == 2) && (nb_len != 0) && !(blob_len & 1))
                    DCE2_MOVE(nb_ptr, nb_len, 1);
            }

            // Attempting to fingerprint Client Windows/Samba version.
            // Move past Account and Domain strings
            // Blob version doesn't have these as they're in the blob
            if (DCE2_ComInfoWordCount(com_info) == 13)
            {
                int j;

                for (j = 0; j < 2; j++)
                {
                    while ((nb_len >= increment) && (*nb_ptr != '\0'))
                        DCE2_MOVE(nb_ptr, nb_len, increment);

                    // Just return success if we run out of data
                    if (nb_len < increment)
                    {
                        return DCE2_RET__SUCCESS;
                    }

                    // Move past NULL string terminator
                    DCE2_MOVE(nb_ptr, nb_len, increment);
                }
            }

            if (nb_len < increment)
            {
                return DCE2_RET__SUCCESS;
            }

            // Note the below is quick and dirty.  We're assuming the client
            // is kosher.  It's policy will be used when the server is
            // sending data to it.

            // Windows Vista and above don't put anything here
            if (*nb_ptr == '\0')
            {
                DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WINVISTA);
                return DCE2_RET__SUCCESS;
            }

            // Windows
            if (*nb_ptr == 'W')
            {
                int state = OS_0;
                int64_t rlen = (int64_t)nb_len;

                while ((rlen > 0) && (state < OS_FS))
                {
                    if (dce2_smb_os_fsm[state].input == (char)*nb_ptr)
                    {
                        state = dce2_smb_os_fsm[state].next_state;
                        DCE2_MOVE(nb_ptr, rlen, increment);
                    }
                    else
                    {
                        state = dce2_smb_os_fsm[state].fail_state;
                    }
                }

                switch (state)
                {
                case OS_WIN2000:
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN2000);
                    break;
                case OS_WINXP:
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WINXP);
                    break;
                case OS_WIN2003:
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN2003);
                    break;
                default:
                    break;
                }

                return DCE2_RET__SUCCESS;
            }

            // Samba puts "Unix" in the OS field
            if (*nb_ptr != 'U')
            {
                return DCE2_RET__SUCCESS;
            }

            // Move past OS string
            for (i = 0; (i < nb_len) && (nb_ptr[i] != '\0'); i += increment)
                ;

            if ((i + increment) >= nb_len)
            {
                return DCE2_RET__SUCCESS;
            }

            // Move to LanMan string
            DCE2_MOVE(nb_ptr, nb_len, i + increment);

            // Samba
            if (*nb_ptr == 'S')
            {
                DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA);
            }
        }
    }
    else
    {
        uint16_t uid = SmbUid(smb_hdr);

        DCE2_SmbInsertUid(ssd, uid);
        ssd->cur_rtracker->uid = uid;  // Set this in case there are chained commands

        if (!(ssd->ssn_state_flags & DCE2_SMB_SSN_STATE__NEGOTIATED))
            ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__NEGOTIATED;

        if (!DCE2_SmbFingerprintedServer(ssd) && DCE2_GcSmbFingerprintServer(
            (dce2SmbProtoConf*)ssd->sd.config))
        {
            uint8_t increment = SmbUnicode(smb_hdr) ? 2 : 1;
            uint32_t i;

            DCE2_SmbSetFingerprintedServer(ssd);

            // Set the policy based on what the server reports in the OS field
            // for Windows and the LanManager field for Samba

            if (DCE2_ComInfoByteCount(com_info) == 0)
                return DCE2_RET__SUCCESS;

            snort::Profile profile(dce2_smb_pstat_smb_fingerprint);

            if (DCE2_ComInfoWordCount(com_info) == 3)
            {
                DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

                // Word count 3 and Unicode has a one byte pad
                if ((increment == 2) && (nb_len != 0))
                    DCE2_MOVE(nb_ptr, nb_len, 1);
            }
            else  // Only valid word counts are 3 and 4
            {
                uint16_t blob_len = SmbSessionSetupAndXRespBlobLen(
                    (const SmbNt10_SessionSetupAndXExtResp*)nb_ptr);

                DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

                if (blob_len > nb_len)
                {
                    return DCE2_RET__ERROR;
                }

                DCE2_MOVE(nb_ptr, nb_len, blob_len);

                if ((increment == 2) && (nb_len != 0) && !(blob_len & 1))
                    DCE2_MOVE(nb_ptr, nb_len, 1);
            }

            // Attempting to fingerprint Server Windows/Samba version.
            // Note the below is quick and dirty.  We're assuming the server
            // is kosher.  It's policy will be used when the client is
            // sending data to it.
            if ((nb_len < increment) || (*nb_ptr == '\0'))
            {
                return DCE2_RET__SUCCESS;
            }

            // Windows
            if (*nb_ptr == 'W')
            {
                int state = OS_0;
                int64_t rlen = (int64_t)nb_len;

                while ((rlen > 0) && (state < OS_FS))
                {
                    if (dce2_smb_os_fsm[state].input == (char)*nb_ptr)
                    {
                        state = dce2_smb_os_fsm[state].next_state;
                        DCE2_MOVE(nb_ptr, rlen, increment);
                    }
                    else
                    {
                        state = dce2_smb_os_fsm[state].fail_state;
                    }
                }

                switch (state)
                {
                case OS_WIN2000:
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN2000);
                    break;
                case OS_WINXP:
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WINXP);
                    break;
                case OS_WIN2003:
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN2003);
                    break;
                case OS_WIN2008:
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN2008);
                    break;
                case OS_WINVISTA:
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WINVISTA);
                    break;
                case OS_WIN7:
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__WIN7);
                    break;
                default:
                    break;
                }

                return DCE2_RET__SUCCESS;
            }

            // Samba puts "Unix" in the OS field
            if (*nb_ptr != 'U')
            {
                return DCE2_RET__SUCCESS;
            }

            // Move past OS string
            for (i = 0; (i < nb_len) && (nb_ptr[i] != '\0'); i += increment)
                ;

            if ((i + increment) >= nb_len)
            {
                return DCE2_RET__SUCCESS;
            }

            // Move to LanMan string
            DCE2_MOVE(nb_ptr, nb_len, i + increment);

            // Samba
            if (*nb_ptr == 'S')
            {
                uint8_t r1 = 0;  // Release version first digit
                uint8_t r2 = 0;  // Release version second digit

                // Get Major version
                for (i = 0; (i < nb_len) && (*nb_ptr != '\0'); i += increment)
                {
                    if (isdigit((int)nb_ptr[i]))
                        break;
                }

                if ((i == nb_len) || (*nb_ptr == '\0'))
                {
                    return DCE2_RET__SUCCESS;
                }

                // If less than 3 set policy to earliest Samba policy we use
                if ((nb_ptr[i] == '0') || (nb_ptr[i] == '1') || (nb_ptr[i] == '2'))
                {
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA_3_0_20);
                    return DCE2_RET__SUCCESS;
                }

                // Need ".\d.\d\d" or ".\d.\d\x00"
                if (i + increment*5 > nb_len)
                {
                    return DCE2_RET__SUCCESS;
                }

                i += increment*2;

                // If it's not 0, then set to latest Samba policy we use
                if (nb_ptr[i] != '0')
                {
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA);
                    return DCE2_RET__SUCCESS;
                }

                r1 = nb_ptr[i + increment*2];
                r2 = nb_ptr[i + increment*3];

                // First digit is 1 or no second digit or 20, Samba 3.0.20
                if ((r1 == '1') || (r2 == '\0') || ((r1 == '2') && (r2 == '0')))
                {
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA_3_0_20);
                    return DCE2_RET__SUCCESS;
                }

                // 21 or 22, Samba 3.0.22
                if ((r1 == '2') && (r2 <= '2'))
                {
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA_3_0_22);
                    return DCE2_RET__SUCCESS;
                }

                // 23, 24 ... 30 ... 37, Samba 3.0.37
                if ((r1 == '2') || ((r1 == '3') && (r2 <= '7')))
                {
                    DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA_3_0_37);
                    return DCE2_RET__SUCCESS;
                }

                DCE2_SsnSetPolicy(&ssd->sd, DCE2_POLICY__SAMBA);
            }
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_NEGOTIATE
DCE2_Ret DCE2_SmbNegotiate(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    snort::Profile profile(dce2_smb_pstat_smb_negotiate);

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least 2 bytes based on byte count check done earlier
        uint8_t* term_ptr;
        int ntlm_index = 0;
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        while ((term_ptr = (uint8_t*)memchr(nb_ptr, '\0', nb_len)) != nullptr)
        {
            if (!SmbFmtDialect(*nb_ptr))
            {
                dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);

                // Windows errors if bad format
                if (DCE2_SsnIsWindowsPolicy(&ssd->sd))
                {
                    return DCE2_RET__ERROR;
                }
            }

            // Move past format
            DCE2_MOVE(nb_ptr, nb_len, 1);

            if (nb_len == 0)
                break;

            // Just a NULL byte - acceptable by Samba and Windows
            if (term_ptr == nb_ptr)
                continue;

            if ((*nb_ptr == 'N')
                && (strncmp((const char*)nb_ptr, SMB_DIALECT_NT_LM_012, term_ptr - nb_ptr) == 0))
                break;

            // Move past string and NULL byte
            DCE2_MOVE(nb_ptr, nb_len, (term_ptr - nb_ptr) + 1);

            ntlm_index++;
        }

        if (term_ptr != nullptr)
        {
            ssd->dialect_index = ntlm_index;
        }
        else
        {
            ssd->dialect_index = DCE2_SENTINEL;
            dce_alert(GID_DCE2, DCE2_SMB_DEPR_DIALECT_NEGOTIATED,
                (dce2CommonStats*)&dce2_smb_stats);
        }
    }
    else
    {
        const uint16_t dialect_index =
            SmbNegotiateRespDialectIndex((const SmbCore_NegotiateProtocolResp*)nb_ptr);

        if ((ssd->dialect_index != DCE2_SENTINEL) && (dialect_index != ssd->dialect_index))
            dce_alert(GID_DCE2, DCE2_SMB_DEPR_DIALECT_NEGOTIATED,
                (dce2CommonStats*)&dce2_smb_stats);

        ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__NEGOTIATED;

        if (DCE2_ComInfoWordCount(com_info) == 17)
        {
            ssd->max_outstanding_requests =
                SmbNt_NegotiateRespMaxMultiplex((const SmbNt_NegotiateProtocolResp*)nb_ptr);
        }
        else if (DCE2_ComInfoWordCount(com_info) == 13)
        {
            ssd->max_outstanding_requests =
                SmbLm_NegotiateRespMaxMultiplex((const SmbLm10_NegotiateProtocolResp*)nb_ptr);
        }
        else
        {
            ssd->max_outstanding_requests = 1;
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TREE_CONNECT_ANDX
DCE2_Ret DCE2_SmbTreeConnectAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        if (DCE2_ScSmbInvalidShares((dce2SmbProtoConf*)ssd->sd.config) != nullptr)
        {
            uint16_t pass_len = SmbTreeConnectAndXReqPassLen((const SmbTreeConnectAndXReq*)nb_ptr);
            DCE2_MOVE(nb_ptr, nb_len, com_size);
            if (pass_len >= nb_len)
                return DCE2_RET__ERROR;

            // Move past password length
            DCE2_MOVE(nb_ptr, nb_len, pass_len);

            const uint8_t* bs = nullptr;
            // Move past path components
            while ((bs = (const uint8_t*)memchr(nb_ptr, '\\', nb_len)) != nullptr)
                DCE2_MOVE(nb_ptr, nb_len, (bs - nb_ptr) + 1);

            // Move past NULL byte if unicode
            if (SmbUnicode(smb_hdr) && (nb_len != 0))
                DCE2_MOVE(nb_ptr, nb_len, 1);

            if (nb_len != 0)
                DCE2_SmbInvalidShareCheck(ssd, smb_hdr, nb_ptr, nb_len);
        }
    }
    else
    {
        DCE2_MOVE(nb_ptr, nb_len, com_size);

        int state = SERVICE_0;
        while ((nb_len > 0) && (state < SERVICE_FS))
        {
            if (dce2_smb_service_fsm[state].input == (char)*nb_ptr)
            {
                state = dce2_smb_service_fsm[state].next_state;
                DCE2_MOVE(nb_ptr, nb_len, 1);
            }
            else
            {
                state = dce2_smb_service_fsm[state].fail_state;
            }
        }

        uint16_t tid = SmbTid(smb_hdr);
        bool is_ipc = true;
        switch (state)
        {
        case SERVICE_IPC:
            break;
        case SERVICE_DISK:
            is_ipc = false;
            break;
        default:
            return DCE2_RET__IGNORE;
        }

        // Insert tid into list
        DCE2_SmbInsertTid(ssd, tid, is_ipc);
        ssd->cur_rtracker->tid = tid;  // Set this in case there are chained commands
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TREE_CONNECT
DCE2_Ret DCE2_SmbTreeConnect(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);

        // Have at least 4 bytes of data based on byte count check done earlier

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        // If unicode flag is set, strings, except possibly the service string
        // are going to be unicode.  The NT spec specifies that unicode strings
        // must be word aligned with respect to the beginning of the SMB and that for
        // type-prefixed strings (this case), the padding byte is found after the
        // type format byte.

        // This byte will realign things.
        if (*nb_ptr != SMB_FMT__ASCII)
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_FORM, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, 1);

        // IPC$ does not need to be case sensitive.  And the case sensitivity flag in
        // the SMB header doesn't seem to have any effect on this.
        const uint8_t* bs = nullptr;
        while ((bs = (const uint8_t*)memchr(nb_ptr, '\\', nb_len)) != nullptr)
            DCE2_MOVE(nb_ptr, nb_len, (bs - nb_ptr) + 1);

        bool unicode = SmbUnicode(smb_hdr);
        if (unicode && (nb_len > 0))
            DCE2_MOVE(nb_ptr, nb_len, 1);

        // Check for invalid shares first
        if ((DCE2_ScSmbInvalidShares((dce2SmbProtoConf*)ssd->sd.config) != nullptr) && (nb_len >
            0))
            DCE2_SmbInvalidShareCheck(ssd, smb_hdr, nb_ptr, nb_len);

        int state = SHARE_0;
        uint8_t increment = unicode ? 2 : 1;
        while ((nb_len >= increment) && (state < SHARE_FS))
        {
            if (dce2_ipc_share_fsm[state].input == toupper((int)nb_ptr[0]))
            {
                if (unicode && (nb_ptr[1] != 0))
                    break;
                state = dce2_ipc_share_fsm[state].next_state;
                DCE2_MOVE(nb_ptr, nb_len, increment);
            }
            else
            {
                state = dce2_ipc_share_fsm[state].fail_state;
            }
        }

        bool is_ipc = false;
        switch (state)
        {
        case SHARE_IPC:
            is_ipc = true;
            break;
        case SHARE_FS:
        default:
            break;
        }

        ssd->cur_rtracker->is_ipc = is_ipc;
    }
    else
    {
        // FIXIT-L What if the TID in the SMB header differs from that returned
        // in the TreeConnect command response?
        uint16_t tid = SmbTid(smb_hdr);
        DCE2_SmbInsertTid(ssd, tid, ssd->cur_rtracker->is_ipc);
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_NT_CREATE_ANDX
DCE2_Ret DCE2_SmbNtCreateAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        const uint16_t fid = SmbNtCreateAndXRespFid((const SmbNtCreateAndXResp*)nb_ptr);
        DCE2_SmbFileTracker* ftracker = nullptr;

        // Set request tracker's current file tracker in case of chained commands
        switch (SmbAndXCom2((const SmbAndXCommon*)nb_ptr))
        {
        // This is in case in the request a write was chained to an open
        // in which case the write will be to the newly opened file
        case SMB_COM_WRITE:
        case SMB_COM_WRITE_ANDX:
        case SMB_COM_TRANSACTION:
        case SMB_COM_READ_ANDX:
            ftracker = DCE2_SmbDequeueTmpFileTracker(ssd, ssd->cur_rtracker, fid);
            break;
        default:
            break;
        }

        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
        {
            const bool is_directory = SmbNtCreateAndXRespDirectory((const SmbNtCreateAndXResp*)nb_ptr);
            const uint16_t resource_type =
                SmbNtCreateAndXRespResourceType((const SmbNtCreateAndXResp*)nb_ptr);

            if (is_directory || !SmbResourceTypeDisk(resource_type))
            {
                if (ftracker != nullptr)
                    DCE2_SmbRemoveFileTracker(ssd, ftracker);
                return DCE2_RET__SUCCESS;
            }

            // Give preference to files opened with the sequential only flag set
            if (((ssd->fapi_ftracker == nullptr) || !ssd->fapi_ftracker->ff_sequential_only)
                && (ftracker == nullptr) && ssd->cur_rtracker->sequential_only)
            {
                DCE2_SmbAbortFileAPI(ssd);
            }
        }

        if (ftracker == nullptr)
        {
            ftracker = DCE2_SmbNewFileTracker(ssd,
                ssd->cur_rtracker->uid, ssd->cur_rtracker->tid, fid);
            if (ftracker == nullptr)
                return DCE2_RET__ERROR;
        }

        DCE2_Update_Ftracker_from_ReqTracker(ftracker, ssd->cur_rtracker);

        if (!ftracker->is_ipc)
        {
            const uint32_t create_disposition =
                SmbNtCreateAndXRespCreateDisposition((const SmbNtCreateAndXResp*)nb_ptr);

            if (SmbCreateDispositionRead(create_disposition))
            {
                ftracker->ff_file_size =
                    SmbNtCreateAndXRespEndOfFile((const SmbNtCreateAndXResp*)nb_ptr);
            }
            else
            {
                ftracker->ff_file_size = ssd->cur_rtracker->file_size;
                ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
            }

            ftracker->ff_sequential_only = ssd->cur_rtracker->sequential_only;
        }

        ssd->cur_rtracker->ftracker = ftracker;
    }
    else
    {
        bool is_ipc = DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid);
        uint8_t smb_com2 = SmbAndXCom2((const SmbAndXCommon*)nb_ptr);
        uint16_t file_name_length =
            SmbNtCreateAndXReqFileNameLen((const SmbNtCreateAndXReq*)nb_ptr);

        if (!is_ipc)
        {
            uint32_t ext_file_attrs =
                SmbNtCreateAndXReqFileAttrs((const SmbNtCreateAndXReq*)nb_ptr);

            if (SmbEvasiveFileAttrs(ext_file_attrs))
                dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                    (dce2CommonStats*)&dce2_smb_stats);
            // If the file is going to be accessed sequentially, track it.
            if (SmbNtCreateAndXReqSequentialOnly((const SmbNtCreateAndXReq*)nb_ptr))
                ssd->cur_rtracker->sequential_only = true;

            ssd->cur_rtracker->file_size = SmbNtCreateAndXReqAllocSize(
                (const SmbNtCreateAndXReq*)nb_ptr);
        }

        DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

        if (file_name_length > DCE2_SMB_MAX_PATH_LEN)
            return DCE2_RET__ERROR;

        uint32_t pad = 0;
        const bool unicode = SmbUnicode(smb_hdr);
        if (unicode)
            pad = (nb_ptr - (const uint8_t*)smb_hdr) & 1;

        if (nb_len < (pad + file_name_length))
            return DCE2_RET__ERROR;

        DCE2_MOVE(nb_ptr, nb_len, pad);

        // Samba allows chaining OpenAndX/NtCreateAndX so might have
        // already been set.
        if (ssd->cur_rtracker->file_name == nullptr)
        {
            ssd->cur_rtracker->file_name =
                DCE2_SmbGetFileName(nb_ptr, file_name_length, unicode,
                &ssd->cur_rtracker->file_name_size);
        }

        if (is_ipc)
        {
            switch (smb_com2)
            {
            case SMB_COM_READ_ANDX:
                if (DCE2_SsnIsWindowsPolicy(&ssd->sd))
                    return DCE2_RET__ERROR;
                break;
            default:
                break;
            }
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TREE_DISCONNECT
DCE2_Ret DCE2_SmbTreeDisconnect(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t*, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
        DCE2_SmbRemoveTid(ssd, ssd->cur_rtracker->tid);

    return DCE2_RET__SUCCESS;
}

// SMB_COM_LOGOFF_ANDX
DCE2_Ret DCE2_SmbLogoffAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t*, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsResponse(com_info))
    {
        DCE2_SmbRemoveUid(ssd, ssd->cur_rtracker->uid);

        switch (DCE2_SsnGetServerPolicy(&ssd->sd))
        {
        case DCE2_POLICY__WIN2000:
        case DCE2_POLICY__WINXP:
        case DCE2_POLICY__WINVISTA:
        case DCE2_POLICY__WIN2003:
        case DCE2_POLICY__WIN2008:
        case DCE2_POLICY__WIN7:
            /* Windows responds to a chained LogoffAndX => SessionSetupAndX with a
             * word count 3 LogoffAndX without the chained SessionSetupAndX */
            if (DCE2_ComInfoWordCount(com_info) == 3)
            {
                uint16_t uid = SmbUid(smb_hdr);
                DCE2_SmbInsertUid(ssd, uid);
                ssd->cur_rtracker->uid = uid;      // Set this in case there are chained commands
            }
            break;
        default:
            break;
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_READ_RAW
DCE2_Ret DCE2_SmbReadRaw(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        DCE2_SmbFileTracker* ftracker =
            DCE2_SmbFindFileTracker(ssd, ssd->cur_rtracker->uid,
            ssd->cur_rtracker->tid, SmbReadRawReqFid((const SmbReadRawReq*)nb_ptr));

        ssd->cur_rtracker->ftracker = ftracker;
        ssd->pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
        if ((ftracker != nullptr) && !ftracker->is_ipc)
            ssd->cur_rtracker->file_offset = SmbReadRawReqOffset((const SmbReadRawExtReq*)nb_ptr);
    }
    else
    {
        // The server response is the raw data.  Supposedly if an error occurs,
        // the server will send a 0 byte read.  Just the NetBIOS header with
        // zero byte length.  Client upon getting the zero read is supposed to issue
        // another read using ReadAndX or Read to get the error.
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_RAW
DCE2_Ret DCE2_SmbWriteRaw(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t fid = SmbWriteRawReqFid((const SmbWriteRawReq*)nb_ptr);
        uint16_t tdcnt = SmbWriteRawReqTotalCount((const SmbWriteRawReq*)nb_ptr);
        bool writethrough = SmbWriteRawReqWriteThrough((const SmbWriteRawReq*)nb_ptr);
        uint16_t doff = SmbWriteRawReqDataOff((const SmbWriteRawReq*)nb_ptr);
        uint16_t dcnt = SmbWriteRawReqDataCnt((const SmbWriteRawReq*)nb_ptr);
        uint64_t offset = SmbWriteRawReqOffset((const SmbWriteRawExtReq*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckTotalCount(tdcnt, dcnt, 0) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (DCE2_SmbCheckData(ssd, (const uint8_t*)smb_hdr, nb_ptr, nb_len,
            byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        // This may move backwards
        DCE2_MOVE(nb_ptr, nb_len, ((const uint8_t*)smb_hdr + doff) - nb_ptr);

        if (dcnt > nb_len)
        {
            dce_alert(GID_DCE2, DCE2_SMB_NB_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        // If all of the data wasn't written in this request, the server will
        // send an interim SMB_COM_WRITE_RAW response and the client will send
        // the rest of the data raw.  In this case if the WriteThrough flag is
        // not set, the server will not send a final SMB_COM_WRITE_COMPLETE
        // response.  If all of the data is in this request the server will
        // send an SMB_COM_WRITE_COMPLETE response regardless of whether or
        // not the WriteThrough flag is set.
        if (dcnt != tdcnt)
        {
            ssd->cur_rtracker->writeraw_writethrough = writethrough;
            ssd->cur_rtracker->writeraw_remaining = tdcnt - dcnt;
        }

        return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt, offset);
    }
    else
    {
        DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);

        // Samba messes this up and sends a request instead of an interim
        // response and a response instead of a Write Complete response.
        switch (policy)
        {
        case DCE2_POLICY__SAMBA:
        case DCE2_POLICY__SAMBA_3_0_37:
        case DCE2_POLICY__SAMBA_3_0_22:
        case DCE2_POLICY__SAMBA_3_0_20:
            if (SmbType(smb_hdr) != SMB_TYPE__REQUEST)
                return DCE2_RET__SUCCESS;
            break;
        default:
            break;
        }

        // If all the data wasn't written initially this interim response will
        // be sent by the server and the raw data will ensue from the client.
        ssd->pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_COMPLETE
DCE2_Ret DCE2_SmbWriteComplete(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t*, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    return DCE2_RET__SUCCESS;
}

// SMB_COM_WRITE_AND_CLOSE
DCE2_Ret DCE2_SmbWriteAndClose(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // Have at least one byte based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t dcnt = SmbWriteAndCloseReqCount((const SmbWriteAndCloseReq*)nb_ptr);
        uint16_t fid = SmbWriteAndCloseReqFid((const SmbWriteAndCloseReq*)nb_ptr);
        uint32_t offset = SmbWriteAndCloseReqOffset((const SmbWriteAndCloseReq*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 1));

        if (DCE2_SmbCheckData(ssd, (const uint8_t*)smb_hdr, nb_ptr, nb_len,
            byte_count, dcnt,
            (uint16_t)(sizeof(SmbNtHdr) + com_size + 1)) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        if (dcnt == 0)
        {
            dce_alert(GID_DCE2, DCE2_SMB_DCNT_ZERO, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        // WriteAndClose has a 1 byte pad after the byte count
        if ((uint32_t)(dcnt + 1) != (uint32_t)byte_count)
            dce_alert(GID_DCE2, DCE2_SMB_INVALID_DSIZE, (dce2CommonStats*)&dce2_smb_stats);

        if (dcnt > nb_len)
            dcnt = (uint16_t)nb_len;

        return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt, offset);
    }
    else
    {
        DCE2_SmbRemoveFileTracker(ssd, ssd->cur_rtracker->ftracker);
    }

    return DCE2_RET__SUCCESS;
}
