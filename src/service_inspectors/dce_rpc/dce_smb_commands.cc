//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "dce_smb_commands.h"

#include "dce_smb_module.h"

#include "main/snort_debug.h"
#include "utils/util.h"
#include "detection/detect.h"

#define DCE2_SMB_TRANS__NONE    0x00
#define DCE2_SMB_TRANS__DATA    0x01
#define DCE2_SMB_TRANS__PARAMS  0x02
#define DCE2_SMB_TRANS__BOTH    (DCE2_SMB_TRANS__DATA|DCE2_SMB_TRANS__PARAMS)

enum SmbNtTransactSubcommand
{
    NT_TRANSACT_UNKNOWN_0000            = 0x0000,
    NT_TRANSACT_CREATE                  = 0x0001,
    NT_TRANSACT_IOCTL                   = 0x0002,
    NT_TRANSACT_SET_SECURITY_DESC       = 0x0003,
    NT_TRANSACT_NOTIFY_CHANGE           = 0x0004,
    NT_TRANSACT_RENAME                  = 0x0005,
    NT_TRANSACT_QUERY_SECURITY_DESC     = 0x0006,
    NT_TRANSACT_SUBCOM_MAX              = 0x0007
} SmbNtTransactSubcommand;

/********************************************************************
 * Global variables
 ********************************************************************/
const char* smb_transaction_sub_command_strings[TRANS_SUBCOM_MAX] =
{
    "Unknown",                               // 0x0000
    "TRANS_SET_NMPIPE_STATE",                // 0x0001
    "Unknown",                               // 0x0002
    "Unknown",                               // 0x0003
    "Unknown",                               // 0x0004
    "Unknown",                               // 0x0005
    "Unknown",                               // 0x0006
    "Unknown",                               // 0x0007
    "Unknown",                               // 0x0008
    "Unknown",                               // 0x0009
    "Unknown",                               // 0x000A
    "Unknown",                               // 0x000B
    "Unknown",                               // 0x000C
    "Unknown",                               // 0x000D
    "Unknown",                               // 0x000E
    "Unknown",                               // 0x000F
    "Unknown",                               // 0x0010
    "TRANS_RAW_READ_NMPIPE",                 // 0x0011
    "Unknown",                               // 0x0012
    "Unknown",                               // 0x0013
    "Unknown",                               // 0x0014
    "Unknown",                               // 0x0015
    "Unknown",                               // 0x0016
    "Unknown",                               // 0x0017
    "Unknown",                               // 0x0018
    "Unknown",                               // 0x0019
    "Unknown",                               // 0x001A
    "Unknown",                               // 0x001B
    "Unknown",                               // 0x001C
    "Unknown",                               // 0x001D
    "Unknown",                               // 0x001E
    "Unknown",                               // 0x001F
    "Unknown",                               // 0x0020
    "TRANS_QUERY_NMPIPE_STATE",              // 0x0021
    "TRANS_QUERY_NMPIPE_INFO",               // 0x0022
    "TRANS_PEEK_NMPIPE",                     // 0x0023
    "Unknown",                               // 0x0024
    "Unknown",                               // 0x0025
    "TRANS_TRANSACT_NMPIPE",                 // 0x0026
    "Unknown",                               // 0x0027
    "Unknown",                               // 0x0028
    "Unknown",                               // 0x0029
    "Unknown",                               // 0x002A
    "Unknown",                               // 0x002B
    "Unknown",                               // 0x002C
    "Unknown",                               // 0x002D
    "Unknown",                               // 0x002E
    "Unknown",                               // 0x002F
    "Unknown",                               // 0x0030
    "TRANS_RAW_WRITE_NMPIPE",                // 0x0031
    "Unknown",                               // 0x0032
    "Unknown",                               // 0x0033
    "Unknown",                               // 0x0034
    "Unknown",                               // 0x0035
    "TRANS_READ_NMPIPE",                     // 0x0036
    "TRANS_WRITE_NMPIPE",                    // 0x0037
    "Unknown",                               // 0x0038
    "Unknown",                               // 0x0039
    "Unknown",                               // 0x003A
    "Unknown",                               // 0x003B
    "Unknown",                               // 0x003C
    "Unknown",                               // 0x003D
    "Unknown",                               // 0x003E
    "Unknown",                               // 0x003F
    "Unknown",                               // 0x0040
    "Unknown",                               // 0x0041
    "Unknown",                               // 0x0042
    "Unknown",                               // 0x0043
    "Unknown",                               // 0x0044
    "Unknown",                               // 0x0045
    "Unknown",                               // 0x0046
    "Unknown",                               // 0x0047
    "Unknown",                               // 0x0048
    "Unknown",                               // 0x0049
    "Unknown",                               // 0x004A
    "Unknown",                               // 0x004B
    "Unknown",                               // 0x004C
    "Unknown",                               // 0x004D
    "Unknown",                               // 0x004E
    "Unknown",                               // 0x004F
    "Unknown",                               // 0x0050
    "Unknown",                               // 0x0051
    "Unknown",                               // 0x0052
    "TRANS_WAIT_NMPIPE",                     // 0x0053
    "TRANS_CALL_NMPIPE"                      // 0x0054
};

const char* smb_transaction2_sub_command_strings[TRANS2_SUBCOM_MAX] =
{
    "TRANS2_OPEN2",                          // 0x0000
    "TRANS2_FIND_FIRST2",                    // 0x0001
    "TRANS2_FIND_NEXT2",                     // 0x0002
    "TRANS2_QUERY_FS_INFORMATION",           // 0x0003
    "TRANS2_SET_FS_INFORMATION",             // 0x0004
    "TRANS2_QUERY_PATH_INFORMATION",         // 0x0005
    "TRANS2_SET_PATH_INFORMATION",           // 0x0006
    "TRANS2_QUERY_FILE_INFORMATION",         // 0x0007
    "TRANS2_SET_FILE_INFORMATION",           // 0x0008
    "TRANS2_FSCTL",                          // 0x0009
    "TRANS2_IOCTL2",                         // 0x000A
    "TRANS2_FIND_NOTIFY_FIRST",              // 0x000B
    "TRANS2_FIND_NOTIFY_NEXT",               // 0x000C
    "TRANS2_CREATE_DIRECTORY",               // 0x000D
    "TRANS2_SESSION_SETUP",                  // 0x000E
    "Unknown",                               // 0x000F
    "TRANS2_GET_DFS_REFERRAL",               // 0x0010
    "TRANS2_REPORT_DFS_INCONSISTENCY"        // 0x0011
};

const char* smb_nt_transact_sub_command_strings[NT_TRANSACT_SUBCOM_MAX] =
{
    "Unknown",                               // 0x0000
    "NT_TRANSACT_CREATE",                    // 0x0001
    "NT_TRANSACT_IOCTL",                     // 0x0002
    "NT_TRANSACT_SET_SECURITY_DESC",         // 0x0003
    "NT_TRANSACT_NOTIFY_CHANGE",             // 0x0004
    "NT_TRANSACT_RENAME",                    // 0x0005
    "NT_TRANSACT_QUERY_SECURITY_DESC"        // 0x0006
};

/********************************************************************
 * Private function prototypes
 ********************************************************************/
static DCE2_Ret DCE2_SmbUpdateTransRequest(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbUpdateTransResponse(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbValidateTransactionFields(const uint8_t*,
    const uint8_t*, const uint32_t, const uint16_t, const uint32_t,
    const uint32_t, const uint32_t, const uint32_t, const uint32_t,
    const uint32_t, const uint32_t, const uint32_t);
static DCE2_Ret DCE2_SmbCheckTransDataParams(
    const uint8_t*, const uint8_t*, const uint32_t, const uint16_t,
    const uint32_t, const uint32_t, const uint32_t, const uint32_t);
static DCE2_Ret DCE2_SmbCheckTotalCount(
    const uint32_t, const uint32_t, const uint32_t);
static DCE2_Ret DCE2_SmbValidateTransactionSent(
    uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
static DCE2_Ret DCE2_SmbTrans2Open2Req(DCE2_SmbSsnData*,
    const uint8_t*, uint32_t, bool);
static DCE2_Ret DCE2_SmbTrans2QueryFileInfoReq(DCE2_SmbSsnData*,
    const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbTrans2SetFileInfoReq(DCE2_SmbSsnData*,
    const uint8_t*, uint32_t, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbProcessRequestData(DCE2_SmbSsnData*, const uint16_t,
    const uint8_t*, uint32_t, uint64_t);
static DCE2_Ret DCE2_SmbProcessResponseData(DCE2_SmbSsnData*,
    const uint8_t*, uint32_t);
static inline void DCE2_SmbCheckFmtData(DCE2_SmbSsnData*, const uint32_t,
    const uint16_t, const uint8_t, const uint16_t, const uint16_t);
static inline DCE2_Ret DCE2_SmbCheckData(DCE2_SmbSsnData*, const uint8_t*,
    const uint8_t*, const uint32_t, const uint16_t, const uint32_t, uint16_t);
static DCE2_Ret DCE2_SmbWriteAndXRawRequest(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbNtTransactCreateReq(DCE2_SmbSsnData*,
    const uint8_t*, uint32_t, bool);
static DCE2_Ret DCE2_SmbUpdateTransSecondary(DCE2_SmbSsnData*, const SmbNtHdr*,
    const DCE2_SmbComInfo*, const uint8_t*, uint32_t);
static DCE2_Ret DCE2_SmbBufferTransactionData(DCE2_SmbTransactionTracker*,
    const uint8_t*, uint16_t, uint16_t);
static DCE2_Ret DCE2_SmbBufferTransactionParameters(DCE2_SmbTransactionTracker*,
    const uint8_t*, uint16_t, uint16_t);

/*********************************************************************
 * Private functions
 ********************************************************************/
static DCE2_Ret DCE2_SmbProcessRequestData(DCE2_SmbSsnData* ssd,
    const uint16_t fid, const uint8_t* data_ptr, uint32_t data_len, uint64_t offset)
{
    DCE2_SmbFileTracker* ftracker = DCE2_SmbGetFileTracker(ssd, fid);

    DebugFormat(DEBUG_DCE_SMB,
        "Entering Processing request data with Fid: 0x%04X, ftracker ? %s ~~~~~~~~~~~~~~~~~\n",
        fid,ftracker ? "TRUE" : "FALSE");
    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

    DebugFormat(DEBUG_DCE_SMB,
        "Processing request data with Fid: 0x%04X, is_ipc ? %s ~~~~~~~~~~~~~~~~~\n", ftracker->fid,
        ftracker->is_ipc ? "TRUE" : "FALSE");

    // Set this in case of chained commands or reassembled packet
    ssd->cur_rtracker->ftracker = ftracker;

    if (ftracker->is_ipc)
    {
        // Maximum possible fragment length is 16 bit
        if (data_len > UINT16_MAX)
            data_len = UINT16_MAX;

        DCE2_CoProcess(&ssd->sd, ftracker->fp_co_tracker, data_ptr, (uint16_t)data_len);

        if (!ftracker->fp_used)
            ftracker->fp_used = true;
    }
    else
    {
        ftracker->ff_file_offset = offset;
        // FIXIT-M uncomment when file processing is ported
        // DCE2_SmbProcessFileData(ssd, ftracker, data_ptr, data_len, true);
    }

    DebugMessage(DEBUG_DCE_SMB, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

    return DCE2_RET__SUCCESS;
}

static DCE2_Ret DCE2_SmbProcessResponseData(DCE2_SmbSsnData* ssd,
    const uint8_t* data_ptr, uint32_t data_len)
{
    DCE2_SmbFileTracker* ftracker = ssd->cur_rtracker->ftracker;

    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

    DebugFormat(DEBUG_DCE_SMB,
        "Processing response data with Fid: 0x%04X ~~~~~~~~~~~~~~~~\n", ftracker->fid);

    if (ftracker->is_ipc)
    {
        // Maximum possible fragment length is 16 bit
        if (data_len > UINT16_MAX)
            data_len = UINT16_MAX;

        DCE2_CoProcess(&ssd->sd, ftracker->fp_co_tracker, data_ptr, (uint16_t)data_len);
    }
    else
    {
        ftracker->ff_file_offset = ssd->cur_rtracker->file_offset;
        // FIXIT-M uncomment when file processing is ported
        //DCE2_SmbProcessFileData(ssd, ftracker, data_ptr, data_len, false);
    }

    DebugMessage(DEBUG_DCE_SMB, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

    return DCE2_RET__SUCCESS;
}

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
    if (((offset + dcnt) > nb_end)           // beyond data left
        || ((offset + dcnt) < offset))       // wrap
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
    }

    return DCE2_RET__SUCCESS;
}

// NT_TRANSACT_CREATE
static DCE2_Ret DCE2_SmbNtTransactCreateReq(DCE2_SmbSsnData* ssd,
    const uint8_t* param_ptr, uint32_t param_len, bool unicode)
{
    uint32_t pad = 0;
    uint32_t file_name_length;
    const uint8_t* param_start = param_ptr;

    if (param_len < sizeof(SmbNtTransactCreateReqParams))
        return DCE2_RET__ERROR;

    if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
    {
        uint32_t ext_file_attrs =
            SmbNtTransactCreateReqFileAttrs((SmbNtTransactCreateReqParams*)param_ptr);

        if (SmbEvasiveFileAttrs(ext_file_attrs))
            dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                (dce2CommonStats*)&dce2_smb_stats);

        // If the file is going to be accessed sequentially, track it.
        if (SmbNtTransactCreateReqSequentialOnly((SmbNtTransactCreateReqParams*)param_ptr))
            ssd->cur_rtracker->sequential_only = true;

        ssd->cur_rtracker->file_size =
            SmbNtTransactCreateReqAllocSize((SmbNtTransactCreateReqParams*)param_ptr);
    }

    file_name_length =
        SmbNtTransactCreateReqFileNameLength((SmbNtTransactCreateReqParams*)param_ptr);

    if (file_name_length > DCE2_SMB_MAX_PATH_LEN)
        return DCE2_RET__ERROR;

    DCE2_MOVE(param_ptr, param_len, sizeof(SmbNtTransactCreateReqParams));

    if (unicode)
        pad = (param_ptr - param_start) & 1;

    if (param_len < (pad + file_name_length))
        return DCE2_RET__ERROR;

    DCE2_MOVE(param_ptr, param_len, pad);

    ssd->cur_rtracker->file_name =
        DCE2_SmbGetString(param_ptr, file_name_length, unicode, false);

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbUpdateTransSecondary()
 *
 * Purpose:
 *  Handles common checks and updates of transaction secondary
 *  requests - SMB_COM_TRANSACTION_SECONDARY,
 *  SMB_COM_TRANSACTION2_SECONDARY and
 *  SMB_COM_NT_TRANSACT_SECONDARY
 *
 * Arguments:
 *  DCE2_SmbSsnData *       - pointer to SMB session data
 *  const SmbNtHdr *        - pointer to SMB header
 *  const DCE2_SmbComInfo * - pointer to com info structure
 *  const uint8_t *         - pointer to data
 *  uint32_t                - data length
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__IGNORE if we don't process the subcommand
 *      DCE2_RET__FULL if the transaction is complete
 *      DCE2_RET__ERROR if an error occurred.
 *      DCE2_RET__SUCCESS if ok (but not complete).
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbUpdateTransSecondary(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr, const DCE2_SmbComInfo* com_info,
    const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
    uint32_t tdcnt, doff, dcnt, ddisp;
    uint32_t tpcnt, poff, pcnt, pdisp;
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;
    uint16_t sub_com = ttracker->subcom;
    int data_params = DCE2_SMB_TRANS__NONE;
    uint8_t smb_com = DCE2_ComInfoSmbCom(com_info);

    switch (smb_com)
    {
    case SMB_COM_TRANSACTION_SECONDARY:
        tdcnt = SmbTransactionSecondaryReqTotalDataCnt((SmbTransactionSecondaryReq*)nb_ptr);
        doff = SmbTransactionSecondaryReqDataOff((SmbTransactionSecondaryReq*)nb_ptr);
        dcnt = SmbTransactionSecondaryReqDataCnt((SmbTransactionSecondaryReq*)nb_ptr);
        ddisp = SmbTransactionSecondaryReqDataDisp((SmbTransactionSecondaryReq*)nb_ptr);
        tpcnt = SmbTransactionSecondaryReqTotalParamCnt((SmbTransactionSecondaryReq*)nb_ptr);
        poff = SmbTransactionSecondaryReqParamOff((SmbTransactionSecondaryReq*)nb_ptr);
        pcnt = SmbTransactionSecondaryReqParamCnt((SmbTransactionSecondaryReq*)nb_ptr);
        pdisp = SmbTransactionSecondaryReqParamDisp((SmbTransactionSecondaryReq*)nb_ptr);

        switch (sub_com)
        {
        case TRANS_TRANSACT_NMPIPE:
        case TRANS_WRITE_NMPIPE:
            data_params = DCE2_SMB_TRANS__DATA;
            break;
        case TRANS_SET_NMPIPE_STATE:
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;
        default:
            return DCE2_RET__IGNORE;
        }
        break;

    case SMB_COM_TRANSACTION2_SECONDARY:
        tdcnt = SmbTransaction2SecondaryReqTotalDataCnt((SmbTransaction2SecondaryReq*)nb_ptr);
        doff = SmbTransaction2SecondaryReqDataOff((SmbTransaction2SecondaryReq*)nb_ptr);
        dcnt = SmbTransaction2SecondaryReqDataCnt((SmbTransaction2SecondaryReq*)nb_ptr);
        ddisp = SmbTransaction2SecondaryReqDataDisp((SmbTransaction2SecondaryReq*)nb_ptr);
        tpcnt = SmbTransaction2SecondaryReqTotalParamCnt((SmbTransaction2SecondaryReq*)nb_ptr);
        poff = SmbTransaction2SecondaryReqParamOff((SmbTransaction2SecondaryReq*)nb_ptr);
        pcnt = SmbTransaction2SecondaryReqParamCnt((SmbTransaction2SecondaryReq*)nb_ptr);
        pdisp = SmbTransaction2SecondaryReqParamDisp((SmbTransaction2SecondaryReq*)nb_ptr);

        switch (sub_com)
        {
        case TRANS2_OPEN2:
        case TRANS2_QUERY_FILE_INFORMATION:
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;
        case TRANS2_SET_FILE_INFORMATION:
            data_params = DCE2_SMB_TRANS__BOTH;
            break;
        default:
            return DCE2_RET__IGNORE;
        }
        break;

    case SMB_COM_NT_TRANSACT_SECONDARY:
        tdcnt = SmbNtTransactSecondaryReqTotalDataCnt((SmbNtTransactSecondaryReq*)nb_ptr);
        doff = SmbNtTransactSecondaryReqDataOff((SmbNtTransactSecondaryReq*)nb_ptr);
        dcnt = SmbNtTransactSecondaryReqDataCnt((SmbNtTransactSecondaryReq*)nb_ptr);
        ddisp = SmbNtTransactSecondaryReqDataDisp((SmbNtTransactSecondaryReq*)nb_ptr);
        tpcnt = SmbNtTransactSecondaryReqTotalParamCnt((SmbNtTransactSecondaryReq*)nb_ptr);
        poff = SmbNtTransactSecondaryReqParamOff((SmbNtTransactSecondaryReq*)nb_ptr);
        pcnt = SmbNtTransactSecondaryReqParamCnt((SmbNtTransactSecondaryReq*)nb_ptr);
        pdisp = SmbNtTransactSecondaryReqParamDisp((SmbNtTransactSecondaryReq*)nb_ptr);

        switch (sub_com)
        {
        case NT_TRANSACT_CREATE:
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;
        default:
            return DCE2_RET__IGNORE;
        }
        break;

    default:
        return DCE2_RET__ERROR;
    }

    if (DCE2_SsnIsSambaPolicy(&ssd->sd))
    {
        // If the total count decreases, Samba will reset this to the new
        // total count.
        if (tdcnt < ttracker->tdcnt)
            ttracker->tdcnt = tdcnt;
        if (tpcnt < ttracker->tpcnt)
            ttracker->tpcnt = tpcnt;
    }
    else
    {
        // Windows always uses the total data count from the first transaction.
        tdcnt = (uint16_t)ttracker->tdcnt;
        tpcnt = (uint16_t)ttracker->tpcnt;
    }

    DCE2_MOVE(nb_ptr, nb_len, com_size);

    if (DCE2_SmbValidateTransactionFields((uint8_t*)smb_hdr, nb_ptr, nb_len,
        byte_count, tdcnt, tpcnt, dcnt, doff, ddisp, pcnt, poff, pdisp) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    if (DCE2_SmbValidateTransactionSent(ttracker->dsent, dcnt, ttracker->tdcnt,
        ttracker->psent, pcnt, ttracker->tpcnt) != DCE2_RET__SUCCESS)
        return DCE2_RET__IGNORE;

    ttracker->dsent += dcnt;
    ttracker->psent += pcnt;

    DebugFormat(DEBUG_DCE_SMB, "Data displacement: %u, "
        "Data count: %u, Total data count: %u\n"
        "Parameter displacement: %u, "
        "Parameter count: %u, Total parameter count: %u\n",
        ddisp, dcnt, tdcnt, pdisp, pcnt, tpcnt);

    if (data_params & DCE2_SMB_TRANS__DATA)
    {
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

        if ((dcnt != 0)
            && (DCE2_SmbBufferTransactionData(ttracker, nb_ptr, dcnt, ddisp)
            != DCE2_RET__SUCCESS))
        {
            return DCE2_RET__ERROR;
        }
    }

    if (data_params & DCE2_SMB_TRANS__PARAMS)
    {
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + poff) - nb_ptr);

        if ((pcnt != 0)
            && (DCE2_SmbBufferTransactionParameters(ttracker, nb_ptr, pcnt, pdisp)
            != DCE2_RET__SUCCESS))
        {
            return DCE2_RET__ERROR;
        }
    }

    if ((ttracker->dsent == ttracker->tdcnt)
        && (ttracker->psent == ttracker->tpcnt))
    {
        return DCE2_RET__FULL;
    }

    return DCE2_RET__SUCCESS;
}

static DCE2_Ret DCE2_SmbBufferTransactionData(DCE2_SmbTransactionTracker* ttracker,
    const uint8_t* data_ptr, uint16_t dcnt, uint16_t ddisp)
{
    Profile profile(dce2_smb_pstat_smb_req);

    DebugMessage(DEBUG_DCE_SMB, "Buffering transaction data.\n");

    if (ttracker->dbuf == nullptr)
    {
        /* Buf size should be the total data count we need */
        ttracker->dbuf = DCE2_BufferNew(ttracker->tdcnt, 0);
    }

    if (DCE2_BufferAddData(ttracker->dbuf, data_ptr, dcnt, ddisp,
        DCE2_BUFFER_MIN_ADD_FLAG__IGNORE) != DCE2_RET__SUCCESS)
    {
        DebugMessage(DEBUG_DCE_SMB,
            "Failed to buffer transaction data.\n");
        return DCE2_RET__ERROR;
    }

    DebugMessage(DEBUG_DCE_SMB,
        "Successfully buffered transaction data.\n");

    return DCE2_RET__SUCCESS;
}

static DCE2_Ret DCE2_SmbBufferTransactionParameters(DCE2_SmbTransactionTracker* ttracker,
    const uint8_t* param_ptr, uint16_t pcnt, uint16_t pdisp)
{
    Profile profile(dce2_smb_pstat_smb_req);

    DebugMessage(DEBUG_DCE_SMB, "Buffering transaction parameters.\n");

    if (ttracker->pbuf == nullptr)
    {
        /* Buf size should be the total data count we need */
        ttracker->pbuf = DCE2_BufferNew(ttracker->tpcnt, 0);
    }

    if (DCE2_BufferAddData(ttracker->pbuf, param_ptr, pcnt, pdisp,
        DCE2_BUFFER_MIN_ADD_FLAG__IGNORE) != DCE2_RET__SUCCESS)
    {
        DebugMessage(DEBUG_DCE_SMB,
            "Failed to buffer transaction parameter data.\n");
        return DCE2_RET__ERROR;
    }

    DebugMessage(DEBUG_DCE_SMB,
        "Successfully buffered transaction parameter data.\n");

    return DCE2_RET__SUCCESS;
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
 *   DCE2_SmbTransaction()
 *   DCE2_SmbTransactionSecondary()
 *   DCE2_SmbWriteAndClose()
 *   DCE2_SmbOpenAndX()
 *   DCE2_SmbReadAndX()
 *   DCE2_SmbWriteAndX()
 *   DCE2_SmbTransaction2()
 *   DCE2_SmbTransaction2Secondary()
 *   DCE2_SmbTreeConnect()
 *   DCE2_SmbTreeDisconnect()
 *   DCE2_SmbNegotiate()
 *   DCE2_SmbSessionSetupAndX()
 *   DCE2_SmbLogoffAndX()
 *   DCE2_SmbTreeConnectAndX()
 *   DCE2_SmbNtTransact()
 *   DCE2_SmbNtTransactSecondary()
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
            && (SmbFileAttrsDirectory(SmbOpenRespFileAttrs((SmbOpenResp*)nb_ptr))
            || SmbOpenForWriting(SmbOpenRespAccessMode((SmbOpenResp*)nb_ptr))))
            return DCE2_RET__SUCCESS;

        ftracker = DCE2_SmbNewFileTracker(ssd, ssd->cur_rtracker->uid,
            ssd->cur_rtracker->tid, SmbOpenRespFid((SmbOpenResp*)nb_ptr));
        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        ftracker->file_name = ssd->cur_rtracker->file_name;
        ssd->cur_rtracker->file_name = nullptr;

        if (!ftracker->is_ipc)
        {
            // This command can only be used to open an existing file
            ftracker->ff_file_size = SmbOpenRespFileSize((SmbOpenResp*)nb_ptr);
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
            DCE2_SmbGetString(nb_ptr, nb_len, SmbUnicode(smb_hdr), false);
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
            SmbCreateRespFid((SmbCreateResp*)nb_ptr));

        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        ftracker->file_name = ssd->cur_rtracker->file_name;
        ssd->cur_rtracker->file_name = nullptr;

        // Command creates or opens and truncates file to 0 so assume
        // upload.
        if (!ftracker->is_ipc)
            ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
    }
    else
    {
        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
        {
            uint16_t file_attrs = SmbCreateReqFileAttrs((SmbCreateReq*)nb_ptr);

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
            DCE2_SmbGetString(nb_ptr, nb_len, SmbUnicode(smb_hdr), false);
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
        uint16_t fid = SmbCloseReqFid((SmbCloseReq*)nb_ptr);

        // Set this for response
        ssd->cur_rtracker->ftracker = DCE2_SmbGetFileTracker(ssd, fid);

        //FIXIT-M port active response related code
/*
#ifdef ACTIVE_RESPONSE
        if ((ssd->fb_ftracker != NULL) && (ssd->fb_ftracker == ssd->cur_rtracker->ftracker))
        {
            void *ssnptr = ssd->sd.wire_pkt->stream_session;
            void *p = (void *)ssd->sd.wire_pkt;
            File_Verdict verdict = DCE2_SmbGetFileVerdict(p, ssnptr);

            if ((verdict == FILE_VERDICT_BLOCK) || (verdict == FILE_VERDICT_REJECT))
                ssd->block_pdus = true;
        }
#endif
*/
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
                if (*((uint16_t*)(nb_ptr + i)) == 0)
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
            DCE2_SmbGetFileTracker(ssd, SmbReadReqFid((SmbReadReq*)nb_ptr));

        // Set this for response since response doesn't have the Fid
        ssd->cur_rtracker->ftracker = ftracker;
        if ((ftracker != nullptr) && !ftracker->is_ipc)
            ssd->cur_rtracker->file_offset = SmbReadReqOffset((SmbReadReq*)nb_ptr);
    }
    else
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t com_dcnt = SmbReadRespCount((SmbReadResp*)nb_ptr);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t fmt_dcnt = alignedNtohs((uint16_t*)(nb_ptr + com_size + 1));

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
        uint16_t com_dcnt = SmbWriteReqCount((SmbWriteReq*)nb_ptr);
        uint16_t fmt_dcnt = alignedNtohs((uint16_t*)(nb_ptr + com_size + 1));
        uint16_t fid = SmbWriteReqFid((SmbWriteReq*)nb_ptr);
        uint32_t offset = SmbWriteReqOffset((SmbWriteReq*)nb_ptr);

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
            SmbCreateNewRespFid((SmbCreateNewResp*)nb_ptr));

        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        ftracker->file_name = ssd->cur_rtracker->file_name;
        ssd->cur_rtracker->file_name = nullptr;

        // Command creates a new file so assume upload.
        if (!ftracker->is_ipc)
            ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
    }
    else
    {
        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
        {
            uint16_t file_attrs = SmbCreateNewReqFileAttrs((SmbCreateNewReq*)nb_ptr);

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
            DCE2_SmbGetString(nb_ptr, nb_len, SmbUnicode(smb_hdr), false);
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
            ssd->cur_rtracker->tid, SmbLockAndReadReqFid((SmbLockAndReadReq*)nb_ptr));

        // No sense in tracking response
        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        if (!ftracker->is_ipc)
            ssd->cur_rtracker->file_offset = SmbLockAndReadReqOffset((SmbLockAndReadReq*)nb_ptr);

        // Set this for response
        ssd->cur_rtracker->ftracker = ftracker;
    }
    else
    {
        // Have at least 3 bytes of data based on byte count check done earlier

        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint8_t fmt = *(nb_ptr + com_size);
        uint16_t com_dcnt = SmbLockAndReadRespCount((SmbLockAndReadResp*)nb_ptr);
        uint16_t fmt_dcnt = alignedNtohs((uint16_t*)(nb_ptr + com_size + 1));

        DCE2_MOVE(nb_ptr, nb_len, (com_size + 3));

        DCE2_SmbCheckFmtData(ssd, nb_len, byte_count, fmt, com_dcnt, fmt_dcnt);

        DebugFormat(DEBUG_DCE_SMB," SmbWriteLockAndRead dcnt %d\n", com_dcnt);
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
        // so an error reponse is returned but the data was actually written.
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
        uint16_t com_dcnt = SmbWriteAndUnlockReqCount((SmbWriteAndUnlockReq*)nb_ptr);
        uint16_t fmt_dcnt = alignedNtohs((uint16_t*)(nb_ptr + com_size + 1));
        uint16_t fid = SmbWriteAndUnlockReqFid((SmbWriteAndUnlockReq*)nb_ptr);
        uint32_t offset = SmbWriteAndUnlockReqOffset((SmbWriteAndUnlockReq*)nb_ptr);

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
        const uint16_t fid = SmbOpenAndXRespFid((SmbOpenAndXResp*)nb_ptr);
        const uint16_t file_attrs = SmbOpenAndXRespFileAttrs((SmbOpenAndXResp*)nb_ptr);
        const uint16_t resource_type = SmbOpenAndXRespResourceType((SmbOpenAndXResp*)nb_ptr);
        DCE2_SmbFileTracker* ftracker = nullptr;

        // Set request tracker's current file tracker in case of chained commands
        switch (SmbAndXCom2((SmbAndXCommon*)nb_ptr))
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

        ftracker->file_name = ssd->cur_rtracker->file_name;
        ssd->cur_rtracker->file_name = nullptr;

        if (!ftracker->is_ipc)
        {
            const uint16_t open_results = SmbOpenAndXRespOpenResults((SmbOpenAndXResp*)nb_ptr);

            if (SmbOpenResultRead(open_results))
            {
                ftracker->ff_file_size = SmbOpenAndXRespFileSize((SmbOpenAndXResp*)nb_ptr);
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
            uint16_t file_attrs = SmbOpenAndXReqFileAttrs((SmbOpenAndXReq*)nb_ptr);

            if (SmbEvasiveFileAttrs(file_attrs))
                dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                    (dce2CommonStats*)&dce2_smb_stats);
            ssd->cur_rtracker->file_size = SmbOpenAndXReqAllocSize((SmbOpenAndXReq*)nb_ptr);
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
                DCE2_SmbGetString(nb_ptr, nb_len, unicode, false);
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
            DCE2_SmbGetFileTracker(ssd, SmbReadAndXReqFid((SmbReadAndXReq*)nb_ptr));

        // No sense in tracking response
        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        if (!ftracker->is_ipc)
            ssd->cur_rtracker->file_offset = SmbReadAndXReqOffset((SmbReadAndXExtReq*)nb_ptr);

        // Set this for response
        ssd->cur_rtracker->ftracker = ftracker;
    }
    else
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t doff = SmbReadAndXRespDataOff((SmbReadAndXResp*)nb_ptr);
        uint32_t dcnt = SmbReadAndXRespDataCnt((SmbReadAndXResp*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckData(ssd, (uint8_t*)smb_hdr, nb_ptr, nb_len,
            byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        // This may move backwards
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

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
        && (SmbWriteAndXReqStartRaw((SmbWriteAndXReq*)nb_ptr)
        || SmbWriteAndXReqRaw((SmbWriteAndXReq*)nb_ptr)))
    {
        DCE2_SmbFileTracker* ftracker =
            DCE2_SmbGetFileTracker(ssd, SmbWriteAndXReqFid((SmbWriteAndXReq*)nb_ptr));

        // Raw mode is only applicable to named pipes.
        if ((ftracker != nullptr) && ftracker->is_ipc)
            return DCE2_SmbWriteAndXRawRequest(ssd, smb_hdr, com_info, nb_ptr, nb_len);
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
        uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
        uint16_t fid = SmbWriteAndXReqFid((SmbWriteAndXReq*)nb_ptr);
        uint16_t doff = SmbWriteAndXReqDataOff((SmbWriteAndXReq*)nb_ptr);
        uint32_t dcnt = SmbWriteAndXReqDataCnt((SmbWriteAndXReq*)nb_ptr);
        uint64_t offset = SmbWriteAndXReqOffset((SmbWriteAndXExtReq*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        if (DCE2_SmbCheckData(ssd, (uint8_t*)smb_hdr, nb_ptr, nb_len,
            byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;

        // This may move backwards
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

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

// SMB_COM_WRITE_ANDX - raw mode
static DCE2_Ret DCE2_SmbWriteAndXRawRequest(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    DebugMessage(DEBUG_DCE_SMB,
        "Processing WriteAndX with raw mode flags\n");

    // Set this now for possible reassembled packet
    uint16_t fid = SmbWriteAndXReqFid((SmbWriteAndXReq*)nb_ptr);
    DCE2_SmbFileTracker* ftracker = DCE2_SmbGetFileTracker(ssd, fid);
    ssd->cur_rtracker->ftracker = ftracker;
    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

    // Got request to write in raw mode without having gotten the initial
    // raw mode request or got initial raw mode request and then another
    // without having finished the first.
    bool start_write_raw = SmbWriteAndXReqStartRaw((SmbWriteAndXReq*)nb_ptr);
    bool continue_write_raw = SmbWriteAndXReqRaw((SmbWriteAndXReq*)nb_ptr);
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
            DebugFormat(DEBUG_DCE_SMB, "%s(%d) Invalid policy: %d",
                __FILE__, __LINE__, policy);
            break;
        }
    }

    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
    uint16_t doff = SmbWriteAndXReqDataOff((SmbWriteAndXReq*)nb_ptr);
    uint32_t dcnt = SmbWriteAndXReqDataCnt((SmbWriteAndXReq*)nb_ptr);
    uint16_t remaining = SmbWriteAndXReqRemaining((SmbWriteAndXReq*)nb_ptr);

    DCE2_MOVE(nb_ptr, nb_len, com_size);

    if (DCE2_SmbCheckData(ssd, (uint8_t*)smb_hdr, nb_ptr, nb_len,
        byte_count, dcnt, doff) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    // This may move backwards
    DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

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
                //FIXIT-M  - port Create reassembled packet
/*
                    const uint8_t *data_ptr = DCE2_BufferData(ftracker->fp_writex_raw->buf);
                    uint32_t data_len = DCE2_BufferLength(ftracker->fp_writex_raw->buf);
                    SFSnortPacket *rpkt = DCE2_SmbGetRpkt(ssd,
                            &data_ptr, &data_len, DCE2_RPKT_TYPE__SMB_TRANS);

                    if (rpkt == nullptr)
                    {
                        DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
                        return DCE2_RET__ERROR;
                    }

                    DebugMessage(DEBUG_DCE_SMB,
                                "Reassembled WriteAndX raw mode request\n"));
                    DCE2_DEBUG_CODE(DCE2_DEBUG__MAIN, DCE2_PrintPktData(rpkt->payload, rpkt->payload_size););

                    (void)DCE2_SmbProcessRequestData(ssd, fid, data_ptr, data_len, 0);

                    DCE2_SmbReturnRpkt();
                    DCE2_BufferEmpty(ftracker->fp_writex_raw->buf);
*/
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
        DebugFormat(DEBUG_DCE_SMB, "%s(%d) Invalid policy: %d",
            __FILE__, __LINE__, policy);
        break;
    }

    return DCE2_SmbProcessRequestData(ssd, fid, nb_ptr, dcnt, 0);
}

// SMB_COM_SESSION_SETUP_ANDX
DCE2_Ret DCE2_SmbSessionSetupAndX(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t max_multiplex =
            SmbSessionSetupAndXReqMaxMultiplex((SmbLm10_SessionSetupAndXReq*)nb_ptr);

        if (max_multiplex < ssd->max_outstanding_requests)
            ssd->max_outstanding_requests = max_multiplex;

        // FIXIT-M port fingerprint related code
    }
    else
    {
        uint16_t uid = SmbUid(smb_hdr);

        DCE2_SmbInsertUid(ssd, uid);
        ssd->cur_rtracker->uid = uid;  // Set this in case there are chained commands

        if (!(ssd->ssn_state_flags & DCE2_SMB_SSN_STATE__NEGOTIATED))
            ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__NEGOTIATED;

        // FIXIT-M port fingerprint related code
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_NEGOTIATE
DCE2_Ret DCE2_SmbNegotiate(DCE2_SmbSsnData* ssd, const SmbNtHdr*,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t)
{
    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    Profile profile(dce2_smb_pstat_smb_negotiate);

    if (DCE2_ComInfoIsRequest(com_info))
    {
        // FIXIT-M add dialect related code
    }
    else
    {
        // FIXIT-M add dialect related code

        ssd->ssn_state_flags |= DCE2_SMB_SSN_STATE__NEGOTIATED;

        if (DCE2_ComInfoWordCount(com_info) == 17)
        {
            ssd->max_outstanding_requests =
                SmbNt_NegotiateRespMaxMultiplex((SmbNt_NegotiateProtocolResp*)nb_ptr);
        }
        else if (DCE2_ComInfoWordCount(com_info) == 13)
        {
            ssd->max_outstanding_requests =
                SmbLm_NegotiateRespMaxMultiplex((SmbLm10_NegotiateProtocolResp*)nb_ptr);
        }
        else
        {
            ssd->max_outstanding_requests = 1;
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TREE_CONNECT_ANDX

#define SERVICE_0     (0)                // IPC start
#define SERVICE_1     (SERVICE_0+4)      // DISK start
#define SERVICE_FS    (SERVICE_1+3)      // Failure
#define SERVICE_IPC   (SERVICE_FS+1)     // IPC service
#define SERVICE_DISK  (SERVICE_FS+2)     // DISK service

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
            uint16_t pass_len = SmbTreeConnectAndXReqPassLen((SmbTreeConnectAndXReq*)nb_ptr);
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
            DebugFormat(DEBUG_DCE_SMB,
                "Tid (%hu) is an IPC tree.\n", tid);
            break;
        case SERVICE_DISK:
            is_ipc = false;
            DebugFormat(DEBUG_DCE_SMB,
                "Tid (%hu) is a DISK tree.\n", tid);
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

#define SHARE_0     (0)
#define SHARE_FS    (SHARE_0+5)
#define SHARE_IPC   (SHARE_FS+1)

static const DCE2_SmbFsm dce2_ipc_share_fsm[] =
{
    { 'I', SHARE_0+1, SHARE_FS },
    { 'P', SHARE_0+2, SHARE_FS },
    { 'C', SHARE_0+3, SHARE_FS },
    { '$', SHARE_0+4, SHARE_FS },
    { '\0', SHARE_IPC, SHARE_FS },

    { 0, SHARE_FS, SHARE_FS }
};

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

        DebugFormat(DEBUG_DCE_SMB, "Tid (%hu) %s an IPC tree\n", tid,
            (ssd->cur_rtracker->is_ipc) ? "is" : "is not");
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
        const uint16_t fid = SmbNtCreateAndXRespFid((SmbNtCreateAndXResp*)nb_ptr);
        DCE2_SmbFileTracker* ftracker = nullptr;

        // Set request tracker's current file tracker in case of chained commands
        switch (SmbAndXCom2((SmbAndXCommon*)nb_ptr))
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
            const bool is_directory = SmbNtCreateAndXRespDirectory((SmbNtCreateAndXResp*)nb_ptr);
            const uint16_t resource_type =
                SmbNtCreateAndXRespResourceType((SmbNtCreateAndXResp*)nb_ptr);

            if (is_directory || !SmbResourceTypeDisk(resource_type))
            {
                if (ftracker != nullptr)
                    DCE2_SmbRemoveFileTracker(ssd, ftracker);
                return DCE2_RET__SUCCESS;
            }

            // Give preference to files opened with the sequential only flag set
// FIXIT-M uncomment once fileApi is ported
/*
            if (((ssd->fapi_ftracker == nullptr) || !ssd->fapi_ftracker->ff_sequential_only)
                    && (ftracker == nullptr) && ssd->cur_rtracker->sequential_only)
            {
                DCE2_SmbAbortFileAPI(ssd);
            }
*/
        }

        if (ftracker == nullptr)
        {
            ftracker = DCE2_SmbNewFileTracker(ssd,
                ssd->cur_rtracker->uid, ssd->cur_rtracker->tid, fid);
            if (ftracker == nullptr)
                return DCE2_RET__ERROR;
        }

        ftracker->file_name = ssd->cur_rtracker->file_name;
        ssd->cur_rtracker->file_name = nullptr;

        DebugFormat(DEBUG_DCE_SMB, "File name: %s\n",
            (ftracker->file_name == nullptr) ? "nullptr" : ftracker->file_name);

        if (!ftracker->is_ipc)
        {
            const uint32_t create_disposition =
                SmbNtCreateAndXRespCreateDisposition((SmbNtCreateAndXResp*)nb_ptr);

            if (SmbCreateDispositionRead(create_disposition))
            {
                ftracker->ff_file_size =
                    SmbNtCreateAndXRespEndOfFile((SmbNtCreateAndXResp*)nb_ptr);
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
        uint8_t smb_com2 = SmbAndXCom2((SmbAndXCommon*)nb_ptr);
        uint16_t file_name_length =
            SmbNtCreateAndXReqFileNameLen((SmbNtCreateAndXReq*)nb_ptr);

        if (!is_ipc)
        {
            uint32_t ext_file_attrs =
                SmbNtCreateAndXReqFileAttrs((SmbNtCreateAndXReq*)nb_ptr);

            if (SmbEvasiveFileAttrs(ext_file_attrs))
                dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                    (dce2CommonStats*)&dce2_smb_stats);
            // If the file is going to be accessed sequentially, track it.
            if (SmbNtCreateAndXReqSequentialOnly((SmbNtCreateAndXReq*)nb_ptr))
                ssd->cur_rtracker->sequential_only = true;

            ssd->cur_rtracker->file_size = SmbNtCreateAndXReqAllocSize(
                (SmbNtCreateAndXReq*)nb_ptr);
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
                DCE2_SmbGetString(nb_ptr, file_name_length, unicode, false);
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

// SMB_COM_TRANSACTION Request
DCE2_Ret DCE2_SmbTransactionReq(DCE2_SmbSsnData* ssd,
    DCE2_SmbTransactionTracker* ttracker,
    const uint8_t* data_ptr, uint32_t data_len,
    const uint8_t* param_ptr, uint32_t param_len)
{
    switch (ttracker->subcom)
    {
    case TRANS_TRANSACT_NMPIPE:
    case TRANS_WRITE_NMPIPE:
        if (DCE2_SmbProcessRequestData(ssd, 0,
            data_ptr, data_len, 0) != DCE2_RET__SUCCESS)
            return DCE2_RET__ERROR;
        break;

    case TRANS_SET_NMPIPE_STATE:
        // Only two parameters but more seems okay
        if (param_len >= 2)
        {
            if ((alignedNtohs((uint16_t*)param_ptr) & PIPE_STATE_MESSAGE_MODE))
                ttracker->pipe_byte_mode = false;
            else
                ttracker->pipe_byte_mode = true;

            // Won't get a response
            if (DCE2_SsnIsWindowsPolicy(&ssd->sd) && ttracker->one_way)
            {
                DebugFormat(DEBUG_DCE_SMB,
                    "Setting pipe to %s mode\n",
                    ttracker->pipe_byte_mode ? "byte" : "message");

                ssd->cur_rtracker->ftracker->fp_byte_mode = ttracker->pipe_byte_mode;
            }
        }
        break;

    case TRANS_READ_NMPIPE:
        break;

    default:
        return DCE2_RET__IGNORE;
    }

    if (DCE2_SsnIsWindowsPolicy(&ssd->sd) && ttracker->one_way && ttracker->disconnect_tid)
        DCE2_SmbRemoveTid(ssd, ssd->cur_rtracker->tid);

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TRANSACTION

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

// Validates Name for Samba Transaction requests
static DCE2_Ret DCE2_SmbTransactionGetName(const uint8_t* nb_ptr,
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

DCE2_Ret DCE2_SmbTransaction(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;

    // Got a matching request for an in progress transaction - don't process it,
    // but don't want to remove tracker.
    if (DCE2_ComInfoIsRequest(com_info)
        && !DCE2_SmbIsTransactionComplete(ttracker))
    {
        DebugMessage(DEBUG_DCE_SMB, "Got new transaction request "
            "that matches an in progress transaction - not inspecting.\n");
        return DCE2_RET__ERROR;
    }

    // Avoid decoding/tracking \PIPE\LANMAN requests
    if (DCE2_ComInfoIsRequest(com_info)
        && (DCE2_ComInfoWordCount(com_info) != 16))
    {
        DebugMessage(DEBUG_DCE_SMB, "\\PIPE\\LANMAN request - not inspecting\n");
        return DCE2_RET__IGNORE;
    }

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    // Interim response is sent if client didn't send all data / parameters
    // in initial Transaction request and will have to complete the request
    // with TransactionSecondary commands.
    if (DCE2_ComInfoIsResponse(com_info)
        && (com_size == sizeof(SmbTransactionInterimResp)))
    {
        DebugMessage(DEBUG_DCE_SMB,
            "  Server Transaction interim response.\n");

        return DCE2_RET__SUCCESS;
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        DCE2_Ret status =
            DCE2_SmbUpdateTransRequest(ssd, smb_hdr, com_info, nb_ptr, nb_len);

        if (status != DCE2_RET__FULL)
            return status;

        ttracker->disconnect_tid = SmbTransactionReqDisconnectTid((SmbTransactionReq*)nb_ptr);
        ttracker->one_way = SmbTransactionReqOneWay((SmbTransactionReq*)nb_ptr);

        uint16_t doff = SmbTransactionReqDataOff((SmbTransactionReq*)nb_ptr);
        uint16_t dcnt = SmbTransactionReqDataCnt((SmbTransactionReq*)nb_ptr);
        uint16_t pcnt = SmbTransactionReqParamCnt((SmbTransactionReq*)nb_ptr);
        uint16_t poff = SmbTransactionReqParamOff((SmbTransactionReq*)nb_ptr);

        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);
        const uint8_t* data_ptr = nb_ptr;

        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + poff) - nb_ptr);
        const uint8_t* param_ptr = nb_ptr;

        status = DCE2_SmbTransactionReq(ssd, ttracker, data_ptr, dcnt, param_ptr, pcnt);
        if (status != DCE2_RET__SUCCESS)
            return status;
    }
    else
    {
        DCE2_Ret status =
            DCE2_SmbUpdateTransResponse(ssd, smb_hdr, com_info, nb_ptr, nb_len);

        if (status != DCE2_RET__FULL)
            return status;

        switch (ttracker->subcom)
        {
        case TRANS_TRANSACT_NMPIPE:
        case TRANS_READ_NMPIPE:
        {
            // FIXIT-M port reassembly case

            uint16_t dcnt = SmbTransactionRespDataCnt((SmbTransactionResp*)nb_ptr);
            uint16_t doff = SmbTransactionRespDataOff((SmbTransactionResp*)nb_ptr);

            DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

            if (DCE2_SmbProcessResponseData(ssd, nb_ptr, dcnt) != DCE2_RET__SUCCESS)
                return DCE2_RET__ERROR;

            break;
        }
        case TRANS_SET_NMPIPE_STATE:
            DebugFormat(DEBUG_DCE_SMB, "Setting pipe "
                "to %s mode\n", ttracker->pipe_byte_mode ? "byte" : "message");
            ssd->cur_rtracker->ftracker->fp_byte_mode = ttracker->pipe_byte_mode;
            break;

        case TRANS_WRITE_NMPIPE:
            break;

        default:
            return DCE2_RET__ERROR;
        }

        if (ttracker->disconnect_tid)
            DCE2_SmbRemoveTid(ssd, ssd->cur_rtracker->tid);
    }

    return DCE2_RET__SUCCESS;
}

#define DCE2_SMB_TRANS__NONE    0x00
#define DCE2_SMB_TRANS__DATA    0x01
#define DCE2_SMB_TRANS__PARAMS  0x02
#define DCE2_SMB_TRANS__BOTH    (DCE2_SMB_TRANS__DATA|DCE2_SMB_TRANS__PARAMS)

/********************************************************************
 * Function: DCE2_SmbUpdateTransRequest()
 *
 * Purpose:
 *  Handles common checks and updates of transaction requests -
 *  SMB_COM_TRANSACTION, SMB_COM_TRANSACTION2 and SMB_COM_NT_TRANSACT
 *
 * Arguments:
 *  DCE2_SmbSsnData *       - pointer to SMB session data
 *  const SmbNtHdr *        - pointer to SMB header
 *  const DCE2_SmbComInfo * - pointer to com info structure
 *  const uint8_t *         - pointer to data
 *  uint32_t                - data length
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__IGNORE if we don't process the subcommand
 *      DCE2_RET__FULL if the transaction is complete
 *      DCE2_RET__ERROR if an error occurred.
 *      DCE2_RET__SUCCESS if ok (but not complete).
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbUpdateTransRequest(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr, const DCE2_SmbComInfo* com_info,
    const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint32_t tpcnt, pcnt, poff;
    uint32_t tdcnt, dcnt, doff;
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    uint16_t byte_count = DCE2_ComInfoByteCount(com_info);
    uint16_t fid;
    uint8_t setup_count;
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;
    uint16_t sub_com =0;
    int data_params = DCE2_SMB_TRANS__NONE;
    uint8_t smb_com = DCE2_ComInfoSmbCom(com_info);

    switch (smb_com)
    {
    case SMB_COM_TRANSACTION:
        sub_com = SmbTransactionReqSubCom((SmbTransactionReq*)nb_ptr);
        fid = SmbTransactionReqFid((SmbTransactionReq*)nb_ptr);
        setup_count = SmbTransactionReqSetupCnt((SmbTransactionReq*)nb_ptr);
        tdcnt = SmbTransactionReqTotalDataCnt((SmbTransactionReq*)nb_ptr);
        doff = SmbTransactionReqDataOff((SmbTransactionReq*)nb_ptr);
        dcnt = SmbTransactionReqDataCnt((SmbTransactionReq*)nb_ptr);
        tpcnt = SmbTransactionReqTotalParamCnt((SmbTransactionReq*)nb_ptr);
        pcnt = SmbTransactionReqParamCnt((SmbTransactionReq*)nb_ptr);
        poff = SmbTransactionReqParamOff((SmbTransactionReq*)nb_ptr);

        DebugFormat(DEBUG_DCE_SMB,
            "Transaction subcommand: %s (0x%04X)\n",
            (sub_com < TRANS_SUBCOM_MAX)
            ? smb_transaction_sub_command_strings[sub_com]
            : "Unknown", sub_com);

        ssd->cur_rtracker->ftracker = DCE2_SmbGetFileTracker(ssd, fid);
        if (ssd->cur_rtracker->ftracker == nullptr)
            return DCE2_RET__IGNORE;

        switch (sub_com)
        {
        case TRANS_TRANSACT_NMPIPE:
            if (DCE2_SsnIsWindowsPolicy(&ssd->sd)
                && ssd->cur_rtracker->ftracker->fp_byte_mode)
            {
                DebugMessage(DEBUG_DCE_SMB, "Pipe is in byte "
                    "mode - TRANS_TRANSACT_NMPIPE won't work\n");
                return DCE2_RET__ERROR;
            }
            data_params = DCE2_SMB_TRANS__DATA;
            break;

        case TRANS_READ_NMPIPE:
            dce_alert(GID_DCE2, DCE2_SMB_UNUSUAL_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
            break;

        case TRANS_SET_NMPIPE_STATE:
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;

        case TRANS_WRITE_NMPIPE:
            dce_alert(GID_DCE2, DCE2_SMB_UNUSUAL_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
            data_params = DCE2_SMB_TRANS__DATA;
            break;

        // Not implemented according to MS-CIFS
        case TRANS_RAW_READ_NMPIPE:

        // Can only write 2 NULL bytes and subsequent writes return pipe disconnected
        case TRANS_RAW_WRITE_NMPIPE:

        // Can at most do a DCE/RPC bind
        case TRANS_CALL_NMPIPE:
            dce_alert(GID_DCE2, DCE2_SMB_DEPR_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
        // Aren't looking at these or the three above
        case TRANS_QUERY_NMPIPE_STATE:
        case TRANS_QUERY_NMPIPE_INFO:
        case TRANS_PEEK_NMPIPE:
        case TRANS_WAIT_NMPIPE:
        default:
            // Don't want to track the response
            return DCE2_RET__IGNORE;
        }

        // Servers return error if incorrect setup count
        if (setup_count != 2)
        {
            dce_alert(GID_DCE2, DCE2_SMB_INVALID_SETUP_COUNT, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        // Samba validates the Name which should be \PIPE\ and errors
        // if not.  Windows doesn't care.
        // And Samba uses the ByteCount to validate
        if (DCE2_SsnIsSambaPolicy(&ssd->sd)
            && (DCE2_SmbTransactionGetName(nb_ptr, nb_len,
            byte_count, SmbUnicode(smb_hdr)) != DCE2_RET__SUCCESS))
        {
            DebugMessage(DEBUG_DCE_SMB, "Failed to validate "
                "pipe name for Samba.\n");
            return DCE2_RET__ERROR;
        }
        break;

    case SMB_COM_TRANSACTION2:
        sub_com = SmbTransaction2ReqSubCom((SmbTransaction2Req*)nb_ptr);
        setup_count = SmbTransaction2ReqSetupCnt((SmbTransaction2Req*)nb_ptr);
        tdcnt = SmbTransaction2ReqTotalDataCnt((SmbTransaction2Req*)nb_ptr);
        doff = SmbTransaction2ReqDataOff((SmbTransaction2Req*)nb_ptr);
        dcnt = SmbTransaction2ReqDataCnt((SmbTransaction2Req*)nb_ptr);
        tpcnt = SmbTransaction2ReqTotalParamCnt((SmbTransaction2Req*)nb_ptr);
        pcnt = SmbTransaction2ReqParamCnt((SmbTransaction2Req*)nb_ptr);
        poff = SmbTransaction2ReqParamOff((SmbTransaction2Req*)nb_ptr);

        DebugFormat(DEBUG_DCE_SMB,
            "Transaction2 subcommand: %s (0x%04X)\n",
            (sub_com < TRANS2_SUBCOM_MAX)
            ? smb_transaction2_sub_command_strings[sub_com]
            : "Unknown", sub_com);

        switch (sub_com)
        {
        case TRANS2_OPEN2:
            dce_alert(GID_DCE2, DCE2_SMB_UNUSUAL_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;
        case TRANS2_QUERY_FILE_INFORMATION:
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;
        case TRANS2_SET_FILE_INFORMATION:
            data_params = DCE2_SMB_TRANS__BOTH;
            break;
        case TRANS2_FIND_FIRST2:
        case TRANS2_FIND_NEXT2:
        case TRANS2_QUERY_FS_INFORMATION:
        case TRANS2_SET_FS_INFORMATION:
        case TRANS2_QUERY_PATH_INFORMATION:
        case TRANS2_SET_PATH_INFORMATION:
        case TRANS2_FSCTL:
        case TRANS2_IOCTL2:
        case TRANS2_FIND_NOTIFY_FIRST:
        case TRANS2_FIND_NOTIFY_NEXT:
        case TRANS2_CREATE_DIRECTORY:
        case TRANS2_SESSION_SETUP:
        case TRANS2_GET_DFS_REFERRAL:
        case TRANS2_REPORT_DFS_INCONSISTENCY:
        default:
            // Don't want to process this transaction any more
            return DCE2_RET__IGNORE;
        }

        if (setup_count != 1)
        {
            dce_alert(GID_DCE2, DCE2_SMB_INVALID_SETUP_COUNT, (dce2CommonStats*)&dce2_smb_stats);
            return DCE2_RET__ERROR;
        }

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        break;

    case SMB_COM_NT_TRANSACT:
        sub_com = SmbNtTransactReqSubCom((SmbNtTransactReq*)nb_ptr);
        setup_count = SmbNtTransactReqSetupCnt((SmbNtTransactReq*)nb_ptr);
        tdcnt = SmbNtTransactReqTotalDataCnt((SmbNtTransactReq*)nb_ptr);
        doff = SmbNtTransactReqDataOff((SmbNtTransactReq*)nb_ptr);
        dcnt = SmbNtTransactReqDataCnt((SmbNtTransactReq*)nb_ptr);
        tpcnt = SmbNtTransactReqTotalParamCnt((SmbNtTransactReq*)nb_ptr);
        pcnt = SmbNtTransactReqParamCnt((SmbNtTransactReq*)nb_ptr);
        poff = SmbNtTransactReqParamOff((SmbNtTransactReq*)nb_ptr);

        DebugFormat(DEBUG_DCE_SMB,
            "Nt Transact subcommand: %s (0x%04X)\n",
            (sub_com < NT_TRANSACT_SUBCOM_MAX)
            ? smb_nt_transact_sub_command_strings[sub_com]
            : "Unknown", sub_com);

        switch (sub_com)
        {
        case NT_TRANSACT_CREATE:
            dce_alert(GID_DCE2, DCE2_SMB_UNUSUAL_COMMAND_USED, (dce2CommonStats*)&dce2_smb_stats);
            if (setup_count != 0)
            {
                dce_alert(GID_DCE2, DCE2_SMB_INVALID_SETUP_COUNT,
                    (dce2CommonStats*)&dce2_smb_stats);
                return DCE2_RET__ERROR;
            }
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;
        case NT_TRANSACT_IOCTL:
        case NT_TRANSACT_SET_SECURITY_DESC:
        case NT_TRANSACT_NOTIFY_CHANGE:
        case NT_TRANSACT_RENAME:
        case NT_TRANSACT_QUERY_SECURITY_DESC:
        default:
            // Don't want to process this transaction any more
            return DCE2_RET__IGNORE;
        }

        DCE2_MOVE(nb_ptr, nb_len, com_size);

        break;

    default:
        return DCE2_RET__ERROR;
    }

    if (DCE2_SmbValidateTransactionFields((uint8_t*)smb_hdr, nb_ptr, nb_len,
        byte_count, tdcnt, tpcnt, dcnt, doff, 0, pcnt, poff, 0) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    ttracker->smb_type = SMB_TYPE__REQUEST;
    ttracker->subcom = (uint8_t)sub_com;
    ttracker->tdcnt = tdcnt;
    ttracker->dsent = dcnt;
    ttracker->tpcnt = tpcnt;
    ttracker->psent = pcnt;

    DebugFormat(DEBUG_DCE_SMB, "Data count: %u, "
        "Total data count: %u, Param count: %u, "
        "Total param count: %u\n", dcnt, tdcnt, pcnt, tpcnt);

    // Testing shows that Transacts aren't processed until
    // all of the data and parameters are received, so overlapping
    // writes to the same FID can occur as long as the pid/mid are
    // distinct (and that depends on policy).  So we need to buffer
    // data up for each incomplete Transact so data doesn't get mangled
    // together with multiple ones intermixing at the same time.

    if (data_params & DCE2_SMB_TRANS__DATA)
    {
        if (tdcnt == 0)
            dce_alert(GID_DCE2, DCE2_SMB_DCNT_ZERO, (dce2CommonStats*)&dce2_smb_stats);

        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

        // If all of the data and parameters weren't sent, buffer what was sent
        if (((dcnt != tdcnt) || (pcnt != tpcnt)) && (dcnt != 0)
            && (DCE2_SmbBufferTransactionData(ttracker,
            nb_ptr, dcnt, 0) != DCE2_RET__SUCCESS))
        {
            return DCE2_RET__ERROR;
        }
    }

    if (data_params & DCE2_SMB_TRANS__PARAMS)
    {
        if (tpcnt == 0)
            dce_alert(GID_DCE2, DCE2_SMB_DCNT_ZERO, (dce2CommonStats*)&dce2_smb_stats);

        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + poff) - nb_ptr);

        // If all of the data and parameters weren't sent, buffer what was sent
        if (((pcnt != tpcnt) || (dcnt != tdcnt)) && (pcnt != 0)
            && (DCE2_SmbBufferTransactionParameters(ttracker,
            nb_ptr, pcnt, 0) != DCE2_RET__SUCCESS))
        {
            return DCE2_RET__ERROR;
        }
    }

    if ((dcnt == tdcnt) && (pcnt == tpcnt))
        return DCE2_RET__FULL;

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbUpdateTransResponse()
 *
 * Purpose:
 *  Handles common checks and updates of transaction responses -
 *  SMB_COM_TRANSACTION, SMB_COM_TRANSACTION2 and SMB_COM_NT_TRANSACT
 *
 * Arguments:
 *  DCE2_SmbSsnData *       - pointer to SMB session data
 *  const SmbNtHdr *        - pointer to SMB header
 *  const DCE2_SmbComInfo * - pointer to com info structure
 *  const uint8_t *         - pointer to data
 *  uint32_t                - data length
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__FULL if the transaction is complete
 *      DCE2_RET__ERROR if an error occurred.
 *      DCE2_RET__SUCCESS if ok (but not complete).
 *
 ********************************************************************/
static DCE2_Ret DCE2_SmbUpdateTransResponse(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr, const DCE2_SmbComInfo* com_info,
    const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint32_t tpcnt, pcnt, poff, pdisp;
    uint32_t tdcnt, dcnt, doff, ddisp;
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;
    uint16_t sub_com = ttracker->subcom;
    int data_params = DCE2_SMB_TRANS__NONE;
    uint8_t smb_com = DCE2_ComInfoSmbCom(com_info);

    switch (smb_com)
    {
    case SMB_COM_TRANSACTION:
        tdcnt = SmbTransactionRespTotalDataCnt((SmbTransactionResp*)nb_ptr);
        doff = SmbTransactionRespDataOff((SmbTransactionResp*)nb_ptr);
        dcnt = SmbTransactionRespDataCnt((SmbTransactionResp*)nb_ptr);
        ddisp = SmbTransactionRespDataDisp((SmbTransactionResp*)nb_ptr);
        tpcnt = SmbTransactionRespTotalParamCnt((SmbTransactionResp*)nb_ptr);
        pcnt = SmbTransactionRespParamCnt((SmbTransactionResp*)nb_ptr);
        poff = SmbTransactionRespParamOff((SmbTransactionResp*)nb_ptr);
        pdisp = SmbTransactionRespParamDisp((SmbTransactionResp*)nb_ptr);

        DebugFormat(DEBUG_DCE_SMB,
            "Transaction subcommand: %s (0x%04X)\n",
            (sub_com < TRANS_SUBCOM_MAX)
            ? smb_transaction_sub_command_strings[sub_com]
            : "Unknown", sub_com);

        switch (sub_com)
        {
        case TRANS_TRANSACT_NMPIPE:
        case TRANS_READ_NMPIPE:
            data_params = DCE2_SMB_TRANS__DATA;
            break;
        case TRANS_SET_NMPIPE_STATE:
        case TRANS_WRITE_NMPIPE:
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;
        default:
            return DCE2_RET__ERROR;
        }

        break;

    case SMB_COM_TRANSACTION2:
        tpcnt = SmbTransaction2RespTotalParamCnt((SmbTransaction2Resp*)nb_ptr);
        pcnt = SmbTransaction2RespParamCnt((SmbTransaction2Resp*)nb_ptr);
        poff = SmbTransaction2RespParamOff((SmbTransaction2Resp*)nb_ptr);
        pdisp = SmbTransaction2RespParamDisp((SmbTransaction2Resp*)nb_ptr);
        tdcnt = SmbTransaction2RespTotalDataCnt((SmbTransaction2Resp*)nb_ptr);
        dcnt = SmbTransaction2RespDataCnt((SmbTransaction2Resp*)nb_ptr);
        doff = SmbTransaction2RespDataOff((SmbTransaction2Resp*)nb_ptr);
        ddisp = SmbTransaction2RespDataDisp((SmbTransaction2Resp*)nb_ptr);

        DebugFormat(DEBUG_DCE_SMB,
            "Transaction2 subcommand: %s (0x%04X)\n",
            (sub_com < TRANS2_SUBCOM_MAX)
            ? smb_transaction2_sub_command_strings[sub_com]
            : "Unknown", sub_com);

        switch (sub_com)
        {
        case TRANS2_OPEN2:
        case TRANS2_SET_FILE_INFORMATION:
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;
        case TRANS2_QUERY_FILE_INFORMATION:
            data_params = DCE2_SMB_TRANS__DATA;
            break;
        default:
            return DCE2_RET__ERROR;
        }

        break;

    case SMB_COM_NT_TRANSACT:
        tpcnt = SmbNtTransactRespTotalParamCnt((SmbNtTransactResp*)nb_ptr);
        pcnt = SmbNtTransactRespParamCnt((SmbNtTransactResp*)nb_ptr);
        poff = SmbNtTransactRespParamOff((SmbNtTransactResp*)nb_ptr);
        pdisp = SmbNtTransactRespParamDisp((SmbNtTransactResp*)nb_ptr);
        tdcnt = SmbNtTransactRespTotalDataCnt((SmbNtTransactResp*)nb_ptr);
        dcnt = SmbNtTransactRespDataCnt((SmbNtTransactResp*)nb_ptr);
        doff = SmbNtTransactRespDataOff((SmbNtTransactResp*)nb_ptr);
        ddisp = SmbNtTransactRespDataDisp((SmbNtTransactResp*)nb_ptr);

        DebugFormat(DEBUG_DCE_SMB,
            "Nt Transact subcommand: %s (0x%04X)\n",
            (sub_com < NT_TRANSACT_SUBCOM_MAX)
            ? smb_nt_transact_sub_command_strings[sub_com]
            : "Unknown", sub_com);

        switch (sub_com)
        {
        case NT_TRANSACT_CREATE:
            data_params = DCE2_SMB_TRANS__PARAMS;
            break;
        default:
            return DCE2_RET__ERROR;
        }

        break;

    default:
        return DCE2_RET__ERROR;
    }

    DCE2_MOVE(nb_ptr, nb_len, DCE2_ComInfoCommandSize(com_info));

    // From client request
    if (ttracker->smb_type == SMB_TYPE__REQUEST)
    {
        ttracker->smb_type = SMB_TYPE__RESPONSE;
        ttracker->tdcnt = tdcnt;
        ttracker->tpcnt = tpcnt;
        ttracker->dsent = 0;
        ttracker->psent = 0;
        DCE2_BufferDestroy(ttracker->dbuf);
        ttracker->dbuf = nullptr;
        DCE2_BufferDestroy(ttracker->pbuf);
        ttracker->pbuf = nullptr;
    }
    else
    {
        if (tdcnt < ttracker->tdcnt)
            ttracker->tdcnt = tdcnt;
        if (tpcnt < ttracker->tpcnt)
            ttracker->tpcnt = pcnt;
    }

    if (DCE2_SmbValidateTransactionFields((uint8_t*)smb_hdr, nb_ptr, nb_len,
        DCE2_ComInfoByteCount(com_info), tdcnt, tpcnt, dcnt, doff, ddisp,
        pcnt, poff, pdisp) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    if (DCE2_SmbValidateTransactionSent(ttracker->dsent, dcnt, ttracker->tdcnt,
        ttracker->psent, pcnt, ttracker->tpcnt) != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    ttracker->dsent += dcnt;
    ttracker->psent += pcnt;

    DebugFormat(DEBUG_DCE_SMB, "Data displacement: %u, "
        "Data count: %u, Total data count: %u\n"
        "Parameter displacement: %u, "
        "Parameter count: %u, Total parameter count: %u\n",
        ddisp, dcnt, tdcnt, pdisp, pcnt, tpcnt);

    if (data_params & DCE2_SMB_TRANS__DATA)
    {
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

        if ((dcnt != 0)
            && (DCE2_SmbBufferTransactionData(ttracker, nb_ptr, dcnt, ddisp)
            != DCE2_RET__SUCCESS))
        {
            return DCE2_RET__ERROR;
        }
    }

    if (data_params & DCE2_SMB_TRANS__PARAMS)
    {
        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + poff) - nb_ptr);

        if ((pcnt != 0)
            && (DCE2_SmbBufferTransactionParameters(ttracker, nb_ptr, pcnt, pdisp)
            != DCE2_RET__SUCCESS))
        {
            return DCE2_RET__ERROR;
        }
    }

    if ((ttracker->dsent == ttracker->tdcnt)
        && (ttracker->psent == ttracker->tpcnt))
    {
        return DCE2_RET__FULL;
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
static DCE2_Ret DCE2_SmbCheckTotalCount(const uint32_t tcnt, const uint32_t cnt, const uint32_t
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

    // Check the data offset + data count
    if (((doffset + dcnt) > nb_end)            // beyond data left
        || ((doffset + dcnt) < doffset))       // wrap
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

    // Check the parameter offset + parameter count
    if (((poffset + pcnt) > nb_end)            // beyond data left
        || ((poffset + pcnt) < poffset))       // wrap
    {
        dce_alert(GID_DCE2, DCE2_SMB_NB_LT_DSIZE, (dce2CommonStats*)&dce2_smb_stats);
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
static DCE2_Ret DCE2_SmbValidateTransactionSent(
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
static inline DCE2_Ret DCE2_SmbValidateTransactionFields(
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

// SMB_COM_TRANSACTION2
DCE2_Ret DCE2_SmbTransaction2(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;

    // Got a matching request for an in progress transaction - don't process it,
    // but don't want to remove tracker.
    if (DCE2_ComInfoIsRequest(com_info)
        && !DCE2_SmbIsTransactionComplete(ttracker))
    {
        DebugMessage(DEBUG_DCE_SMB, "Got new transaction request "
            "that matches an in progress transaction - not inspecting.\n");
        return DCE2_RET__ERROR;
    }

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    // Interim response is sent if client didn't send all data / parameters
    // in initial Transaction2 request and will have to complete the request
    // with Transaction2Secondary commands.
    if (DCE2_ComInfoIsResponse(com_info)
        && (com_size == sizeof(SmbTransaction2InterimResp)))
    {
        return DCE2_RET__SUCCESS;
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint16_t pcnt = SmbTransaction2ReqParamCnt((SmbTransaction2Req*)nb_ptr);
        uint16_t poff = SmbTransaction2ReqParamOff((SmbTransaction2Req*)nb_ptr);
        uint16_t dcnt = SmbTransaction2ReqDataCnt((SmbTransaction2Req*)nb_ptr);
        uint16_t doff = SmbTransaction2ReqDataOff((SmbTransaction2Req*)nb_ptr);
        const uint8_t* data_ptr;
        DCE2_Ret status =
            DCE2_SmbUpdateTransRequest(ssd, smb_hdr, com_info, nb_ptr, nb_len);

        if (status != DCE2_RET__FULL)
            return status;

        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + poff) - nb_ptr);

        switch (ttracker->subcom)
        {
        case TRANS2_OPEN2:
            if (DCE2_SmbTrans2Open2Req(ssd, nb_ptr, pcnt,
                SmbUnicode(smb_hdr)) != DCE2_RET__SUCCESS)
                return DCE2_RET__ERROR;
            break;

        case TRANS2_QUERY_FILE_INFORMATION:
            status = DCE2_SmbTrans2QueryFileInfoReq(ssd, nb_ptr, pcnt);
            if (status != DCE2_RET__SUCCESS)
                return status;
            break;

        case TRANS2_SET_FILE_INFORMATION:
            data_ptr = nb_ptr;
            DCE2_MOVE(data_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - data_ptr);

            status = DCE2_SmbTrans2SetFileInfoReq(ssd, nb_ptr, pcnt, data_ptr, dcnt);
            if (status != DCE2_RET__SUCCESS)
                return status;
            break;

        default:
            return DCE2_RET__IGNORE;
        }
    }
    else
    {
        const uint8_t* ptr;
        uint32_t len;
        DCE2_SmbFileTracker* ftracker = nullptr;
        DCE2_Ret status =
            DCE2_SmbUpdateTransResponse(ssd, smb_hdr, com_info, nb_ptr, nb_len);

        if (status != DCE2_RET__FULL)
            return status;

        switch (ttracker->subcom)
        {
        case TRANS2_OPEN2:
            if (!DCE2_BufferIsEmpty(ttracker->pbuf))
            {
                ptr = DCE2_BufferData(ttracker->pbuf);
                len = DCE2_BufferLength(ttracker->pbuf);
            }
            else
            {
                uint16_t poff = SmbTransaction2RespParamOff((SmbTransaction2Resp*)nb_ptr);
                uint16_t pcnt = SmbTransaction2RespParamCnt((SmbTransaction2Resp*)nb_ptr);

                DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + poff) - nb_ptr);

                ptr = nb_ptr;
                len = pcnt;
            }

            if (len < sizeof(SmbTrans2Open2RespParams))
                return DCE2_RET__ERROR;

            if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid)
                && (SmbFileAttrsDirectory(SmbTrans2Open2RespFileAttrs(
                (SmbTrans2Open2RespParams*)ptr))
                || !SmbResourceTypeDisk(SmbTrans2Open2RespResourceType(
                (SmbTrans2Open2RespParams*)ptr))))
            {
                return DCE2_RET__SUCCESS;
            }

            ftracker = DCE2_SmbNewFileTracker(ssd, ssd->cur_rtracker->uid,
                ssd->cur_rtracker->tid, SmbTrans2Open2RespFid((SmbTrans2Open2RespParams*)ptr));
            if (ftracker == nullptr)
                return DCE2_RET__ERROR;

            ftracker->file_name = ssd->cur_rtracker->file_name;
            ssd->cur_rtracker->file_name = nullptr;

            if (!ftracker->is_ipc)
            {
                uint16_t open_results =
                    SmbTrans2Open2RespActionTaken((SmbTrans2Open2RespParams*)ptr);

                if (SmbOpenResultRead(open_results))
                {
                    ftracker->ff_file_size =
                        SmbTrans2Open2RespFileDataSize((SmbTrans2Open2RespParams*)ptr);
                }
                else
                {
                    ftracker->ff_file_size = ssd->cur_rtracker->file_size;
                    ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
                }
            }
            break;

        case TRANS2_QUERY_FILE_INFORMATION:
            ftracker = ssd->cur_rtracker->ftracker;
            if (ftracker == nullptr)
                return DCE2_RET__ERROR;

            if (!DCE2_BufferIsEmpty(ttracker->dbuf))
            {
                ptr = DCE2_BufferData(ttracker->dbuf);
                len = DCE2_BufferLength(ttracker->dbuf);
            }
            else
            {
                uint16_t doff = SmbTransaction2RespDataOff((SmbTransaction2Resp*)nb_ptr);
                uint16_t dcnt = SmbTransaction2RespDataCnt((SmbTransaction2Resp*)nb_ptr);

                DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + doff) - nb_ptr);

                ptr = nb_ptr;
                len = dcnt;
            }

            switch (ttracker->info_level)
            {
            case SMB_INFO_STANDARD:
                if (len >= sizeof(SmbQueryInfoStandard))
                {
                    ftracker->ff_file_size =
                        SmbQueryInfoStandardFileDataSize((SmbQueryInfoStandard*)ptr);
                }
                break;
            case SMB_INFO_QUERY_EA_SIZE:
                if (len >= sizeof(SmbQueryInfoQueryEaSize))
                {
                    ftracker->ff_file_size =
                        SmbQueryInfoQueryEaSizeFileDataSize((SmbQueryInfoQueryEaSize*)ptr);
                }
                break;
            case SMB_QUERY_FILE_STANDARD_INFO:
                if (len >= sizeof(SmbQueryFileStandardInfo))
                {
                    ftracker->ff_file_size =
                        SmbQueryFileStandardInfoEndOfFile((SmbQueryFileStandardInfo*)ptr);
                }
                break;
            case SMB_QUERY_FILE_ALL_INFO:
                if (len >= sizeof(SmbQueryFileAllInfo))
                {
                    ftracker->ff_file_size =
                        SmbQueryFileAllInfoEndOfFile((SmbQueryFileAllInfo*)ptr);
                }
                break;
            case SMB_INFO_PT_FILE_STANDARD_INFO:
                if (len >= sizeof(SmbQueryPTFileStreamInfo))
                {
                    ftracker->ff_file_size =
                        SmbQueryPTFileStreamInfoStreamSize((SmbQueryPTFileStreamInfo*)ptr);
                }
                break;
            case SMB_INFO_PT_FILE_STREAM_INFO:
                if (len >= sizeof(SmbQueryFileStandardInfo))
                {
                    ftracker->ff_file_size =
                        SmbQueryFileStandardInfoEndOfFile((SmbQueryFileStandardInfo*)ptr);
                }
                break;
            case SMB_INFO_PT_FILE_ALL_INFO:
                if (len >= sizeof(SmbQueryPTFileAllInfo))
                {
                    ftracker->ff_file_size =
                        SmbQueryPTFileAllInfoEndOfFile((SmbQueryPTFileAllInfo*)ptr);
                }
                break;
            case SMB_INFO_PT_NETWORK_OPEN_INFO:
                if (len >= sizeof(SmbQueryPTNetworkOpenInfo))
                {
                    ftracker->ff_file_size =
                        SmbQueryPTNetworkOpenInfoEndOfFile((SmbQueryPTNetworkOpenInfo*)ptr);
                }
                break;
            default:
                break;
            }
            break;

        case TRANS2_SET_FILE_INFORMATION:
            ftracker = ssd->cur_rtracker->ftracker;
            if (ftracker == nullptr)
                return DCE2_RET__ERROR;

            if (!DCE2_BufferIsEmpty(ttracker->pbuf))
            {
                ptr = DCE2_BufferData(ttracker->pbuf);
                len = DCE2_BufferLength(ttracker->pbuf);
            }
            else
            {
                uint16_t poff = SmbTransaction2RespParamOff((SmbTransaction2Resp*)nb_ptr);
                uint16_t pcnt = SmbTransaction2RespParamCnt((SmbTransaction2Resp*)nb_ptr);

                DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + poff) - nb_ptr);

                ptr = nb_ptr;
                len = pcnt;
            }

            // *ptr will be non-zero if there was an error.
            if ((len >= 2) && (*ptr == 0))
                ftracker->ff_file_size = ssd->cur_rtracker->file_size;
            break;

        default:
            break;
        }
    }

    return DCE2_RET__SUCCESS;
}

static inline bool DCE2_SmbFileUpload(DCE2_SmbFileDirection dir)
{
    return dir == DCE2_SMB_FILE_DIRECTION__UPLOAD;
}

static inline bool DCE2_SmbFileDownload(DCE2_SmbFileDirection dir)
{
    return dir == DCE2_SMB_FILE_DIRECTION__DOWNLOAD;
}

// TRANS2_OPEN2
static DCE2_Ret DCE2_SmbTrans2Open2Req(DCE2_SmbSsnData* ssd,
    const uint8_t* param_ptr, uint32_t param_len, bool unicode)
{
    if (param_len < sizeof(SmbTrans2Open2ReqParams))
        return DCE2_RET__ERROR;

    if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
    {
        uint16_t file_attrs =
            SmbTrans2Open2ReqFileAttrs((SmbTrans2Open2ReqParams*)param_ptr);

        if (SmbEvasiveFileAttrs(file_attrs))
            dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                (dce2CommonStats*)&dce2_smb_stats);

        ssd->cur_rtracker->file_size =
            SmbTrans2Open2ReqAllocSize((SmbTrans2Open2ReqParams*)param_ptr);
    }

    DCE2_MOVE(param_ptr, param_len, sizeof(SmbTrans2Open2ReqParams));

    ssd->cur_rtracker->file_name =
        DCE2_SmbGetString(param_ptr, param_len, unicode, false);

    return DCE2_RET__SUCCESS;
}

// TRANS2_QUERY_FILE_INFORMATION
static DCE2_Ret DCE2_SmbTrans2QueryFileInfoReq(DCE2_SmbSsnData* ssd,
    const uint8_t* param_ptr, uint32_t param_len)
{
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;
    DCE2_SmbFileTracker* ftracker;

    if (param_len < sizeof(SmbTrans2QueryFileInfoReqParams))
        return DCE2_RET__ERROR;

    ftracker = DCE2_SmbFindFileTracker(ssd,
        ssd->cur_rtracker->uid, ssd->cur_rtracker->tid,
        SmbTrans2QueryFileInfoReqFid((SmbTrans2QueryFileInfoReqParams*)param_ptr));

    if ((ftracker == nullptr) || ftracker->is_ipc
        || DCE2_SmbFileUpload(ftracker->ff_file_direction))
        return DCE2_RET__IGNORE;

    ttracker->info_level =
        SmbTrans2QueryFileInfoReqInfoLevel((SmbTrans2QueryFileInfoReqParams*)param_ptr);

    ssd->cur_rtracker->ftracker = ftracker;

    return DCE2_RET__SUCCESS;
}

// TRANS2_SET_FILE_INFORMATION
static DCE2_Ret DCE2_SmbTrans2SetFileInfoReq(DCE2_SmbSsnData* ssd,
    const uint8_t* param_ptr, uint32_t param_len,
    const uint8_t* data_ptr, uint32_t data_len)
{
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;
    DCE2_SmbFileTracker* ftracker;

    if ((param_len < sizeof(SmbTrans2SetFileInfoReqParams))
        || (data_len < sizeof(uint64_t)))
        return DCE2_RET__ERROR;

    ttracker->info_level =
        SmbTrans2SetFileInfoReqInfoLevel((SmbTrans2SetFileInfoReqParams*)param_ptr);

    // Check to see if there is an attempt to set READONLY/HIDDEN/SYSTEM
    // attributes on a file
    if (SmbSetFileInfoSetFileBasicInfo(ttracker->info_level)
        && (data_len >= sizeof(SmbSetFileBasicInfo)))
    {
        uint32_t ext_file_attrs =
            SmbSetFileInfoExtFileAttrs((SmbSetFileBasicInfo*)data_ptr);

        if (SmbEvasiveFileAttrs(ext_file_attrs))
            dce_alert(GID_DCE2, DCE2_SMB_EVASIVE_FILE_ATTRS,
                (dce2CommonStats*)&dce2_smb_stats);

        // Don't need to see the response
        return DCE2_RET__IGNORE;
    }

    // Only looking for end of file information for this subcommand
    if (!SmbSetFileInfoEndOfFile(ttracker->info_level))
        return DCE2_RET__IGNORE;

    ftracker = DCE2_SmbFindFileTracker(ssd,
        ssd->cur_rtracker->uid, ssd->cur_rtracker->tid,
        SmbTrans2SetFileInfoReqFid((SmbTrans2SetFileInfoReqParams*)param_ptr));

    if ((ftracker == nullptr) || ftracker->is_ipc
        || DCE2_SmbFileDownload(ftracker->ff_file_direction)
        || (ftracker->ff_bytes_processed != 0))
        return DCE2_RET__IGNORE;

    ssd->cur_rtracker->file_size = alignedNtohq((uint64_t*)data_ptr);
    ssd->cur_rtracker->ftracker = ftracker;

    return DCE2_RET__SUCCESS;
}

// SMB_COM_NT_TRANSACT
DCE2_Ret DCE2_SmbNtTransact(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    uint16_t com_size = DCE2_ComInfoCommandSize(com_info);
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;

    // NOTE: Only looking at NT_TRANSACT_CREATE as another way to open a named pipe

    // Got a matching request for an in progress transaction - don't process it,
    // but don't want to remove tracker.
    if (DCE2_ComInfoIsRequest(com_info)
        && !DCE2_SmbIsTransactionComplete(ttracker))
    {
        DebugMessage(DEBUG_DCE_SMB, "Got new transaction request "
            "that matches an in progress transaction - not inspecting.\n");
        return DCE2_RET__ERROR;
    }

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    // Interim response is sent if client didn't send all data / parameters
    // in initial NtTransact request and will have to complete the request
    // with NtTransactSecondary commands.
    if (DCE2_ComInfoIsResponse(com_info)
        && (com_size == sizeof(SmbNtTransactInterimResp)))
    {
        return DCE2_RET__SUCCESS;
    }

    if (DCE2_ComInfoIsRequest(com_info))
    {
        uint32_t pcnt = SmbNtTransactReqParamCnt((SmbNtTransactReq*)nb_ptr);
        uint32_t poff = SmbNtTransactReqParamOff((SmbNtTransactReq*)nb_ptr);
        DCE2_Ret status =
            DCE2_SmbUpdateTransRequest(ssd, smb_hdr, com_info, nb_ptr, nb_len);

        if (status != DCE2_RET__FULL)
            return status;

        DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + poff) - nb_ptr);

        switch (ttracker->subcom)
        {
        case NT_TRANSACT_CREATE:
            status = DCE2_SmbNtTransactCreateReq(ssd, nb_ptr, pcnt, SmbUnicode(smb_hdr));
            if (status != DCE2_RET__SUCCESS)
                return status;
            break;

        default:
            return DCE2_RET__IGNORE;
        }
    }
    else
    {
        const uint8_t* ptr;
        uint32_t len;
        DCE2_SmbFileTracker* ftracker = nullptr;

        DCE2_Ret status =
            DCE2_SmbUpdateTransResponse(ssd, smb_hdr, com_info, nb_ptr, nb_len);

        if (status != DCE2_RET__FULL)
            return status;

        if (!DCE2_BufferIsEmpty(ttracker->pbuf))
        {
            ptr = DCE2_BufferData(ttracker->pbuf);
            len = DCE2_BufferLength(ttracker->pbuf);
        }
        else
        {
            uint32_t poff = SmbNtTransactRespParamOff((SmbNtTransactResp*)nb_ptr);
            uint32_t pcnt = SmbNtTransactRespParamCnt((SmbNtTransactResp*)nb_ptr);

            DCE2_MOVE(nb_ptr, nb_len, ((uint8_t*)smb_hdr + poff) - nb_ptr);

            ptr = nb_ptr;
            len = pcnt;
        }

        if (len < sizeof(SmbNtTransactCreateRespParams))
            return DCE2_RET__ERROR;

        if (!DCE2_SmbIsTidIPC(ssd, ssd->cur_rtracker->tid))
        {
            const bool is_directory =
                SmbNtTransactCreateRespDirectory((SmbNtTransactCreateRespParams*)ptr);
            const uint16_t resource_type =
                SmbNtTransactCreateRespResourceType((SmbNtTransactCreateRespParams*)ptr);

            if (is_directory || !SmbResourceTypeDisk(resource_type))
                return DCE2_RET__SUCCESS;

            // FIXIT-M port as part of fileAPI user story
/*
            // Give preference to files opened with the sequential only flag set
            if (((ssd->fapi_ftracker == nullptr) || !ssd->fapi_ftracker->ff_sequential_only)
                    && ssd->cur_rtracker->sequential_only)
            {
                DCE2_SmbAbortFileAPI(ssd);
            }
*/
        }

        ftracker = DCE2_SmbNewFileTracker(ssd,
            ssd->cur_rtracker->uid, ssd->cur_rtracker->tid,
            SmbNtTransactCreateRespFid((SmbNtTransactCreateRespParams*)ptr));
        if (ftracker == nullptr)
            return DCE2_RET__ERROR;

        ftracker->file_name = ssd->cur_rtracker->file_name;
        ssd->cur_rtracker->file_name = nullptr;

        if (!ftracker->is_ipc)
        {
            uint32_t create_disposition =
                SmbNtTransactCreateRespCreateAction((SmbNtTransactCreateRespParams*)ptr);

            if (SmbCreateDispositionRead(create_disposition))
            {
                ftracker->ff_file_size =
                    SmbNtTransactCreateRespEndOfFile((SmbNtTransactCreateRespParams*)ptr);
            }
            else
            {
                ftracker->ff_file_size = ssd->cur_rtracker->file_size;
                ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
            }

            ftracker->ff_sequential_only = ssd->cur_rtracker->sequential_only;
        }
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_TRANSACTION_SECONDARY
DCE2_Ret DCE2_SmbTransactionSecondary(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;
    DCE2_Ret status;

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    status = DCE2_SmbUpdateTransSecondary(ssd, smb_hdr, com_info, nb_ptr, nb_len);
    if (status != DCE2_RET__FULL)
        return status;

    switch (ttracker->subcom)
    {
    case TRANS_TRANSACT_NMPIPE:
    case TRANS_WRITE_NMPIPE:
    {
// FIXIT-M uncomment after porting packet reassembly code
/*
                const uint8_t *data_ptr = DCE2_BufferData(ttracker->dbuf);
                uint32_t data_len = DCE2_BufferLength(ttracker->dbuf);
                rpkt = DCE2_SmbGetRpkt(ssd, &data_ptr, &data_len, DCE2_RPKT_TYPE__SMB_TRANS);

                if (rpkt == nullptr)
                    return DCE2_RET__ERROR;

                DebugMessage(DEBUG_DCE_SMB, "Reassembled Transaction request\n"));
                DCE2_DEBUG_CODE(DCE2_DEBUG__MAIN, DCE2_PrintPktData(rpkt->payload, rpkt->payload_size););

                status = DCE2_SmbTransactionReq(ssd, ttracker, data_ptr, data_len,
                        DCE2_BufferData(ttracker->pbuf), DCE2_BufferLength(ttracker->pbuf));

                DCE2_SmbReturnRpkt();
*/
    }
    break;

    default:
        status = DCE2_SmbTransactionReq(ssd, ttracker,
            DCE2_BufferData(ttracker->dbuf), DCE2_BufferLength(ttracker->dbuf),
            DCE2_BufferData(ttracker->pbuf), DCE2_BufferLength(ttracker->pbuf));
        break;
    }

    return status;
}

// SMB_COM_TRANSACTION2_SECONDARY
DCE2_Ret DCE2_SmbTransaction2Secondary(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    DCE2_Ret status;
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    status = DCE2_SmbUpdateTransSecondary(ssd, smb_hdr, com_info, nb_ptr, nb_len);
    if (status != DCE2_RET__FULL)
        return status;

    switch (ttracker->subcom)
    {
    case TRANS2_OPEN2:
        status = DCE2_SmbTrans2Open2Req(ssd, DCE2_BufferData(ttracker->pbuf),
            DCE2_BufferLength(ttracker->pbuf), SmbUnicode(smb_hdr));
        if (status != DCE2_RET__SUCCESS)
            return status;
        break;

    case TRANS2_QUERY_FILE_INFORMATION:
        status = DCE2_SmbTrans2QueryFileInfoReq(ssd, DCE2_BufferData(ttracker->pbuf),
            DCE2_BufferLength(ttracker->pbuf));
        if (status != DCE2_RET__SUCCESS)
            return status;
        break;

    case TRANS2_SET_FILE_INFORMATION:
        status = DCE2_SmbTrans2SetFileInfoReq(ssd, DCE2_BufferData(ttracker->pbuf),
            DCE2_BufferLength(ttracker->pbuf),
            DCE2_BufferData(ttracker->dbuf),
            DCE2_BufferLength(ttracker->dbuf));
        if (status != DCE2_RET__SUCCESS)
            return status;
        break;

    default:
        break;
    }

    return DCE2_RET__SUCCESS;
}

// SMB_COM_NT_TRANSACT_SECONDARY
DCE2_Ret DCE2_SmbNtTransactSecondary(DCE2_SmbSsnData* ssd, const SmbNtHdr* smb_hdr,
    const DCE2_SmbComInfo* com_info, const uint8_t* nb_ptr, uint32_t nb_len)
{
    DCE2_Ret status;
    DCE2_SmbTransactionTracker* ttracker = &ssd->cur_rtracker->ttracker;

    if (!DCE2_ComInfoCanProcessCommand(com_info))
        return DCE2_RET__ERROR;

    status = DCE2_SmbUpdateTransSecondary(ssd, smb_hdr, com_info, nb_ptr, nb_len);
    if (status != DCE2_RET__FULL)
        return status;

    switch (ttracker->subcom)
    {
    case NT_TRANSACT_CREATE:
        status = DCE2_SmbNtTransactCreateReq(ssd, DCE2_BufferData(ttracker->pbuf),
            DCE2_BufferLength(ttracker->pbuf), SmbUnicode(smb_hdr));
        if (status != DCE2_RET__SUCCESS)
            return status;
        break;

    default:
        break;
    }

    return DCE2_RET__SUCCESS;
}

