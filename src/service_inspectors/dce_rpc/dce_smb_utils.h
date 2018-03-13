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

// dce_smb_utils.h author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

#ifndef DCE_SMB_UTILS_H
#define DCE_SMB_UTILS_H

#include "dce_smb.h"
#include "file_api/file_flows.h"

/********************************************************************
 * Enums
 ********************************************************************/
enum DCE2_SmbComError
{
    // No errors associated with the command
    DCE2_SMB_COM_ERROR__COMMAND_OK          = 0x0000,

    // An error was reported in the SMB response header
    DCE2_SMB_COM_ERROR__STATUS_ERROR        = 0x0001,

    // An invalid word count makes it unlikely any data accessed will be correct
    // and if accessed the possibility of accessing out of bounds data
    DCE2_SMB_COM_ERROR__INVALID_WORD_COUNT  = 0x0002,

    // An invalid byte count just means the byte count is not right for
    // the command processed.  The command can still be processed but
    // the byte count should not be used.  In general, the byte count
    // should not be used since Windows and Samba often times ignore it
    DCE2_SMB_COM_ERROR__INVALID_BYTE_COUNT  = 0x0004,

    // Not enough data to process command so don't try to access any
    // of the command's header or data.
    DCE2_SMB_COM_ERROR__BAD_LENGTH          = 0x0008
};

/********************************************************************
 * Structures
 ********************************************************************/
struct DCE2_SmbComInfo
{
    int smb_type;   // SMB_TYPE__REQUEST or SMB_TYPE__RESPONSE
    int cmd_error;  // mask of DCE2_SmbComError
    uint8_t smb_com;
    uint8_t word_count;
    uint16_t byte_count;
    uint16_t cmd_size;
};

// Inline accessor functions for DCE2_SmbComInfo

inline bool DCE2_ComInfoIsResponse(const DCE2_SmbComInfo* com_info)
{
    return (com_info->smb_type == SMB_TYPE__RESPONSE) ? true : false;
}

inline bool DCE2_ComInfoIsRequest(const DCE2_SmbComInfo* com_info)
{
    return (com_info->smb_type == SMB_TYPE__REQUEST) ? true : false;
}

inline uint16_t DCE2_ComInfoByteCount(const DCE2_SmbComInfo* com_info)
{
    return com_info->byte_count;
}

inline uint8_t DCE2_ComInfoSmbCom(const DCE2_SmbComInfo* com_info)
{
    return com_info->smb_com;
}

inline uint16_t DCE2_ComInfoCommandSize(const DCE2_SmbComInfo* com_info)
{
    return com_info->cmd_size;
}

inline bool DCE2_ComInfoIsStatusError(const DCE2_SmbComInfo* com_info)
{
    return (com_info->cmd_error & DCE2_SMB_COM_ERROR__STATUS_ERROR) ? true : false;
}

inline bool DCE2_ComInfoIsInvalidWordCount(const DCE2_SmbComInfo* com_info)
{
    return (com_info->cmd_error & DCE2_SMB_COM_ERROR__INVALID_WORD_COUNT) ? true : false;
}

inline bool DCE2_ComInfoIsBadLength(const DCE2_SmbComInfo* com_info)
{
    return (com_info->cmd_error & DCE2_SMB_COM_ERROR__BAD_LENGTH) ? true : false;
}

inline uint8_t DCE2_ComInfoWordCount(const DCE2_SmbComInfo* com_info)
{
    return com_info->word_count;
}

// If this returns false, the command should not be processed
inline bool DCE2_ComInfoCanProcessCommand(const DCE2_SmbComInfo* com_info)
{
    if (DCE2_ComInfoIsBadLength(com_info)
        || DCE2_ComInfoIsStatusError(com_info)
        || DCE2_ComInfoIsInvalidWordCount(com_info))
        return false;
    return true;
}

/********************************************************************
 * Function prototypes
 ********************************************************************/
bool DCE2_SmbIsTidIPC(DCE2_SmbSsnData*, const uint16_t);
char* DCE2_SmbGetFileName(const uint8_t *data, uint32_t data_len, bool unicode, uint16_t *file_name_len);
int DCE2_SmbUidTidFidCompare(const void*, const void*);
DCE2_Ret DCE2_SmbFindUid(DCE2_SmbSsnData*, const uint16_t);
void DCE2_SmbInsertUid(DCE2_SmbSsnData*, const uint16_t);
void DCE2_SmbRemoveUid(DCE2_SmbSsnData*, const uint16_t);
DCE2_SmbRequestTracker* DCE2_SmbNewRequestTracker(DCE2_SmbSsnData*, const SmbNtHdr*);
void DCE2_SmbCleanTransactionTracker(DCE2_SmbTransactionTracker*);
void DCE2_SmbCleanRequestTracker(DCE2_SmbRequestTracker*);
void DCE2_SmbRemoveRequestTracker(DCE2_SmbSsnData*, DCE2_SmbRequestTracker*);
DCE2_SmbFileTracker* DCE2_SmbGetFileTracker(DCE2_SmbSsnData*,
    const uint16_t);
DCE2_SmbFileTracker* DCE2_SmbGetTmpFileTracker(DCE2_SmbRequestTracker*);
void DCE2_SmbRemoveFileTracker(DCE2_SmbSsnData*, DCE2_SmbFileTracker*);
void DCE2_SmbCleanFileTracker(DCE2_SmbFileTracker*);
void DCE2_SmbFileTrackerDataFree(void*);
void DCE2_SmbCleanSessionFileTracker(DCE2_SmbSsnData*, DCE2_SmbFileTracker*);
void DCE2_SmbRemoveFileTrackerFromRequestTrackers(DCE2_SmbSsnData*,
    DCE2_SmbFileTracker*);
DCE2_SmbFileTracker* DCE2_SmbDequeueTmpFileTracker(DCE2_SmbSsnData*,
    DCE2_SmbRequestTracker*, const uint16_t);
DCE2_SmbFileTracker* DCE2_SmbNewFileTracker(DCE2_SmbSsnData*,
    const uint16_t, const uint16_t, const uint16_t);
void DCE2_SmbQueueTmpFileTracker(DCE2_SmbSsnData*,
    DCE2_SmbRequestTracker*, const uint16_t, const uint16_t);
DCE2_Ret DCE2_SmbFindTid(DCE2_SmbSsnData*, const uint16_t);
void DCE2_SmbRemoveTid(DCE2_SmbSsnData*, const uint16_t);
void DCE2_SmbInsertTid(DCE2_SmbSsnData*, const uint16_t, const bool);
void DCE2_SmbInvalidShareCheck(DCE2_SmbSsnData*,
    const SmbNtHdr*, const uint8_t*, uint32_t);
DCE2_Ret DCE2_SmbInitFileTracker(DCE2_SmbSsnData*,
    DCE2_SmbFileTracker*, const bool, const uint16_t,
    const uint16_t, const int);
void DCE2_SmbRequestTrackerDataFree(void*);
DCE2_SmbFileTracker* DCE2_SmbFindFileTracker(DCE2_SmbSsnData*,
    const uint16_t, const uint16_t, const uint16_t);
DCE2_Ret DCE2_SmbProcessRequestData(DCE2_SmbSsnData*, const uint16_t,
    const uint8_t*, uint32_t, uint64_t);
DCE2_Ret DCE2_SmbProcessResponseData(DCE2_SmbSsnData*,
    const uint8_t*, uint32_t);
void DCE2_SmbInitRdata(uint8_t*, int);
void DCE2_SmbSetRdata(DCE2_SmbSsnData*, uint8_t*, uint16_t);
snort::Packet* DCE2_SmbGetRpkt(DCE2_SmbSsnData*, const uint8_t**,
    uint32_t*, DCE2_RpktType);
DCE2_Ret DCE2_SmbHandleSegmentation(DCE2_Buffer**,
    const uint8_t*, uint32_t, uint32_t);
bool DCE2_SmbIsSegBuffer(DCE2_SmbSsnData*, const uint8_t*);
void DCE2_SmbSegAlert(DCE2_SmbSsnData*, uint32_t rule_id);
void DCE2_SmbAbortFileAPI(DCE2_SmbSsnData*);
void DCE2_SmbProcessFileData(DCE2_SmbSsnData* ssd,
    DCE2_SmbFileTracker* ftracker, const uint8_t* data_ptr,
    uint32_t data_len, bool upload);
void DCE2_FileDetect();
FileVerdict DCE2_get_file_verdict(DCE2_SmbSsnData* );
void DCE2_SmbInitDeletePdu();
void DCE2_Update_Ftracker_from_ReqTracker(DCE2_SmbFileTracker*, DCE2_SmbRequestTracker*);

/********************************************************************
 * Inline functions
 ********************************************************************/

/********************************************************************
 * Function: DCE2_SmbType()
 *
 * Purpose:
 *  Since Windows and Samba don't seem to care or even look at the
 *  actual flag in the SMB header, make the determination based on
 *  whether from client or server.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - session data structure that has the raw
 *     packet and packet flags to make determination
 *
 * Returns:
 *  SMB_TYPE__REQUEST if packet is from client
 *  SMB_TYPE__RESPONSE if packet is from server
 *
 ********************************************************************/
inline int DCE2_SmbType(DCE2_SmbSsnData* ssd)
{
    if (DCE2_SsnFromClient(ssd->sd.wire_pkt))
        return SMB_TYPE__REQUEST;
    else
        return SMB_TYPE__RESPONSE;
}

inline bool SmbUnicode(const SmbNtHdr* hdr)
{
    return (snort::alignedNtohs(&hdr->smb_flg2) & SMB_FLG2__UNICODE) ? true : false;
}

inline bool SmbExtAttrReadOnly(const uint32_t ext_file_attrs)
{
    if (ext_file_attrs & SMB_EXT_FILE_ATTR_READONLY)
        return true;
    return false;
}

inline bool SmbExtAttrHidden(const uint32_t ext_file_attrs)
{
    if (ext_file_attrs & SMB_EXT_FILE_ATTR_HIDDEN)
        return true;
    return false;
}

inline bool SmbExtAttrSystem(const uint32_t ext_file_attrs)
{
    if (ext_file_attrs & SMB_EXT_FILE_ATTR_SYSTEM)
        return true;
    return false;
}

inline bool SmbEvasiveFileAttrs(const uint32_t ext_file_attrs)
{
    return (SmbExtAttrReadOnly(ext_file_attrs)
           && SmbExtAttrHidden(ext_file_attrs)
           && SmbExtAttrSystem(ext_file_attrs));
}

inline uint8_t SmbCom(const SmbNtHdr* hdr)
{
    return hdr->smb_com;
}

inline bool SmbStatusNtCodes(const SmbNtHdr* hdr)
{
    if (snort::alignedNtohs(&hdr->smb_flg2) & SMB_FLG2__NT_CODES)
        return true;
    return false;
}

inline uint32_t SmbNtStatus(const SmbNtHdr* hdr)
{
    return snort::alignedNtohl(&hdr->smb_status.nt_status);
}

inline uint8_t SmbStatusClass(const SmbNtHdr* hdr)
{
    return hdr->smb_status.smb_status.smb_class;
}

inline uint16_t SmbStatusCode(const SmbNtHdr* hdr)
{
    return snort::alignedNtohs(&hdr->smb_status.smb_status.smb_code);
}

inline uint8_t SmbNtStatusSeverity(const SmbNtHdr* hdr)
{
    return (uint8_t)(SmbNtStatus(hdr) >> 30);
}

inline uint16_t SmbPid(const SmbNtHdr* hdr)
{
    return snort::alignedNtohs(&hdr->smb_pid);
}

inline uint16_t SmbMid(const SmbNtHdr* hdr)
{
    return snort::alignedNtohs(&hdr->smb_mid);
}

inline uint16_t SmbUid(const SmbNtHdr* hdr)
{
    return snort::alignedNtohs(&hdr->smb_uid);
}

inline uint16_t SmbTid(const SmbNtHdr* hdr)
{
    return snort::alignedNtohs(&hdr->smb_tid);
}

inline bool SmbErrorInvalidDeviceRequest(const SmbNtHdr* hdr)
{
    if (SmbStatusNtCodes(hdr))
    {
        if (SmbNtStatus(hdr) == SMB_NT_STATUS__INVALID_DEVICE_REQUEST)
            return true;
    }
    else
    {
        if ((SmbStatusClass(hdr) == SMB_ERROR_CLASS__ERRSRV)
            && (SmbStatusCode(hdr) == SMB_ERRSRV__INVALID_DEVICE))
            return true;
    }

    return false;
}

inline bool SmbErrorRangeNotLocked(const SmbNtHdr* hdr)
{
    if (SmbStatusNtCodes(hdr))
    {
        if (SmbNtStatus(hdr) == SMB_NT_STATUS__RANGE_NOT_LOCKED)
            return true;
    }
    else
    {
        if ((SmbStatusClass(hdr) == SMB_ERROR_CLASS__ERRDOS)
            && (SmbStatusCode(hdr) == SMB_ERRDOS__NOT_LOCKED))
            return true;
    }

    return false;
}

// Convenience function to determine whether or not the transaction is complete
// for one side, i.e. all data and parameters sent.
inline bool DCE2_SmbIsTransactionComplete(DCE2_SmbTransactionTracker* ttracker)
{
    if ((ttracker->tdcnt == ttracker->dsent)
        && (ttracker->tpcnt == ttracker->psent))
        return true;
    return false;
}

inline DCE2_Buffer** DCE2_SmbGetSegBuffer(DCE2_SmbSsnData* ssd)
{
    if (DCE2_SsnFromServer(ssd->sd.wire_pkt))
        return &ssd->srv_seg;
    return &ssd->cli_seg;
}

#endif

