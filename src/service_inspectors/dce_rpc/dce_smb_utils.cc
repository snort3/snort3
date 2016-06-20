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

// dce_smb_utils.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

#include "dce_smb.h"
#include "dce_smb_utils.h"
#include "dce_smb_module.h"
#include "dce_list.h"
#include "main/snort_debug.h"
#include "utils/util.h"
#include "detection/detect.h"

/********************************************************************
 * Function:  DCE2_SmbIsTidIPC()
 *
 * Purpose: Checks to see if the TID passed in was to IPC or not.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - pointer to session data
 *  const uint16_t    - the TID to check
 *
 * Returns:
 *  bool - True if TID is IPC, false if not or if TID not found.
 *
 ********************************************************************/
bool DCE2_SmbIsTidIPC(DCE2_SmbSsnData* ssd, const uint16_t tid)
{
    if ((ssd->tid != DCE2_SENTINEL)
        && ((ssd->tid & 0x0000ffff) == (int)tid))
    {
        if ((ssd->tid >> 16) == 0)
            return true;
    }
    else
    {
        int check_tid = (int)(uintptr_t)DCE2_ListFind(ssd->tids, (void*)(uintptr_t)tid);
        if (((check_tid & 0x0000ffff) == (int)tid) && ((check_tid >> 16) == 0))
            return true;
    }

    return false;
}

/********************************************************************
 * Function: DCE2_SmbGetString()
 *
 * Purpose:
 *  Parses data passed in and returns an ASCII string.  True
 *  unicode characters are replaced with a '.'
 *
 * Arguments:
 *  const uint8_t *  - pointer to data
 *  uint32_t         - data length
 *  bool             - true if the data is unicode (UTF-16LE)
 *  bool             - true if the function should only return the
 *                     file name instead of the entire path
 *
 * Returns:
 *  char *  - NULL terminated ASCII string
 *
 ********************************************************************/
char* DCE2_SmbGetString(const uint8_t* data,
    uint32_t data_len, bool unicode, bool get_file)
{
    char* str;
    uint32_t i, j, k = unicode ? data_len - 1 : data_len;
    uint8_t inc = unicode ? 2 : 1;

    if (data_len < inc)
        return nullptr;

    // Move forward.  Don't know if the end of data is actually
    // the end of the string.
    for (i = 0, j = 0; i < k; i += inc)
    {
        uint16_t uchar = unicode ? extract_16bits(data + i) : data[i];

        if (uchar == 0)
            break;
        else if (get_file && ((uchar == 0x002F) || (uchar == 0x005C)))  // slash and back-slash
            j = i + inc;
    }

    // Only got a NULL byte or nothing after slash/back-slash or too big.
    if ((i == 0) || (j == i)
        || (get_file && (i > DCE2_SMB_MAX_COMP_LEN))
        || (i > DCE2_SMB_MAX_PATH_LEN))
        return nullptr;

    str = (char*)snort_calloc(((i-j)>>(inc-1))+1);
    if (str == nullptr)
        return nullptr;

    for (k = 0; j < i; j += inc, k++)
    {
        if (isprint((int)data[j]))
            str[k] = (char)data[j];
        else
            str[k] = '.';
    }

    str[k] = 0;

    return str;
}

int DCE2_SmbUidTidFidCompare(const void* a, const void* b)
{
    int x = (int)(uintptr_t)a;
    int y = (int)(uintptr_t)b;

    if (x == y)
        return 0;

    /* Only care about equality for finding */
    return -1;
}

DCE2_Ret DCE2_SmbFindUid(DCE2_SmbSsnData* ssd, const uint16_t uid)
{
    DCE2_Ret status;

    Profile profile(dce2_smb_pstat_smb_uid);

    if ((ssd->uid != DCE2_SENTINEL) && (ssd->uid == (int)uid))
        status = DCE2_RET__SUCCESS;
    else
        status = DCE2_ListFindKey(ssd->uids, (void*)(uintptr_t)uid);

    return status;
}

void DCE2_SmbInsertUid(DCE2_SmbSsnData* ssd, const uint16_t uid)
{
    Profile profile(dce2_smb_pstat_smb_uid);

    DebugFormat(DEBUG_DCE_SMB, "Inserting Uid: %hu\n", uid);

    if (ssd->uid == DCE2_SENTINEL)
    {
        ssd->uid = (int)uid;
    }
    else
    {
        if (ssd->uids == nullptr)
        {
            ssd->uids = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED, DCE2_SmbUidTidFidCompare,
                nullptr, nullptr, DCE2_LIST_FLAG__NO_DUPS);

            if (ssd->uids == nullptr)
            {
                return;
            }
        }

        DCE2_ListInsert(ssd->uids, (void*)(uintptr_t)uid, (void*)(uintptr_t)uid);
    }
}

void DCE2_SmbRemoveUid(DCE2_SmbSsnData* ssd, const uint16_t uid)
{
    const DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);

    Profile profile(dce2_smb_pstat_smb_uid);

    DebugFormat(DEBUG_DCE_SMB,"Removing Uid: %hu\n", uid);

    if ((ssd->uid != DCE2_SENTINEL) && (ssd->uid == (int)uid))
        ssd->uid = DCE2_SENTINEL;
    else
        DCE2_ListRemove(ssd->uids, (void*)(uintptr_t)uid);

    switch (policy)
    {
    case DCE2_POLICY__WIN2000:
    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
        // Removing uid invalidates any fid that was created with it */
        if ((ssd->ftracker.fid != DCE2_SENTINEL) &&
            (ssd->ftracker.uid == uid))
        {
            DCE2_SmbRemoveFileTracker(ssd, &ssd->ftracker);
        }

        if (ssd->ftrackers != nullptr)
        {
            DCE2_SmbFileTracker* ftracker;

            for (ftracker = (DCE2_SmbFileTracker*)DCE2_ListFirst(ssd->ftrackers);
                ftracker != nullptr;
                ftracker = (DCE2_SmbFileTracker*)DCE2_ListNext(ssd->ftrackers))
            {
                if (ftracker->uid == uid)
                {
// FIXIT-M uncomment after file api is ported
/*
                        if (ssd->fapi_ftracker == ftracker)
                            DCE2_SmbFinishFileAPI(ssd);

#ifdef ACTIVE_RESPONSE
                        if (ssd->fb_ftracker == ftracker)
                            DCE2_SmbFinishFileBlockVerdict(ssd);
#endif
*/
                    DCE2_ListRemoveCurrent(ssd->ftrackers);
                    DCE2_SmbRemoveFileTrackerFromRequestTrackers(ssd, ftracker);
                }
            }
        }

        break;

    case DCE2_POLICY__SAMBA_3_0_20:
    case DCE2_POLICY__SAMBA_3_0_22:
        // Removing Uid used to create file doesn't invalidate it.
        break;

    default:
        DebugFormat(DEBUG_DCE_SMB, "%s(%d) Invalid policy: %d",
            __FILE__, __LINE__, policy);
        break;
    }
}

DCE2_SmbRequestTracker* DCE2_SmbNewRequestTracker(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr)
{
    uint16_t pid = SmbPid(smb_hdr);
    uint16_t mid = SmbMid(smb_hdr);
    uint16_t uid = SmbUid(smb_hdr);
    uint16_t tid = SmbTid(smb_hdr);

    Profile profile(dce2_smb_pstat_smb_req);

    if (ssd == nullptr)
    {
        return nullptr;
    }

    if (ssd->outstanding_requests >= ssd->max_outstanding_requests)
    {
        dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats);
    }

    // Check for outstanding requests with the same MID
    DCE2_SmbRequestTracker* tmp_rtracker = &ssd->rtracker;
    while ((tmp_rtracker != nullptr) && (tmp_rtracker->mid != DCE2_SENTINEL))
    {
        if (tmp_rtracker->mid == (int)mid)
        {
            // Have yet to see an MID repeatedly used so shouldn't
            // be any outstanding requests with the same MID.
            dce_alert(GID_DCE2, DCE2_SMB_REQS_SAME_MID, (dce2CommonStats*)&dce2_smb_stats);
            break;
        }

        // Look at the next request in the queue
        if (tmp_rtracker == &ssd->rtracker)
            tmp_rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueFirst(ssd->rtrackers);
        else
            tmp_rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueNext(ssd->rtrackers);
    }

    DCE2_SmbRequestTracker* rtracker = nullptr;
    if (ssd->rtracker.mid == DCE2_SENTINEL)
    {
        rtracker = &ssd->rtracker;
    }
    else
    {
        if (ssd->rtrackers == nullptr)
        {
            ssd->rtrackers = DCE2_QueueNew(DCE2_SmbRequestTrackerDataFree);
            if (ssd->rtrackers == nullptr)
            {
                return nullptr;
            }
        }

        rtracker = (DCE2_SmbRequestTracker*)snort_calloc(sizeof(DCE2_SmbRequestTracker));
        if (rtracker == nullptr)
        {
            return nullptr;
        }

        if (DCE2_QueueEnqueue(ssd->rtrackers, (void*)rtracker) != DCE2_RET__SUCCESS)
        {
            snort_free((void*)rtracker);
            return nullptr;
        }
    }

    rtracker->smb_com = SmbCom(smb_hdr);
    rtracker->uid = uid;
    rtracker->tid = tid;
    rtracker->pid = pid;
    rtracker->mid = (int)mid;
    memset(&rtracker->ttracker, 0, sizeof(rtracker->ttracker));
    rtracker->ftracker = nullptr;
    rtracker->sequential_only = false;

    ssd->outstanding_requests++;
    if (ssd->outstanding_requests > dce2_smb_stats.smb_max_outstanding_requests)
        dce2_smb_stats.smb_max_outstanding_requests = ssd->outstanding_requests;

    DebugFormat(DEBUG_DCE_SMB, "Added new request tracker => "
        "Uid: %hu, Tid: %hu, Pid: %hu, Mid: %d\n",
        rtracker->uid, rtracker->tid, rtracker->pid, rtracker->mid);
    DebugFormat(DEBUG_DCE_SMB,
        "Current outstanding requests: %hu\n", ssd->outstanding_requests);

    return rtracker;
}

DCE2_SmbFileTracker* DCE2_SmbNewFileTracker(DCE2_SmbSsnData* ssd,
    const uint16_t uid, const uint16_t tid, const uint16_t fid)
{
    Profile profile(dce2_smb_pstat_smb_fid);

    // Already have tracker for file API and not setting file data pointer
    // so don't create new file tracker.
    bool is_ipc = DCE2_SmbIsTidIPC(ssd, tid);
    if (!is_ipc && (ssd->fapi_ftracker != nullptr)
        && (DCE2_ScSmbFileDepth((dce2SmbProtoConf*)ssd->sd.config) == -1))
        return nullptr;

    DebugFormat(DEBUG_DCE_SMB, "Creating new file tracker "
        "with Uid: %hu, Tid: %hu, Fid: 0x%04X\n", uid, tid, fid);

    DCE2_SmbFileTracker* ftracker = nullptr;
    if (ssd->ftracker.fid == DCE2_SENTINEL)
    {
        ftracker = &ssd->ftracker;
        if (DCE2_SmbInitFileTracker(ssd, ftracker, is_ipc, uid, tid, (int)fid) !=
            DCE2_RET__SUCCESS)
        {
            DCE2_SmbCleanFileTracker(ftracker);
            return nullptr;
        }
    }
    else
    {
        ftracker = (DCE2_SmbFileTracker*)snort_calloc(sizeof(DCE2_SmbFileTracker));

        if (ftracker == nullptr)
        {
            return nullptr;
        }

        if (DCE2_SmbInitFileTracker(ssd, ftracker, is_ipc, uid, tid, (int)fid) !=
            DCE2_RET__SUCCESS)
        {
            DCE2_SmbCleanFileTracker(ftracker);
            snort_free((void*)ftracker);
            return nullptr;
        }

        if (ssd->ftrackers == nullptr)
        {
            ssd->ftrackers = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED,
                DCE2_SmbUidTidFidCompare, DCE2_SmbFileTrackerDataFree, nullptr,
                DCE2_LIST_FLAG__NO_DUPS);

            if (ssd->ftrackers == nullptr)
            {
                DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
                return nullptr;
            }
        }

        if (DCE2_ListInsert(ssd->ftrackers, (void*)(uintptr_t)fid,
            (void*)ftracker) != DCE2_RET__SUCCESS)
        {
            DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
            return nullptr;
        }
    }

    return ftracker;
}

DCE2_Ret DCE2_SmbInitFileTracker(DCE2_SmbSsnData* ssd,
    DCE2_SmbFileTracker* ftracker, const bool is_ipc, const uint16_t uid,
    const uint16_t tid, const int fid)
{
    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

    ftracker->uid = uid;
    ftracker->tid = tid;
    ftracker->fid = fid;
    ftracker->is_ipc = is_ipc;
    ftracker->file_name = nullptr;
    if (is_ipc)
    {
        DCE2_CoTracker* co_tracker = (DCE2_CoTracker*)snort_calloc(sizeof(DCE2_CoTracker));
        if (co_tracker == nullptr)
            return DCE2_RET__ERROR;
        DCE2_CoInitTracker(co_tracker);
        ftracker->fp_co_tracker = co_tracker;
        ftracker->fp_byte_mode = false;
        ftracker->fp_used = false;
        ftracker->fp_writex_raw = nullptr;
    }
    else
    {
        ftracker->ff_file_size = 0;
        ftracker->ff_file_offset = 0;
        ftracker->ff_bytes_processed = 0;
        ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UNKNOWN;
        ftracker->ff_file_chunks = nullptr;
        ftracker->ff_bytes_queued = 0;
        if ((ssd->fapi_ftracker == nullptr) && (ssd->max_file_depth != -1))
        {
            DebugFormat(DEBUG_DCE_SMB, "Designating file tracker "
                "for file API processing: 0x%04X\n", (uint16_t)fid);
            ssd->fapi_ftracker = ftracker;
        }
    }

    return DCE2_RET__SUCCESS;
}

DCE2_SmbFileTracker* DCE2_SmbFindFileTracker(DCE2_SmbSsnData* ssd,
    const uint16_t uid, const uint16_t tid, const uint16_t fid)
{
    Profile profile(dce2_smb_pstat_smb_fid);

    DebugFormat(DEBUG_DCE_SMB, "Finding file tracker with "
        "Uid: %hu, Tid: %hu, Fid: 0x%04X ... ", uid, tid, fid);

    DCE2_SmbFileTracker* ftracker;
    if ((ssd->ftracker.fid != DCE2_SENTINEL) && (ssd->ftracker.fid == (int)fid))
    {
        ftracker = &ssd->ftracker;
    }
    else
    {
        ftracker = (DCE2_SmbFileTracker*)
            DCE2_ListFind(ssd->ftrackers, (void*)(uintptr_t)fid);
    }

    if (ftracker == nullptr)
    {
        DebugMessage(DEBUG_DCE_SMB, "Not found.\n");
        return nullptr;
    }

    // Note IPC Tid has already been validated in initial processing
    const DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    switch (policy)
    {
    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
        // Only Uid used to open file can be used to make a request
        if (ftracker->uid != uid)
        {
            DebugMessage(DEBUG_DCE_SMB, "Not found.\n");
            return nullptr;
        }

        break;

    case DCE2_POLICY__WIN2000:
    case DCE2_POLICY__SAMBA_3_0_20:
    case DCE2_POLICY__SAMBA_3_0_22:
        // Any valid Uid can be used to make a request to a file ...
        // except for Windows 2000 on the first use.
        if ((policy != DCE2_POLICY__WIN2000) || (ftracker->is_ipc && ftracker->fp_used))
        {
            // Check that the Uid exists
            if (DCE2_SmbFindUid(ssd, uid) != DCE2_RET__SUCCESS)
            {
                DebugMessage(DEBUG_DCE_SMB, "Not found.\n");
                return nullptr;
            }

            break;
        }

    // Fall through for Windows 2000 for first request to file

    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
        // Both Uid and Tid used to create file must be used to make a request
        if ((ftracker->uid != uid) || (ftracker->tid != tid))
        {
            DebugMessage(DEBUG_DCE_SMB, "Not found.\n");
            return nullptr;
        }

        break;

    default:
        DebugFormat(DEBUG_DCE_SMB, "%s(%d) Invalid policy: %d",
            __FILE__, __LINE__, policy);
        break;
    }

    DebugFormat(DEBUG_DCE_SMB, "Found with "
        "Uid: %hu, Tid: %hu, Fid: 0x%04X\n",
        ftracker->uid, ftracker->tid, ftracker->fid);
    return ftracker;
}

DCE2_SmbFileTracker* DCE2_SmbGetFileTracker(DCE2_SmbSsnData* ssd,
    const uint16_t fid)
{
    DCE2_SmbFileTracker* ftracker = ssd->cur_rtracker->ftracker;

    if (ftracker == nullptr)
    {
        // Write could've been chained to an OpenAndX or NtCreateAndX so a
        // temporary file tracker would've been created until we get the
        // response with the Fid returned from the OpenAndX / NtCreateAndX
        ftracker = DCE2_SmbGetTmpFileTracker(ssd->cur_rtracker);
        if (ftracker == nullptr)
        {
            // Otherwise find it with the passed in Fid
            ftracker = DCE2_SmbFindFileTracker(ssd, ssd->cur_rtracker->uid,
                ssd->cur_rtracker->tid, fid);
        }
    }

    return ftracker;
}

DCE2_SmbFileTracker* DCE2_SmbGetTmpFileTracker(DCE2_SmbRequestTracker* rtracker)
{
    if (!DCE2_QueueIsEmpty(rtracker->ft_queue))
        return (DCE2_SmbFileTracker*)DCE2_QueueLast(rtracker->ft_queue);
    return nullptr;
}

void DCE2_SmbRemoveFileTracker(DCE2_SmbSsnData* ssd, DCE2_SmbFileTracker* ftracker)
{
    if (ftracker == nullptr)
        return;

    Profile profile(dce2_smb_pstat_smb_fid);

    DebugFormat(DEBUG_DCE_SMB,
        "Removing file tracker with Fid: 0x%04X\n", ftracker->fid);

    // FIXIT-M uncomment when file api related code is ported
    /*
    if (ssd->fapi_ftracker == ftracker)
        DCE2_SmbFinishFileAPI(ssd);
    */

    //FIXIT-M port active response related code
/*
#ifdef ACTIVE_RESPONSE
    if (ssd->fb_ftracker == ftracker)
        DCE2_SmbFinishFileBlockVerdict(ssd);
#endif
*/
    if (ftracker == &ssd->ftracker)
        DCE2_SmbCleanFileTracker(&ssd->ftracker);
    else if (ssd->ftrackers != nullptr)
        DCE2_ListRemove(ssd->ftrackers, (void*)(uintptr_t)ftracker->fid);

    DCE2_SmbRemoveFileTrackerFromRequestTrackers(ssd, ftracker);
}

void DCE2_SmbCleanFileTracker(DCE2_SmbFileTracker* ftracker)
{
    if (ftracker == nullptr)
        return;

    Profile profile(dce2_smb_pstat_smb_fid);

    ftracker->fid = DCE2_SENTINEL;
    if (ftracker->file_name != nullptr)
    {
        snort_free((void*)ftracker->file_name);
        ftracker->file_name = nullptr;
    }

    if (ftracker->is_ipc)
    {
        ftracker->fp_used = 0;
        ftracker->fp_byte_mode = 0;

        if (ftracker->fp_writex_raw != nullptr)
        {
            DCE2_BufferDestroy(ftracker->fp_writex_raw->buf);
            snort_free((void*)ftracker->fp_writex_raw);
            ftracker->fp_writex_raw = nullptr;
        }

        if (ftracker->fp_co_tracker != nullptr)
        {
            DCE2_CoCleanTracker(ftracker->fp_co_tracker);
            snort_free((void*)ftracker->fp_co_tracker);
            ftracker->fp_co_tracker = nullptr;
        }
    }
    else
    {
        ftracker->ff_file_size = 0;
        ftracker->ff_file_offset = 0;
        ftracker->ff_bytes_processed = 0;
        ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UNKNOWN;
        ftracker->ff_bytes_queued = 0;
        ftracker->ff_sequential_only = false;
        if (ftracker->ff_file_chunks != nullptr)
        {
            DCE2_ListDestroy(ftracker->ff_file_chunks);
            ftracker->ff_file_chunks = nullptr;
        }
    }
}

void DCE2_SmbFileTrackerDataFree(void* data)
{
    DCE2_SmbFileTracker* ftracker = (DCE2_SmbFileTracker*)data;

    if (ftracker == nullptr)
        return;

    DebugFormat(DEBUG_DCE_SMB, "Freeing file tracker: "
        "Uid: %hu, Tid: %hu, Fid: 0x%04X\n",
        ftracker->uid, ftracker->tid, ftracker->fid);

    DCE2_SmbCleanFileTracker(ftracker);
    snort_free((void*)ftracker);
}

/********************************************************************
 *
 * Remove file tracker and associated pointers in session
 *
 ********************************************************************/
void DCE2_SmbCleanSessionFileTracker(DCE2_SmbSsnData* ssd, DCE2_SmbFileTracker* ftracker)
{
    DCE2_SmbCleanFileTracker(ftracker);
    snort_free((void*)ftracker);
    if (ssd->fapi_ftracker == ftracker)
        ssd->fapi_ftracker = nullptr;
}

void DCE2_SmbCleanTransactionTracker(DCE2_SmbTransactionTracker* ttracker)
{
    Profile profile(dce2_smb_pstat_smb_req);

    if (ttracker == nullptr)
    {
        return;
    }

    if (ttracker->dbuf != nullptr)
        DCE2_BufferDestroy(ttracker->dbuf);

    if (ttracker->pbuf != nullptr)
        DCE2_BufferDestroy(ttracker->pbuf);

    memset(ttracker, 0, sizeof(*ttracker));
}

void DCE2_SmbCleanRequestTracker(DCE2_SmbRequestTracker* rtracker)
{
    Profile profile(dce2_smb_pstat_smb_req);

    if (rtracker == nullptr)
    {
        return;
    }

    if (rtracker->mid == DCE2_SENTINEL)
    {
        return;
    }

    rtracker->mid = DCE2_SENTINEL;
    rtracker->ftracker = nullptr;
    rtracker->sequential_only = false;

    DCE2_SmbCleanTransactionTracker(&rtracker->ttracker);

    DCE2_QueueDestroy(rtracker->ft_queue);
    rtracker->ft_queue = nullptr;

    if (rtracker->file_name != nullptr)
    {
        snort_free((void*)rtracker->file_name);
        rtracker->file_name = nullptr;
    }
}

void DCE2_SmbRemoveRequestTracker(DCE2_SmbSsnData* ssd,
    DCE2_SmbRequestTracker* rtracker)
{
    Profile profile(dce2_smb_pstat_smb_req);

    if ((ssd == nullptr) || (rtracker == nullptr))
    {
        return;
    }

    DebugFormat(DEBUG_DCE_SMB, "Removing request tracker => "
        "Uid: %hu, Tid: %hu, Pid: %hu, Mid: %d ... ",
        rtracker->uid, rtracker->tid, rtracker->pid, rtracker->mid);

    if (rtracker == &ssd->rtracker)
    {
        DebugMessage(DEBUG_DCE_SMB, "Removed\n");

        DCE2_SmbCleanRequestTracker(&ssd->rtracker);
        ssd->outstanding_requests--;
        return;
    }

    DCE2_SmbRequestTracker* tmp_node;
    for (tmp_node = (DCE2_SmbRequestTracker*)DCE2_QueueFirst(ssd->rtrackers);
        tmp_node != nullptr;
        tmp_node = (DCE2_SmbRequestTracker*)DCE2_QueueNext(ssd->rtrackers))
    {
        if (tmp_node == (void*)rtracker)
        {
            DebugMessage(DEBUG_DCE_SMB, "Removed\n");

            DCE2_QueueRemoveCurrent(ssd->rtrackers);
            ssd->outstanding_requests--;
            return;
        }
    }

    DebugMessage(DEBUG_DCE_SMB, "Not removed.\n");
}

void DCE2_SmbRemoveFileTrackerFromRequestTrackers(DCE2_SmbSsnData* ssd,
    DCE2_SmbFileTracker* ftracker)
{
    if (ftracker == nullptr)
        return;

    // NULL out file trackers of any outstanding requests
    // that reference this file tracker
    if (ssd->rtracker.ftracker == ftracker)
        ssd->rtracker.ftracker = nullptr;

    if ((ssd->cur_rtracker != nullptr) && (ssd->cur_rtracker->ftracker == ftracker))
        ssd->cur_rtracker->ftracker = nullptr;

    DCE2_SmbRequestTracker* rtracker;
    for (rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueFirst(ssd->rtrackers);
        rtracker != nullptr;
        rtracker = (DCE2_SmbRequestTracker*)DCE2_QueueNext(ssd->rtrackers))
    {
        if (rtracker->ftracker == ftracker)
            rtracker->ftracker = nullptr;
    }
}

DCE2_SmbFileTracker* DCE2_SmbDequeueTmpFileTracker(DCE2_SmbSsnData* ssd,
    DCE2_SmbRequestTracker* rtracker, const uint16_t fid)
{
    Profile profile(dce2_smb_pstat_smb_fid);

    DebugFormat(DEBUG_DCE_SMB, "Dequeueing file tracker "
        "and binding to fid: 0x%04X\n", fid);

    DCE2_SmbFileTracker* ftracker = (DCE2_SmbFileTracker*)DCE2_QueueDequeue(rtracker->ft_queue);

    if (ftracker == nullptr)
    {
        return nullptr;
    }

    if (ssd->ftracker.fid == DCE2_SENTINEL)
    {
        memcpy(&ssd->ftracker, ftracker, sizeof(DCE2_SmbFileTracker));
        snort_free((void*)ftracker);
        if (ssd->fapi_ftracker == ftracker)
            ssd->fapi_ftracker = &ssd->ftracker;
        ftracker = &ssd->ftracker;
    }
    else
    {
        if (ssd->ftrackers == nullptr)
        {
            ssd->ftrackers = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED,
                DCE2_SmbUidTidFidCompare, DCE2_SmbFileTrackerDataFree, nullptr,
                DCE2_LIST_FLAG__NO_DUPS);

            if (ssd->ftrackers == nullptr)
            {
                DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
                return nullptr;
            }
        }

        if (DCE2_ListInsert(ssd->ftrackers, (void*)(uintptr_t)fid,
            (void*)ftracker) != DCE2_RET__SUCCESS)
        {
            DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
            return nullptr;
        }
    }

    // Other values were intialized when queueing.
    ftracker->fid = (int)fid;

    return ftracker;
}

void DCE2_SmbRequestTrackerDataFree(void* data)
{
    DCE2_SmbRequestTracker* rtracker = (DCE2_SmbRequestTracker*)data;

    if (rtracker == nullptr)
        return;

    DebugFormat(DEBUG_DCE_SMB, "Freeing request tracker: "
        "Uid: %hu, Tid: %hu, Pid: %hu, Mid: %d\n",
        rtracker->uid, rtracker->tid, rtracker->pid, rtracker->mid);

    DCE2_SmbCleanRequestTracker(rtracker);
    snort_free((void*)rtracker);
}

DCE2_Ret DCE2_SmbFindTid(DCE2_SmbSsnData* ssd, const uint16_t tid)
{
    DCE2_Ret status;

    Profile profile(dce2_smb_pstat_smb_tid);

    if ((ssd->tid != DCE2_SENTINEL) && ((ssd->tid & 0x0000ffff) == (int)tid))
        status = DCE2_RET__SUCCESS;
    else
        status = DCE2_ListFindKey(ssd->tids, (void*)(uintptr_t)tid);

    return status;
}

void DCE2_SmbRemoveTid(DCE2_SmbSsnData* ssd, const uint16_t tid)
{
    Profile profile(dce2_smb_pstat_smb_tid);

    DebugFormat(DEBUG_DCE_SMB, "Removing Tid: %hu\n", tid);

    if ((ssd->tid != DCE2_SENTINEL) && ((ssd->tid & 0x0000ffff) == (int)tid))
        ssd->tid = DCE2_SENTINEL;
    else
        DCE2_ListRemove(ssd->tids, (void*)(uintptr_t)tid);

    // Removing Tid invalidates files created with it
    if ((ssd->ftracker.fid != DCE2_SENTINEL)
        && (ssd->ftracker.tid == tid))
    {
        DCE2_SmbRemoveFileTracker(ssd, &ssd->ftracker);
    }

    if (ssd->ftrackers != nullptr)
    {
        DCE2_SmbFileTracker* ftracker;

        for (ftracker = (DCE2_SmbFileTracker*)DCE2_ListFirst(ssd->ftrackers);
            ftracker != nullptr;
            ftracker = (DCE2_SmbFileTracker*)DCE2_ListNext(ssd->ftrackers))
        {
            if (ftracker->tid == (int)tid)
            {
// FIXIT-M uncomment once file api is ported
/*
                if (ssd->fapi_ftracker == ftracker)
                    DCE2_SmbFinishFileAPI(ssd);

#ifdef ACTIVE_RESPONSE
                if (ssd->fb_ftracker == ftracker)
                    DCE2_SmbFinishFileBlockVerdict(ssd);
#endif
*/
                DCE2_ListRemoveCurrent(ssd->ftrackers);
                DCE2_SmbRemoveFileTrackerFromRequestTrackers(ssd, ftracker);
            }
        }
    }
}

void DCE2_SmbInsertTid(DCE2_SmbSsnData* ssd,
    const uint16_t tid, const bool is_ipc)
{
    Profile profile(dce2_smb_pstat_smb_tid);

    if (!is_ipc && (!DCE2_ScSmbFileInspection((dce2SmbProtoConf*)ssd->sd.config)
        || ((ssd->max_file_depth == -1) && DCE2_ScSmbFileDepth(
        (dce2SmbProtoConf*)ssd->sd.config) == -1)))
    {
        DebugFormat(DEBUG_DCE_SMB, "Not inserting TID (%hu) "
            "because it's not IPC and not inspecting normal file "
            "data.", tid);
        return;
    }

    if (is_ipc && DCE2_ScSmbFileInspectionOnly((dce2SmbProtoConf*)ssd->sd.config))
    {
        DebugFormat(DEBUG_DCE_SMB, "Not inserting TID (%hu) "
            "because it's IPC and only inspecting normal file "
            "data.", tid);
        return;
    }

    DebugFormat(DEBUG_DCE_SMB, "Inserting Tid: %hu\n", tid);
    int insert_tid = (int)tid;
    // Set a bit so as to distinguish between IPC and non-IPC TIDs
    if (!is_ipc)
        insert_tid |= (1 << 16);

    if (ssd->tid == DCE2_SENTINEL)
    {
        ssd->tid = insert_tid;
    }
    else
    {
        if (ssd->tids == nullptr)
        {
            ssd->tids = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED, DCE2_SmbUidTidFidCompare,
                nullptr, nullptr, DCE2_LIST_FLAG__NO_DUPS);

            if (ssd->tids == nullptr)
            {
                return;
            }
        }

        DCE2_ListInsert(ssd->tids, (void*)(uintptr_t)tid, (void*)(uintptr_t)insert_tid);
    }
}

/********************************************************************
 * Function: DCE2_SmbInvalidShareCheck()
 *
 * Purpose:
 *  Checks the share reported in a TreeConnect or TreeConnectAndX
 *  against the invalid share list configured in the dcerpc2
 *  configuration in snort.conf.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - SMB session data structure
 *  SmbNtHdr *        - pointer to the SMB header structure
 *  uint8_t *         - current pointer to the share to check
 *  uint32_t          - the remaining length
 *
 * Returns: None
 *  Alerts if there is an invalid share match.
 *
 ********************************************************************/
void DCE2_SmbInvalidShareCheck(DCE2_SmbSsnData* ssd,
    const SmbNtHdr* smb_hdr, const uint8_t* nb_ptr, uint32_t nb_len)
{
    DCE2_List* share_list = DCE2_ScSmbInvalidShares((dce2SmbProtoConf*)ssd->sd.config);
    if (share_list == nullptr)
        return;

    dce2SmbShare* smb_share;
    for (smb_share = (dce2SmbShare*)DCE2_ListFirst(share_list);
        smb_share != nullptr;
        smb_share = (dce2SmbShare*)DCE2_ListNext(share_list))
    {
        unsigned int i;
        const char* share_str;
        unsigned int share_str_len;

        if (SmbUnicode(smb_hdr))
        {
            share_str = smb_share->unicode_str;
            share_str_len = smb_share->unicode_str_len;
        }
        else
        {
            share_str = smb_share->ascii_str;
            share_str_len = smb_share->ascii_str_len;
        }

        /* Make sure we have enough data */
        if (nb_len < share_str_len)
            continue;

        /* Test for share match */
        for (i = 0; i < share_str_len; i++)
        {
            /* All share strings should have been converted to upper case and
             * should include null terminating bytes */
            if ((nb_ptr[i] != share_str[i]) && (nb_ptr[i] != tolower((int)share_str[i])))
                break;
        }

        if (i == share_str_len)
        {
            /* Should only match one share since no duplicate shares in list */
            dce_alert(GID_DCE2, DCE2_SMB_INVALID_SHARE, (dce2CommonStats*)&dce2_smb_stats);
            break;
        }
    }
}

void DCE2_SmbQueueTmpFileTracker(DCE2_SmbSsnData* ssd,
    DCE2_SmbRequestTracker* rtracker, const uint16_t uid, const uint16_t tid)
{
    Profile profile(dce2_smb_pstat_smb_fid);

    DebugFormat(DEBUG_DCE_SMB, "Queueing file tracker "
        "with Uid: %hu, Tid: %hu\n", uid, tid);

    DCE2_SmbFileTracker* ftracker = (DCE2_SmbFileTracker*)
        snort_calloc(sizeof(DCE2_SmbFileTracker));

    if (ftracker == nullptr)
    {
        return;
    }

    bool is_ipc = DCE2_SmbIsTidIPC(ssd, tid);
    if (DCE2_SmbInitFileTracker(ssd, ftracker, is_ipc, uid, tid, DCE2_SENTINEL) !=
        DCE2_RET__SUCCESS)
    {
        DCE2_SmbCleanFileTracker(ftracker);
        snort_free((void*)ftracker);
        return;
    }

    if (!is_ipc && (ssd->fapi_ftracker == ftracker))
        ssd->fapi_ftracker = nullptr;

    if (rtracker->ft_queue == nullptr)
    {
        rtracker->ft_queue = DCE2_QueueNew(DCE2_SmbFileTrackerDataFree);
        if (rtracker->ft_queue == nullptr)
        {
            DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
            return;
        }
    }

    if (DCE2_QueueEnqueue(rtracker->ft_queue, (void*)ftracker) != DCE2_RET__SUCCESS)
    {
        DCE2_SmbCleanSessionFileTracker(ssd, ftracker);
        return;
    }
}

