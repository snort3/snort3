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

// dce_smb_utils.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb_utils.h"

#include "detection/detection_engine.h"
#include "detection/detection_util.h"
#include "file_api/file_api.h"
#include "main/snort.h"
#include "packet_io/active.h"
#include "utils/util.h"

#include "dce_smb_module.h"

using namespace snort;

static uint8_t dce2_smb_delete_pdu[65535];

/********************************************************************
 * Private function prototypes
 ********************************************************************/
static void DCE2_SmbSetNewFileAPIFileTracker(DCE2_SmbSsnData* ssd);
static void DCE2_SmbResetFileChunks(DCE2_SmbFileTracker* ssd);
static void DCE2_SmbFinishFileAPI(DCE2_SmbSsnData* ssd);
static void DCE2_SmbFinishFileBlockVerdict(DCE2_SmbSsnData* ssd);

/********************************************************************
 * Inline functions
 ********************************************************************/
static inline bool DCE2_SmbIsVerdictSuspend(bool upload, FilePosition position)
{
    if (upload &&
        ((position == SNORT_FILE_FULL) || (position == SNORT_FILE_END)))
        return true;
    return false;
}

static inline bool DCE2_SmbFileUpload(DCE2_SmbFileDirection dir)
{
    return dir == DCE2_SMB_FILE_DIRECTION__UPLOAD;
}

static inline bool DCE2_SmbFileDirUnknown(DCE2_SmbFileDirection dir)
{
    return dir == DCE2_SMB_FILE_DIRECTION__UNKNOWN;
}

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

// Extract file name from data. Supports ASCII and UTF-16LE.
// Returns byte stream (ASCII or UTF-16LE with BOM)
char* DCE2_SmbGetFileName(const uint8_t* data, uint32_t data_len, bool unicode,
    uint16_t* file_name_len)
{
    const uint8_t inc = unicode ? 2 : 1;
    if (data_len < inc)
        return nullptr;

    const uint32_t max_len =  unicode ? data_len - 1 : data_len;
    // Move forward.  Don't know if the end of data is actually
    // the end of the string.
    uint32_t i;
    for (i = 0; i < max_len; i += inc)
    {
        uint16_t uchar = unicode ? extract_16bits(data + i) : data[i];
        if (uchar == 0)
            break;
    }

    char* fname = nullptr;
    const uint32_t real_len = i;

    if (unicode)
    {
        fname = (char*)snort_calloc(real_len + UTF_16_LE_BOM_LEN + 2);
        memcpy(fname, UTF_16_LE_BOM, UTF_16_LE_BOM_LEN);//Prepend with BOM
        memcpy(fname + UTF_16_LE_BOM_LEN, data, real_len);
        *file_name_len = real_len + UTF_16_LE_BOM_LEN;
    }
    else
    {
        fname = (char*)snort_alloc(real_len + 1);
        memcpy(fname, data, real_len);
        fname[real_len] = 0;
        *file_name_len = real_len;
    }

    return fname;
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
        if ((ssd->ftracker.fid_v1 != DCE2_SENTINEL) &&
            (ssd->ftracker.uid_v1 == uid))
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
                if (ftracker->uid_v1 == uid)
                {
                    if (ssd->fapi_ftracker == ftracker)
                        DCE2_SmbFinishFileAPI(ssd);

                    if (ssd->fb_ftracker == ftracker)
                        DCE2_SmbFinishFileBlockVerdict(ssd);

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
        assert(false);
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

    DCE2_SmbFileTracker* ftracker = nullptr;
    if (ssd->ftracker.fid_v1 == DCE2_SENTINEL)
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

    ftracker->uid_v1 = uid;
    ftracker->tid_v1 = tid;
    ftracker->fid_v1 = fid;
    ftracker->is_ipc = is_ipc;
    ftracker->is_smb2 = false;
    ftracker->file_name = nullptr;
    ftracker->file_name_size = 0;
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
            ssd->fapi_ftracker = ftracker;
        }
    }

    return DCE2_RET__SUCCESS;
}

DCE2_SmbFileTracker* DCE2_SmbFindFileTracker(DCE2_SmbSsnData* ssd,
    const uint16_t uid, const uint16_t tid, const uint16_t fid)
{
    Profile profile(dce2_smb_pstat_smb_fid);

    DCE2_SmbFileTracker* ftracker;
    if ((ssd->ftracker.fid_v1 != DCE2_SENTINEL) && (ssd->ftracker.fid_v1 == (int)fid))
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
        return nullptr;
    }

    // Note IPC Tid has already been validated in initial processing
    const DCE2_Policy policy = DCE2_SsnGetServerPolicy(&ssd->sd);
    switch (policy)
    {
    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
        // Only Uid used to open file can be used to make a request
        if (ftracker->uid_v1 != uid)
        {
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
                return nullptr;
            }

            break;
        }
        // fallthrough

    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
        // Both Uid and Tid used to create file must be used to make a request
        if ((ftracker->uid_v1 != uid) || (ftracker->tid_v1 != tid))
        {
            return nullptr;
        }

        break;

    default:
        assert(false);
        break;
    }

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

    if (ssd->fapi_ftracker == ftracker)
        DCE2_SmbFinishFileAPI(ssd);

    if (ssd->fb_ftracker == ftracker)
        DCE2_SmbFinishFileBlockVerdict(ssd);

    if (ftracker == &ssd->ftracker)
        DCE2_SmbCleanFileTracker(&ssd->ftracker);
    else if (ssd->ftrackers != nullptr)
        DCE2_ListRemove(ssd->ftrackers, (void*)(uintptr_t)ftracker->fid_v1);

    DCE2_SmbRemoveFileTrackerFromRequestTrackers(ssd, ftracker);
}

void DCE2_SmbCleanFileTracker(DCE2_SmbFileTracker* ftracker)
{
    if (ftracker == nullptr)
        return;

    Profile profile(dce2_smb_pstat_smb_fid);

    ftracker->fid_v1 = DCE2_SENTINEL;
    if (ftracker->file_name != nullptr)
    {
        snort_free((void*)ftracker->file_name);
        ftracker->file_name = nullptr;
        ftracker->file_name_size = 0;
    }

    if (ftracker->is_ipc)
    {
        ftracker->fp_used = false;
        ftracker->fp_byte_mode = false;

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
        rtracker->file_name_size = 0;
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

    if (rtracker == &ssd->rtracker)
    {
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
            DCE2_QueueRemoveCurrent(ssd->rtrackers);
            ssd->outstanding_requests--;
            return;
        }
    }
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

    DCE2_SmbFileTracker* ftracker = (DCE2_SmbFileTracker*)DCE2_QueueDequeue(rtracker->ft_queue);

    if (ftracker == nullptr)
    {
        return nullptr;
    }

    if (ssd->ftracker.fid_v1 == DCE2_SENTINEL)
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

    // Other values were initialized when queuing.
    ftracker->fid_v1 = (int)fid;

    return ftracker;
}

void DCE2_SmbRequestTrackerDataFree(void* data)
{
    DCE2_SmbRequestTracker* rtracker = (DCE2_SmbRequestTracker*)data;

    if (rtracker == nullptr)
        return;

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

    if ((ssd->tid != DCE2_SENTINEL) && ((ssd->tid & 0x0000ffff) == (int)tid))
        ssd->tid = DCE2_SENTINEL;
    else
        DCE2_ListRemove(ssd->tids, (void*)(uintptr_t)tid);

    // Removing Tid invalidates files created with it
    if ((ssd->ftracker.fid_v1 != DCE2_SENTINEL)
        && (ssd->ftracker.tid_v1 == tid))
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
            if (ftracker->tid_v1 == (int)tid)
            {
                if (ssd->fapi_ftracker == ftracker)
                    DCE2_SmbFinishFileAPI(ssd);

                if (ssd->fb_ftracker == ftracker)
                    DCE2_SmbFinishFileBlockVerdict(ssd);

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
        trace_logf(dce_smb, "Not inserting TID (%hu) "
            "because it's not IPC and not inspecting normal file "
            "data.\n", tid);
        return;
    }

    if (is_ipc && DCE2_ScSmbFileInspectionOnly((dce2SmbProtoConf*)ssd->sd.config))
    {
        trace_logf(dce_smb, "Not inserting TID (%hu) "
            "because it's IPC and only inspecting normal file "
            "data.\n", tid);
        return;
    }

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

DCE2_Ret DCE2_SmbProcessRequestData(DCE2_SmbSsnData* ssd,
    const uint16_t fid, const uint8_t* data_ptr, uint32_t data_len, uint64_t offset)
{
    DCE2_SmbFileTracker* ftracker = DCE2_SmbGetFileTracker(ssd, fid);

    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

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
        DCE2_SmbProcessFileData(ssd, ftracker, data_ptr, data_len, true);
    }

    return DCE2_RET__SUCCESS;
}

DCE2_Ret DCE2_SmbProcessResponseData(DCE2_SmbSsnData* ssd,
    const uint8_t* data_ptr, uint32_t data_len)
{
    DCE2_SmbFileTracker* ftracker = ssd->cur_rtracker->ftracker;

    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

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
        DCE2_SmbProcessFileData(ssd, ftracker, data_ptr, data_len, false);
    }

    return DCE2_RET__SUCCESS;
}

static inline uint16_t SmbHtons(const uint16_t* ptr)
{
    return alignedNtohs(ptr);
}

/********************************************************************
 * Function: DCE2_SmbInitRdata()
 *
 * Purpose:
 *  Initializes the reassembled packet structure for an SMB
 *  reassembled packet.  Uses WriteAndX and ReadAndX.
 *  TODO Use command that was used when reassembly occurred.
 *  One issue with this is that multiple different write/read
 *  commands can be used to write/read the full DCE/RPC
 *  request/response.
 *
 * Arguments:
 *  uint8_t * - pointer to the start of the NetBIOS header where
 *              data initialization should start.
 *  int dir   - FLAG_FROM_CLIENT or FLAG_FROM_SERVER
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_SmbInitRdata(uint8_t* nb_ptr, int dir)
{
    NbssHdr* nb_hdr = (NbssHdr*)nb_ptr;
    SmbNtHdr* smb_hdr = (SmbNtHdr*)((uint8_t*)nb_hdr + sizeof(NbssHdr));

    nb_hdr->type = NBSS_SESSION_TYPE__MESSAGE;
    memcpy((void*)smb_hdr->smb_idf, (void*)"\xffSMB", sizeof(smb_hdr->smb_idf));

    if (dir == PKT_FROM_CLIENT)
    {
        SmbWriteAndXReq* writex =
            (SmbWriteAndXReq*)((uint8_t*)smb_hdr + sizeof(SmbNtHdr));
        uint16_t offset = sizeof(SmbNtHdr) + sizeof(SmbWriteAndXReq);

        smb_hdr->smb_com = SMB_COM_WRITE_ANDX;
        smb_hdr->smb_flg = 0x00;

        writex->smb_wct = 12;
        writex->smb_com2 = SMB_COM_NO_ANDX_COMMAND;
        writex->smb_doff = SmbHtons(&offset);
    }
    else
    {
        SmbReadAndXResp* readx =
            (SmbReadAndXResp*)((uint8_t*)smb_hdr + sizeof(SmbNtHdr));
        uint16_t offset = sizeof(SmbNtHdr) + sizeof(SmbReadAndXResp);

        smb_hdr->smb_com = SMB_COM_READ_ANDX;
        smb_hdr->smb_flg = 0x80;

        readx->smb_wct = 12;
        readx->smb_com2 = SMB_COM_NO_ANDX_COMMAND;
        readx->smb_doff = SmbHtons(&offset);
    }
}

/********************************************************************
 * Function: DCE2_SmbSetRdata()
 *
 * Purpose:
 *  When a reassembled packet is needed this function is called to
 *  fill in appropriate fields to make the reassembled packet look
 *  correct from an SMB standpoint.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - the session data structure.
 *  uint8_t * - pointer to the start of the NetBIOS header where
 *              data initialization should start.
 *  uint16_t  - the length of the connection-oriented DCE/RPC data.
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_SmbSetRdata(DCE2_SmbSsnData* ssd, uint8_t* nb_ptr, uint16_t co_len)
{
    NbssHdr* nb_hdr = (NbssHdr*)nb_ptr;
    SmbNtHdr* smb_hdr = (SmbNtHdr*)((uint8_t*)nb_hdr + sizeof(NbssHdr));
    uint16_t uid = (ssd->cur_rtracker == nullptr) ? 0 : ssd->cur_rtracker->uid;
    uint16_t tid = (ssd->cur_rtracker == nullptr) ? 0 : ssd->cur_rtracker->tid;
    DCE2_SmbFileTracker* ftracker = (ssd->cur_rtracker == nullptr) ? nullptr :
        ssd->cur_rtracker->ftracker;

    smb_hdr->smb_uid = SmbHtons((const uint16_t*)&uid);
    smb_hdr->smb_tid = SmbHtons((const uint16_t*)&tid);

    if (DCE2_SsnFromClient(ssd->sd.wire_pkt))
    {
        SmbWriteAndXReq* writex =
            (SmbWriteAndXReq*)((uint8_t*)smb_hdr + sizeof(SmbNtHdr));
        uint32_t nb_len = sizeof(SmbNtHdr) + sizeof(SmbWriteAndXReq) + co_len;

        /* The data will get truncated anyway since we can only fit
         * 64K in the reassembly buffer */
        if (nb_len > UINT16_MAX)
            nb_len = UINT16_MAX;

        nb_hdr->length = htons((uint16_t)nb_len);

        if ((ftracker != nullptr) && (ftracker->fid_v1 > 0))
        {
            uint16_t fid = (uint16_t)ftracker->fid_v1;
            writex->smb_fid = SmbHtons(&fid);
        }
        else
        {
            writex->smb_fid = 0;
        }

        writex->smb_countleft = SmbHtons(&co_len);
        writex->smb_dsize = SmbHtons(&co_len);
        writex->smb_bcc = SmbHtons(&co_len);
    }
    else
    {
        SmbReadAndXResp* readx =
            (SmbReadAndXResp*)((uint8_t*)smb_hdr + sizeof(SmbNtHdr));
        uint32_t nb_len = sizeof(SmbNtHdr) + sizeof(SmbReadAndXResp) + co_len;

        /* The data will get truncated anyway since we can only fit
         * 64K in the reassembly buffer */
        if (nb_len > UINT16_MAX)
            nb_len = UINT16_MAX;

        nb_hdr->length = htons((uint16_t)nb_len);

        readx->smb_remaining = SmbHtons(&co_len);
        readx->smb_dsize = SmbHtons(&co_len);
        readx->smb_bcc = SmbHtons(&co_len);
    }
}

Packet* DCE2_SmbGetRpkt(DCE2_SmbSsnData* ssd,
    const uint8_t** data, uint32_t* data_len, DCE2_RpktType rtype)
{
    if ((ssd == nullptr) || (data == nullptr) || (*data == nullptr)
        || (data_len == nullptr) || (*data_len == 0))
        return nullptr;

    Packet* rpkt = DCE2_GetRpkt(ssd->sd.wire_pkt, rtype, *data, *data_len);

    if ( !rpkt )
        return nullptr;

    *data = rpkt->data;
    *data_len = rpkt->dsize;

    uint16_t header_len;
    switch (rtype)
    {
    case DCE2_RPKT_TYPE__SMB_TRANS:
        if (DCE2_SmbType(ssd) == SMB_TYPE__REQUEST)
            header_len = DCE2_MOCK_HDR_LEN__SMB_CLI;
        else
            header_len = DCE2_MOCK_HDR_LEN__SMB_SRV;
        DCE2_SmbSetRdata(ssd, const_cast<uint8_t*>(rpkt->data),
            (uint16_t)(rpkt->dsize - header_len));
        DCE2_MOVE(*data, *data_len, header_len);
        break;
    case DCE2_RPKT_TYPE__SMB_SEG:
    default:
        break;
    }

    return rpkt;
}

/********************************************************************
 * Function: DCE2_SmbHandleSegmentation()
 *
 * Wrapper around DCE2_HandleSegmentation() to allocate a new
 * buffer object if necessary.
 *
 * Arguments:
 *  DCE2_SmbBuffer **
 *      Pointer to pointer of buffer to add data to.  If NULL
 *      a new buffer will be allocated.
 *  uint8_t *
 *      Pointer to the current data cursor in packet.
 *  uint32_t
 *      Length of data to add to buffer.
 *  uint32_t
 *      The minimum allocation size so that small allocations
 *      aren't consistently done.
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__ERROR if an error occurred.  Nothing can
 *          be trusted.
 *      DCE2_RET__SUCCESS if data was successfully added.
 *
 ********************************************************************/
DCE2_Ret DCE2_SmbHandleSegmentation(DCE2_Buffer** buf,
    const uint8_t* data_ptr, uint32_t add_len, uint32_t alloc_size)
{
    Profile profile(dce2_smb_pstat_smb_seg);

    if (buf == nullptr)
    {
        return DCE2_RET__ERROR;
    }

    if (*buf == nullptr)
    {
        /* No initial size or min alloc size */
        *buf = DCE2_BufferNew(alloc_size, alloc_size);
    }

    DCE2_Ret status = DCE2_BufferAddData(*buf, data_ptr, add_len,
        DCE2_BufferLength(*buf), DCE2_BUFFER_MIN_ADD_FLAG__IGNORE);

    return status;
}

/********************************************************************
 * Function: DCE2_SmbIsSegBuffer()
 *
 * Purpose:
 *  Determines whether the pointer passed in lies within one of the
 *  segmentation buffers or not.
 *
 * Arguments:
 *  DCE2_SmbSsnData *
 *      Pointer to SMB session data.
 *
 * Returns:
 *  bool  -  True is the pointer lies within one of the segmentation
 *           buffers.
 *           False if it doesn't.
 *
 ********************************************************************/
bool DCE2_SmbIsSegBuffer(DCE2_SmbSsnData* ssd, const uint8_t* ptr)
{
    DCE2_Buffer* seg_buf;

    if (DCE2_SsnFromServer(ssd->sd.wire_pkt))
        seg_buf = ssd->srv_seg;
    else
        seg_buf = ssd->cli_seg;

    if (DCE2_BufferIsEmpty(seg_buf))
        return false;

    /* See if we're looking at a segmentation buffer */
    if ((ptr < DCE2_BufferData(seg_buf)) ||
        (ptr > (DCE2_BufferData(seg_buf) + DCE2_BufferLength(seg_buf))))
    {
        return false;
    }

    return true;
}

/********************************************************************
 * Function: DCE2_SmbSegAlert()
 *
 * Purpose:
 *  To create a reassembled packet using the data in one of the
 *  segmentation buffers in order to generate an alert with the
 *  correct, or more complete data.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - Pointer to SMB session data.
 *  rule_id -  rule id .
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_SmbSegAlert(DCE2_SmbSsnData* ssd, uint32_t rule_id)
{
    DCE2_Buffer* buf;

    if (DCE2_SsnFromClient(ssd->sd.wire_pkt))
        buf = ssd->cli_seg;
    else
        buf = ssd->srv_seg;

    /* This should be called from the desegmentation code. */
    if (DCE2_BufferIsEmpty(buf))
        return;

    const uint8_t* data_ptr = DCE2_BufferData(buf);
    uint32_t data_len = DCE2_BufferLength(buf);

    Packet* rpkt = DCE2_SmbGetRpkt(ssd, &data_ptr, &data_len, DCE2_RPKT_TYPE__SMB_SEG);
    if (rpkt == nullptr)
        return;

    dce_alert(GID_DCE2, rule_id, (dce2CommonStats*)&dce2_smb_stats);
}

static void DCE2_SmbResetFileChunks(DCE2_SmbFileTracker* ftracker)
{
    if (ftracker == nullptr)
        return;

    DCE2_ListDestroy(ftracker->ff_file_chunks);
    ftracker->ff_file_chunks = nullptr;
    ftracker->ff_bytes_queued = 0;
}

void DCE2_SmbAbortFileAPI(DCE2_SmbSsnData* ssd)
{
    DCE2_SmbResetFileChunks(ssd->fapi_ftracker);
    ssd->fapi_ftracker = nullptr;
}

static FileContext* DCE2_get_main_file_context(DCE2_SmbSsnData* ssd)
{
    assert(ssd->sd.wire_pkt);
    FileFlows* file_flows = FileFlows::get_file_flows((ssd->sd.wire_pkt)->flow);
    assert(file_flows);
    return file_flows->get_current_file_context();
}

FileVerdict DCE2_get_file_verdict(DCE2_SmbSsnData* ssd)
{
    FileContext* file = DCE2_get_main_file_context(ssd);
    if ( !file )
        return FILE_VERDICT_UNKNOWN;
    return file->verdict;
}

void DCE2_SmbInitDeletePdu()
{
    NbssHdr* nb_hdr = (NbssHdr*)dce2_smb_delete_pdu;
    SmbNtHdr* smb_hdr = (SmbNtHdr*)((uint8_t*)nb_hdr + sizeof(*nb_hdr));
    SmbDeleteReq* del_req = (SmbDeleteReq*)((uint8_t*)smb_hdr + sizeof(*smb_hdr));
    uint8_t* del_req_fmt = (uint8_t*)del_req + sizeof(*del_req);
    uint16_t smb_flg2 = 0x4001;
    uint16_t search_attrs = 0x0006;

    memset(dce2_smb_delete_pdu, 0, sizeof(dce2_smb_delete_pdu));

    nb_hdr->type = 0;
    nb_hdr->flags = 0;

    memcpy((void*)smb_hdr->smb_idf, (void*)"\xffSMB", sizeof(smb_hdr->smb_idf));
    smb_hdr->smb_com = SMB_COM_DELETE;
    smb_hdr->smb_status.nt_status = 0;
    //smb_hdr->smb_flg = 0x18;
    smb_hdr->smb_flg = 0;
    smb_hdr->smb_flg2 = SmbHtons(&smb_flg2);
    smb_hdr->smb_tid = 0;   // needs to be set before injected
    smb_hdr->smb_pid = 777;
    smb_hdr->smb_uid = 0;   // needs to be set before injected
    smb_hdr->smb_mid = 777;

    del_req->smb_wct = 1;
    del_req->smb_search_attrs = SmbHtons(&search_attrs);
    *del_req_fmt = SMB_FMT__ASCII;
}

static void DCE2_SmbInjectDeletePdu(DCE2_SmbSsnData* ssd, DCE2_SmbFileTracker* ftracker)
{
    Packet* inject_pkt = snort::Snort::get_packet();
    if ( inject_pkt->flow != ssd->sd.wire_pkt->flow )
        return;

    NbssHdr* nb_hdr = (NbssHdr*)dce2_smb_delete_pdu;
    SmbNtHdr* smb_hdr = (SmbNtHdr*)((uint8_t*)nb_hdr + sizeof(*nb_hdr));
    SmbDeleteReq* del_req = (SmbDeleteReq*)((uint8_t*)smb_hdr + sizeof(*smb_hdr));
    char* del_filename = (char*)((uint8_t*)del_req + sizeof(*del_req) + 1);
    FileCharEncoding encoding = get_character_encoding(ftracker->file_name,
        ftracker->file_name_size);
    uint16_t file_name_len;

    if (encoding == SNORT_CHAR_ENCODING_UTF_16LE)
    {
        file_name_len = ftracker->file_name_size - UTF_16_LE_BOM_LEN + 2;
        uint16_t smb_flg2 = 0xC001;
        smb_hdr->smb_flg2 = SmbHtons(&smb_flg2);
    }
    else
    {
        file_name_len = ftracker->file_name_size + 1;
    }

    nb_hdr->length = htons(sizeof(*smb_hdr) + sizeof(*del_req) + 1 + file_name_len);
    uint32_t len = ntohs(nb_hdr->length) + sizeof(*nb_hdr);
    smb_hdr->smb_tid = SmbHtons(&ftracker->tid_v1);
    smb_hdr->smb_uid = SmbHtons(&ftracker->uid_v1);
    del_req->smb_bcc = 1 + file_name_len;
    memcpy(del_filename, ftracker->file_name + UTF_16_LE_BOM_LEN, file_name_len);

    Active::inject_data(inject_pkt, 0, (uint8_t*)nb_hdr, len);
}

static FileVerdict DCE2_SmbLookupFileVerdict(DCE2_SmbSsnData* ssd)
{
    Profile profile(dce2_smb_pstat_smb_file_api);

    FileContext* file = DCE2_get_main_file_context(ssd);

    if ( !file )
        return FILE_VERDICT_UNKNOWN;

    FileVerdict verdict = file->verdict;

    if (verdict == FILE_VERDICT_PENDING)
        verdict = file->file_signature_lookup(ssd->sd.wire_pkt->flow);

    return verdict;
}

static void DCE2_SmbFinishFileBlockVerdict(DCE2_SmbSsnData* ssd)
{
    Profile profile(dce2_smb_pstat_smb_file);

    FileVerdict verdict = DCE2_SmbLookupFileVerdict(ssd);
    if ((verdict == FILE_VERDICT_BLOCK) || (verdict == FILE_VERDICT_REJECT))
    {
        DCE2_SmbInjectDeletePdu(ssd, ssd->fb_ftracker);
    }

    ssd->fb_ftracker = nullptr;
    ssd->block_pdus = false;
}

static void DCE2_SmbFinishFileAPI(DCE2_SmbSsnData* ssd)
{
    Packet* p = ssd->sd.wire_pkt;
    DCE2_SmbFileTracker* ftracker = ssd->fapi_ftracker;

    if (ftracker == nullptr)
        return;

    Profile profile(dce2_smb_pstat_smb_file);
    FileFlows* file_flows = FileFlows::get_file_flows(p->flow);
    bool upload = (ftracker->ff_file_direction == DCE2_SMB_FILE_DIRECTION__UPLOAD);

    if (get_file_processed_size(p->flow) != 0)
    {
        // Never knew the size of the file so never knew when to tell the
        // fileAPI the upload/download was finished.
        if ((ftracker->ff_file_size == 0)
            && (ftracker->ff_bytes_processed != 0))
        {
            Profile profile(dce2_smb_pstat_smb_file_api);
            if (file_flows->file_process(nullptr, 0, SNORT_FILE_END, upload))
            {
                if (upload)
                {
                    FileVerdict verdict = DCE2_get_file_verdict(ssd);

                    if ((verdict == FILE_VERDICT_BLOCK) || (verdict == FILE_VERDICT_REJECT))
                        ssd->fb_ftracker = ftracker;
                }
            }
            dce2_smb_stats.smb_files_processed++;
        }
    }

    ssd->fapi_ftracker = nullptr;
}

static DCE2_Ret DCE2_SmbFileAPIProcess(DCE2_SmbSsnData* ssd,
    DCE2_SmbFileTracker* ftracker, const uint8_t* data_ptr,
    uint32_t data_len, bool upload)
{
    FilePosition position;

    if (ssd->fb_ftracker && (ssd->fb_ftracker != ftracker))
        return DCE2_RET__SUCCESS;

    // Trim data length if it exceeds the maximum file depth
    if ((ssd->max_file_depth != 0)
        && (ftracker->ff_bytes_processed + data_len) > (uint64_t)ssd->max_file_depth)
        data_len = ssd->max_file_depth - ftracker->ff_bytes_processed;

    if (ftracker->ff_file_size == 0)
    {
        // Don't know the file size.
        if ((ftracker->ff_bytes_processed == 0) && (ssd->max_file_depth != 0)
            && (data_len == (uint64_t)ssd->max_file_depth))
            position = SNORT_FILE_FULL;
        else if (ftracker->ff_bytes_processed == 0)
            position = SNORT_FILE_START;
        else if ((ssd->max_file_depth != 0)
            && ((ftracker->ff_bytes_processed + data_len) == (uint64_t)ssd->max_file_depth))
            position = SNORT_FILE_END;
        else
            position = SNORT_FILE_MIDDLE;
    }
    else
    {
        if ((ftracker->ff_bytes_processed == 0)
            && ((data_len == ftracker->ff_file_size)
            || ((ssd->max_file_depth != 0) && (data_len == (uint64_t)ssd->max_file_depth))))
            position = SNORT_FILE_FULL;
        else if (ftracker->ff_bytes_processed == 0)
            position = SNORT_FILE_START;
        else if (((ftracker->ff_bytes_processed + data_len) >= ftracker->ff_file_size)
            || ((ssd->max_file_depth != 0)
            && ((ftracker->ff_bytes_processed + data_len) == (uint64_t)ssd->max_file_depth)))
            position = SNORT_FILE_END;
        else
            position = SNORT_FILE_MIDDLE;
    }

    Profile profile(dce2_smb_pstat_smb_file_api);
    FileFlows* file_flows = FileFlows::get_file_flows(ssd->sd.wire_pkt->flow);
    if (!file_flows->file_process(data_ptr, (int)data_len, position, upload,
        DCE2_SmbIsVerdictSuspend(upload, position)))
    {
        trace_logf(dce_smb, "File API returned FAILURE "
            "for (0x%02X) %s\n", ftracker->fid_v1, upload ? "UPLOAD" : "DOWNLOAD");

        // Failure.  Abort tracking this file under file API
        return DCE2_RET__ERROR;
    }
    else
    {
        if (((position == SNORT_FILE_START) || (position == SNORT_FILE_FULL))
            && (ftracker->file_name_size != 0))
        {
            file_flows->set_file_name((uint8_t*)ftracker->file_name, ftracker->file_name_size);
        }

        if ((position == SNORT_FILE_FULL) || (position == SNORT_FILE_END))
        {
            if (upload)
            {
                FileVerdict verdict = DCE2_get_file_verdict(ssd);

                if ((verdict == FILE_VERDICT_BLOCK) || (verdict == FILE_VERDICT_REJECT)
                    || (verdict == FILE_VERDICT_PENDING))
                {
                    ssd->fb_ftracker = ftracker;
                }
            }
            ftracker->ff_sequential_only = false;

            dce2_smb_stats.smb_files_processed++;
            return DCE2_RET__FULL;
        }
    }

    return DCE2_RET__SUCCESS;
}

static int DCE2_SmbFileOffsetCompare(const void* a, const void* b)
{
    const DCE2_SmbFileChunk* x = (const DCE2_SmbFileChunk*)a;
    const DCE2_SmbFileChunk* y = (const DCE2_SmbFileChunk*)b;

    if (x->offset > y->offset)
        return 1;
    if (x->offset < y->offset)
        return -1;

    return 0;
}

static void DCE2_SmbFileChunkFree(void* data)
{
    DCE2_SmbFileChunk* fc = (DCE2_SmbFileChunk*)data;

    if (fc == nullptr)
        return;

    if (fc->data != nullptr)
        snort_free((void*)fc->data);

    snort_free((void*)fc);
}

static DCE2_Ret DCE2_SmbHandleOutOfOrderFileData(DCE2_SmbSsnData* ssd,
    DCE2_SmbFileTracker* ftracker, const uint8_t* data_ptr,
    uint32_t data_len, bool upload)
{
    if (ftracker->ff_file_offset == ftracker->ff_bytes_processed)
    {
        uint64_t initial_offset = ftracker->ff_file_offset;
        uint64_t next_offset = initial_offset + data_len;
        DCE2_SmbFileChunk* file_chunk = (DCE2_SmbFileChunk*)DCE2_ListFirst(
            ftracker->ff_file_chunks);
        DCE2_Ret ret = DCE2_SmbFileAPIProcess(ssd, ftracker, data_ptr, data_len, upload);

        ftracker->ff_bytes_processed += data_len;
        ftracker->ff_file_offset = ftracker->ff_bytes_processed;

        if (ret != DCE2_RET__SUCCESS)
            return ret;

        // Should already be chunks in here if we came into this function
        // with an in order chunk, but check just in case.
        if (file_chunk == nullptr)
            return DCE2_RET__ERROR;

        while (file_chunk != nullptr)
        {
            if (file_chunk->offset > next_offset)
                break;

            if (file_chunk->offset == next_offset)
            {
                ret = DCE2_SmbFileAPIProcess(ssd, ftracker,
                    file_chunk->data, file_chunk->length, upload);

                ftracker->ff_bytes_processed += file_chunk->length;
                ftracker->ff_file_offset = ftracker->ff_bytes_processed;

                if (ret != DCE2_RET__SUCCESS)
                    return ret;

                next_offset = file_chunk->offset + file_chunk->length;
            }

            ftracker->ff_bytes_queued -= file_chunk->length;
            DCE2_ListRemoveCurrent(ftracker->ff_file_chunks);

            file_chunk = (DCE2_SmbFileChunk*)DCE2_ListNext(ftracker->ff_file_chunks);
        }

        if (initial_offset == 0)
            DCE2_SmbResetFileChunks(ftracker);
    }
    else
    {
        if (ftracker->ff_file_chunks == nullptr)
        {
            ftracker->ff_file_chunks = DCE2_ListNew(DCE2_LIST_TYPE__SORTED,
                DCE2_SmbFileOffsetCompare, DCE2_SmbFileChunkFree,
                nullptr, DCE2_LIST_FLAG__NO_DUPS);

            if (ftracker->ff_file_chunks == nullptr)
                return DCE2_RET__ERROR;
        }

        DCE2_SmbFileChunk* file_chunk = (DCE2_SmbFileChunk*)snort_calloc(
            sizeof(DCE2_SmbFileChunk));
        file_chunk->data = (uint8_t*)snort_calloc(data_len);

        file_chunk->offset = ftracker->ff_file_offset;
        file_chunk->length = data_len;
        memcpy(file_chunk->data, data_ptr, data_len);
        ftracker->ff_bytes_queued += data_len;

        DCE2_Ret ret;
        if ((ret = DCE2_ListInsert(ftracker->ff_file_chunks,
                (void*)file_chunk, (void*)file_chunk)) != DCE2_RET__SUCCESS)
        {
            snort_free((void*)file_chunk->data);
            snort_free((void*)file_chunk);

            if (ret != DCE2_RET__DUPLICATE)
                return DCE2_RET__ERROR;
        }
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_SmbProcessFileData()
 *
 * Purpose:
 *  Processes regular file data send via reads/writes.  Sends
 *  data to the file API for type id and signature and sets the
 *  file data ptr for rule inspection.
 *
 * Arguments:
 *  DCE2_SmbSsnData *      - pointer to SMB session data
 *  DCE2_SmbFileTracker *  - pointer to file tracker
 *  const uint8_t *        - pointer to file data
 *  uint32_t               - length of file data
 *  bool                   - whether it's an upload (true) or
 *                           download (false)
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_SmbProcessFileData(DCE2_SmbSsnData* ssd,
    DCE2_SmbFileTracker* ftracker, const uint8_t* data_ptr,
    uint32_t data_len, bool upload)
{
    bool cur_upload = DCE2_SmbFileUpload(ftracker->ff_file_direction) ? true : false;
    int64_t file_data_depth = DCE2_ScSmbFileDepth((dce2SmbProtoConf*)ssd->sd.config);

    if (data_len == 0)
        return;

    Profile profile(dce2_smb_pstat_smb_file);

    // Account for wrapping.  Not likely but just in case.
    if ((ftracker->ff_bytes_processed + data_len) < ftracker->ff_bytes_processed)
    {
        DCE2_SmbRemoveFileTracker(ssd, ftracker);
        return;
    }

    if ((ftracker->ff_bytes_processed == 0)
        && DCE2_SmbFileDirUnknown(ftracker->ff_file_direction))
    {
        ftracker->ff_file_direction =
            upload ? DCE2_SMB_FILE_DIRECTION__UPLOAD : DCE2_SMB_FILE_DIRECTION__DOWNLOAD;
    }
    else if (cur_upload != upload)
    {
        if (cur_upload)
        {
            // Went from writing to reading.  Ignore the read.
            return;
        }

        // Went from reading to writing.  Consider the transfer done
        // and remove the file tracker.
        DCE2_SmbRemoveFileTracker(ssd, ftracker);
        return;
    }

    if ((file_data_depth != -1) &&
        ((ftracker->ff_file_offset == ftracker->ff_bytes_processed) &&
        ((file_data_depth == 0) || (ftracker->ff_bytes_processed < (uint64_t)file_data_depth))))
    {
        set_file_data(data_ptr, (data_len > UINT16_MAX) ? UINT16_MAX : (uint16_t)data_len);
        DCE2_FileDetect();
    }

    if (ftracker == ssd->fapi_ftracker)
    {
        DCE2_Ret ret;

        if ((ftracker->ff_file_offset != ftracker->ff_bytes_processed)
            || !DCE2_ListIsEmpty(ftracker->ff_file_chunks))
        {
            if ((ssd->max_file_depth != 0)
                && (ftracker->ff_file_offset >= (uint64_t)ssd->max_file_depth))
            {
                // If the offset is beyond the max file depth, ignore it.
                return;
            }
            else if (upload && (data_len == 1)
                && (ftracker->ff_file_offset > ftracker->ff_bytes_processed))
            {
                // Sometimes a write one byte is done at a high offset, I'm
                // guessing to make sure the system has sufficient disk
                // space to complete the full write.  Ignore it because it
                // will likely be overwritten.
                return;
            }

            if ((ftracker->ff_file_offset == 0) && (ftracker->ff_bytes_processed != 0))
            {
                // Sometimes initial reads/writes are out of order to get file info
                // such as an icon, then proceed to write in order.  Usually the
                // first read/write is at offset 0, then the next ones are somewhere
                // off in the distance.  Reset and continue on below.
                DCE2_SmbResetFileChunks(ftracker);
                ftracker->ff_bytes_processed = 0;
            }
            else if (ftracker->ff_file_offset < ftracker->ff_bytes_processed)
            {
                trace_logf(dce_smb, "File offset %" PRIu64 " is "
                    "less than bytes processed %" PRIu64 " - aborting.\n",
                    ftracker->ff_file_offset, ftracker->ff_bytes_processed);

                DCE2_SmbAbortFileAPI(ssd);
                DCE2_SmbSetNewFileAPIFileTracker(ssd);
                return;
            }
            else
            {
                ret = DCE2_SmbHandleOutOfOrderFileData(ssd, ftracker, data_ptr, data_len, upload);
                if (ret != DCE2_RET__SUCCESS)
                {
                    DCE2_SmbAbortFileAPI(ssd);
                    DCE2_SmbSetNewFileAPIFileTracker(ssd);
                }
                return;
            }
        }

        ret = DCE2_SmbFileAPIProcess(ssd, ftracker, data_ptr, data_len, upload);

        ftracker->ff_bytes_processed += data_len;
        ftracker->ff_file_offset = ftracker->ff_bytes_processed;

        if (ret != DCE2_RET__SUCCESS)
        {
            DCE2_SmbAbortFileAPI(ssd);
            DCE2_SmbSetNewFileAPIFileTracker(ssd);
        }
    }
    else
    {
        if (ftracker->ff_file_offset == ftracker->ff_bytes_processed)
        {
            ftracker->ff_bytes_processed += data_len;
            ftracker->ff_file_offset = ftracker->ff_bytes_processed;
        }

        if ((file_data_depth == -1)
            || ((file_data_depth != 0)
            && (ftracker->ff_bytes_processed >= (uint64_t)file_data_depth)))
        {
	    // Bytes processed is at or beyond file data depth - finished.
            DCE2_SmbRemoveFileTracker(ssd, ftracker);
            return;
        }
    }
}

void DCE2_FileDetect()
{
    Packet* top_pkt = DetectionEngine::get_current_packet();

    Profile profile(dce2_smb_pstat_smb_file_detect);
    DetectionEngine::detect(top_pkt);

    dce2_detected = 1;
}

static void DCE2_SmbSetNewFileAPIFileTracker(DCE2_SmbSsnData* ssd)
{
    assert(ssd);
    DCE2_SmbFileTracker* ftracker = &ssd->ftracker;

    while (ftracker != nullptr)
    {
        if ((ftracker != ssd->fapi_ftracker) && (ftracker->fid_v1 != DCE2_SENTINEL)
            && !ftracker->is_ipc && ftracker->ff_sequential_only
            && (ftracker->ff_bytes_processed == 0))
        {
            break;
        }

        if (ftracker == &ssd->ftracker)
            ftracker = (DCE2_SmbFileTracker*)DCE2_ListFirst(ssd->ftrackers);
        else
            ftracker = (DCE2_SmbFileTracker*)DCE2_ListNext(ssd->ftrackers);
    }
    ssd->fapi_ftracker = ftracker;
}

void DCE2_Update_Ftracker_from_ReqTracker(DCE2_SmbFileTracker* ftracker,
    DCE2_SmbRequestTracker* cur_rtracker)
{
    ftracker->file_name = cur_rtracker->file_name;
    ftracker->file_name_size = cur_rtracker->file_name_size;
    cur_rtracker->file_name = nullptr;
    cur_rtracker->file_name_size = 0;
}

