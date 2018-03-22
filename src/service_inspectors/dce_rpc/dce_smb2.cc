//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// SMB2 file processing
// Author(s):  Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb2.h"

#include "detection/detection_util.h"
#include "file_api/file_flows.h"
#include "file_api/file_service.h"
#include "utils/util.h"

#include "dce_smb_module.h"
#include "dce_smb_utils.h"

using namespace snort;

#define   UNKNOWN_FILE_SIZE                  ~0

// FIXIT-L port fileCache related code along with
// DCE2_Smb2Init, DCE2_Smb2Close and DCE2_Smb2UpdateStats

static void DCE2_Smb2Inspect(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* end);

static inline uint32_t Smb2Tid(const Smb2Hdr* hdr)
{
    return alignedNtohl(&(((const Smb2SyncHdr*)hdr)->tree_id));
}

static int DCE2_Smb2TidCompare(const void* a, const void* b)
{
    uint32_t x = (uint32_t)(uintptr_t)a;
    uint32_t y = (uint32_t)(uintptr_t)b;

    if (x == y)
        return 0;

    /* Only care about equality for finding */
    return -1;
}

static inline void DCE2_Smb2InsertTid(DCE2_SmbSsnData* ssd, const uint32_t tid,
    const uint8_t share_type)
{
    bool is_ipc = (share_type != SMB2_SHARE_TYPE_DISK);

    if (!is_ipc && (!DCE2_ScSmbFileInspection((dce2SmbProtoConf*)ssd->sd.config)
        || ((ssd->max_file_depth == -1) && DCE2_ScSmbFileDepth(
        (dce2SmbProtoConf*)ssd->sd.config) == -1)))
    {
        trace_logf(dce_smb, "Not inserting TID (%u) because it's "
            "not IPC and not inspecting normal file data.\n", tid);
        return;
    }

    if (is_ipc)
    {
        trace_logf(dce_smb, "Not inserting TID (%u) "
            "because it's IPC and only inspecting normal file data.\n", tid);
        return;
    }

    if (ssd->tids == nullptr)
    {
        ssd->tids = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED, DCE2_Smb2TidCompare,
            nullptr, nullptr, DCE2_LIST_FLAG__NO_DUPS);

        if (ssd->tids == nullptr)
        {
            return;
        }
    }

    DCE2_ListInsert(ssd->tids, (void*)(uintptr_t)tid, (void*)(uintptr_t)share_type);
}

static DCE2_Ret DCE2_Smb2FindTid(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr)
{
    /* Still process async commands*/
    if (alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND)
        return DCE2_RET__SUCCESS;

    return DCE2_ListFindKey(ssd->tids, (void*)(uintptr_t)Smb2Tid(smb_hdr));
}

static inline void DCE2_Smb2RemoveTid(DCE2_SmbSsnData* ssd, const uint32_t tid)
{
    DCE2_ListRemove(ssd->tids, (void*)(uintptr_t)tid);
}

static inline void DCE2_Smb2StoreRequest(DCE2_SmbSsnData* ssd,
    uint64_t message_id, uint64_t offset, uint64_t file_id)
{
    Smb2Request* request = ssd->smb2_requests;
    ssd->max_outstanding_requests = 128; /* windows client max */

    while (request)
    {
        if (request->message_id == message_id)
            return;
        request = request->next;
    }

    request = (Smb2Request*)snort_calloc(sizeof(*request));

    ssd->outstanding_requests++;

    if (ssd->outstanding_requests >= ssd->max_outstanding_requests)
    {
        dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats);
        snort_free((void*)request);
        return;
    }

    request->message_id = message_id;
    request->offset = offset;
    request->file_id = file_id;

    request->next = ssd->smb2_requests;
    request->previous = nullptr;
    if (ssd->smb2_requests)
        ssd->smb2_requests->previous = request;
    ssd->smb2_requests = request;
}

static inline Smb2Request* DCE2_Smb2GetRequest(DCE2_SmbSsnData* ssd,
    uint64_t message_id)
{
    Smb2Request* request = ssd->smb2_requests;
    while (request)
    {
        if (request->message_id == message_id)
            return request;
        request = request->next;
    }

    return nullptr;
}

static inline void DCE2_Smb2RemoveRequest(DCE2_SmbSsnData* ssd,
    Smb2Request* request)
{
    if (request->previous)
    {
        request->previous->next = request->next;
    }

    if (request->next)
    {
        request->next->previous = request->previous;
    }

    if (request == ssd->smb2_requests)
    {
        ssd->smb2_requests =  request->next;
    }

    ssd->outstanding_requests--;
    snort_free((void*)request);
}

static inline void DCE2_Smb2FreeFileName(DCE2_SmbFileTracker* ftracker)
{
    if (ftracker->file_name)
    {
        snort_free((void*)ftracker->file_name);
        ftracker->file_name = nullptr;
    }
    ftracker->file_name_size = 0;
}

static inline void DCE2_Smb2ResetFileName(DCE2_SmbFileTracker* ftracker)
{
    // FIXIT-L remove snort_free once file cache is ported.
    if (ftracker->file_name)
    {
        snort_free((void*)ftracker->file_name);
    }
    ftracker->file_name = nullptr;
    ftracker->file_name_size = 0;
}

static inline FileContext* get_file_context(DCE2_SmbSsnData* ssd, uint64_t file_id)
{
    assert(ssd->sd.wire_pkt);
    FileFlows* file_flows = FileFlows::get_file_flows((ssd->sd.wire_pkt)->flow);
    if(!file_flows)
        return nullptr;
    return file_flows->get_file_context(file_id, true);
}

static inline void DCE2_Smb2ProcessFileData(DCE2_SmbSsnData* ssd, const uint8_t* file_data,
    uint32_t data_size, FileDirection dir)
{
    int64_t file_detection_depth = DCE2_ScSmbFileDepth((dce2SmbProtoConf*)ssd->sd.config);
    int64_t detection_size = 0;

    if (file_detection_depth == 0)
        detection_size = data_size;
    else if ( ssd->ftracker.tracker.file.file_offset < (uint64_t)file_detection_depth)
    {
        if ( file_detection_depth - ssd->ftracker.tracker.file.file_offset < data_size )
            detection_size = file_detection_depth - ssd->ftracker.tracker.file.file_offset;
        else
            detection_size = data_size;
    }

    if (detection_size)
    {
        set_file_data(file_data,
            (detection_size > UINT16_MAX) ? UINT16_MAX : (uint16_t)detection_size);

        DCE2_FileDetect();
    }

    assert(ssd->sd.wire_pkt);
    FileFlows* file_flows = FileFlows::get_file_flows((ssd->sd.wire_pkt)->flow);
    if(!file_flows)
        return;

    file_flows->file_process(ssd->ftracker.fid_v2, file_data, data_size,
        ssd->ftracker.tracker.file.file_offset, dir);
}

/********************************************************************
 *
 * Process tree connect command
 * Share type is defined here
 *
 ********************************************************************/
static void DCE2_Smb2TreeConnect(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end)
{
    /* Using structure size to decide whether it is response or request*/
    uint16_t structure_size;
    const Smb2TreeConnectResponseHdr* smb_tree_connect_hdr = (const Smb2TreeConnectResponseHdr*)smb_data;

    if ((const uint8_t*)smb_tree_connect_hdr + SMB2_TREE_CONNECT_RESPONSE_STRUC_SIZE > end)
        return;

    structure_size = alignedNtohs(&(smb_tree_connect_hdr->structure_size));

    if (structure_size == SMB2_TREE_CONNECT_RESPONSE_STRUC_SIZE)
    {
        DCE2_Smb2InsertTid(ssd, Smb2Tid(smb_hdr), smb_tree_connect_hdr->share_type);
    }
}

/********************************************************************
 *
 * Process tree connect command
 * Share type is defined here
 *
 ********************************************************************/
static void DCE2_Smb2TreeDisconnect(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end)
{
    /* Using structure size to decide whether it is response or request*/
    uint16_t structure_size;
    const Smb2TreeDisConnectHdr* smb_tree_disconnect_hdr = (const Smb2TreeDisConnectHdr*)smb_data;

    if ((const uint8_t*)smb_tree_disconnect_hdr + SMB2_TREE_DISCONNECT_STRUC_SIZE > end)
        return;

    structure_size = alignedNtohs(&(smb_tree_disconnect_hdr->structure_size));

    if (structure_size == SMB2_TREE_DISCONNECT_STRUC_SIZE)
    {
        DCE2_Smb2RemoveTid(ssd, Smb2Tid(smb_hdr));
    }
}

/********************************************************************
 *
 * Process create request, first command for a file processing
 * Update file name
 *
 ********************************************************************/
static void DCE2_Smb2CreateRequest(DCE2_SmbSsnData* ssd, const Smb2Hdr*,
    const Smb2CreateRequestHdr* smb_create_hdr,const uint8_t* end)
{
    uint16_t name_offset = alignedNtohs(&(smb_create_hdr->name_offset));
 
    DCE2_Smb2InitFileTracker(&ssd->ftracker, false, 0);

    if (name_offset > SMB2_HEADER_LENGTH)
    {
        uint16_t size;
        const uint8_t* file_data =  (const uint8_t*)smb_create_hdr + smb_create_hdr->name_offset -
            SMB2_HEADER_LENGTH;
        if (file_data >= end)
            return;
        size = alignedNtohs(&(smb_create_hdr->name_length));
        if (!size || (file_data + size > end))
            return;
        if (ssd->ftracker.file_name)
        {
            snort_free((void*)ssd->ftracker.file_name);
            ssd->ftracker.file_name_size = 0;
        }
        ssd->ftracker.file_name = DCE2_SmbGetFileName(file_data, size, true,
            &ssd->ftracker.file_name_size);
    }
}

/********************************************************************
 *
 * Process create response, need to update file id
 * For downloading, file size is decided here
 *
 ********************************************************************/
static void DCE2_Smb2CreateResponse(DCE2_SmbSsnData* ssd, const Smb2Hdr*,
    const Smb2CreateResponseHdr* smb_create_hdr, const uint8_t*)
{
    uint64_t fileId_persistent;
    uint64_t file_size = UNKNOWN_FILE_SIZE;
  

    fileId_persistent = alignedNtohq((const uint64_t*)(&(smb_create_hdr->fileId_persistent)));
    ssd->ftracker.fid_v2 = fileId_persistent;
    if (smb_create_hdr->end_of_file)
    {
        file_size = alignedNtohq((const uint64_t*)(&(smb_create_hdr->end_of_file)));      
        ssd->ftracker.tracker.file.file_size = file_size;
    }

    if (ssd->ftracker.file_name && ssd->ftracker.file_name_size)
    {
        FileContext* file = get_file_context(ssd, ssd->ftracker.fid_v2);
        if (file)
        {
            file->set_file_size(file_size);
            file->set_file_name(ssd->ftracker.file_name, ssd->ftracker.file_name_size);
        }
    }
    DCE2_Smb2ResetFileName(&(ssd->ftracker));
}

/********************************************************************
 *
 * Process create command
 *
 ********************************************************************/
static void DCE2_Smb2Create(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end)
{
    uint16_t structure_size;
    const Smb2CreateRequestHdr* smb_create_hdr = (const Smb2CreateRequestHdr*)smb_data;

    structure_size = alignedNtohs(&(smb_create_hdr->structure_size));

    /* Using structure size to decide whether it is response or request */
    if (structure_size == SMB2_CREATE_REQUEST_STRUC_SIZE)
    {
        if ((const uint8_t*)smb_create_hdr + SMB2_CREATE_REQUEST_STRUC_SIZE - 1 > end)
            return;
        DCE2_Smb2CreateRequest(ssd, smb_hdr, smb_create_hdr, end);
    }
    else if (structure_size == SMB2_CREATE_RESPONSE_STRUC_SIZE)
    {
        if ((const uint8_t*)smb_create_hdr + SMB2_CREATE_RESPONSE_STRUC_SIZE -1 > end)
            return;
        DCE2_Smb2CreateResponse(ssd, smb_hdr, (const Smb2CreateResponseHdr*)smb_create_hdr, end);
    }
    else if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE)
    {
        const Smb2ErrorResponseHdr* smb_err_response_hdr = (const Smb2ErrorResponseHdr*)smb_data;
        if ((const uint8_t*)smb_create_hdr + SMB2_ERROR_RESPONSE_STRUC_SIZE - 1 > end)
            return;
        /* client will ignore when byte count is 0 */
        if (smb_err_response_hdr->byte_count)
        {
            /*Response error, clean up request state*/
            DCE2_Smb2FreeFileName(&(ssd->ftracker));
        }
    }
}

/********************************************************************
 *
 * Process close command
 * For some upload, file_size is decided here.
 *
 ********************************************************************/
static void DCE2_Smb2CloseCmd(DCE2_SmbSsnData* ssd, const Smb2Hdr*,
    const uint8_t* smb_data, const uint8_t* end)
{
    /* Using structure size to decide whether it is response or request*/
    uint16_t structure_size;
    const Smb2CloseRequestHdr* smb_close_hdr = (const Smb2CloseRequestHdr*)smb_data;

    if ((const uint8_t*)smb_close_hdr + SMB2_CLOSE_REQUEST_STRUC_SIZE > end)
        return;

    structure_size = alignedNtohs(&(smb_close_hdr->structure_size));

    if ((structure_size == SMB2_CLOSE_REQUEST_STRUC_SIZE) &&
        !ssd->ftracker.tracker.file.file_size
        && ssd->ftracker.tracker.file.file_offset)
    {
        FileDirection dir = DCE2_SsnFromClient(ssd->sd.wire_pkt) ? FILE_UPLOAD : FILE_DOWNLOAD;
        ssd->ftracker.tracker.file.file_size = ssd->ftracker.tracker.file.file_offset;
        uint64_t fileId_persistent = alignedNtohq(&(smb_close_hdr->fileId_persistent));
        FileContext* file = get_file_context(ssd, fileId_persistent);
        if (file)
        {
            file->set_file_size(ssd->ftracker.tracker.file.file_size);
        }

        DCE2_Smb2ProcessFileData(ssd, nullptr, 0, dir);
    }
}

/********************************************************************
 *
 * Process set info command
 * For upload, file_size is decided here.
 *
 ********************************************************************/
static void DCE2_Smb2SetInfo(DCE2_SmbSsnData* ssd, const Smb2Hdr*,
    const uint8_t* smb_data, const uint8_t* end)
{
    /* Using structure size to decide whether it is response or request*/
    uint16_t structure_size;
    const Smb2SetInfoRequestHdr* smb_set_info_hdr = (const Smb2SetInfoRequestHdr*)smb_data;

    if ((const uint8_t*)smb_set_info_hdr + SMB2_SET_INFO_REQUEST_STRUC_SIZE > end)
        return;

    structure_size = alignedNtohs(&(smb_set_info_hdr->structure_size));

    if (structure_size == SMB2_SET_INFO_REQUEST_STRUC_SIZE)
    {
        const uint8_t* file_data =  (const uint8_t*)smb_set_info_hdr + SMB2_SET_INFO_REQUEST_STRUC_SIZE - 1;
        if (smb_set_info_hdr->file_info_class == SMB2_FILE_ENDOFFILE_INFO)
        {
            uint64_t file_size = alignedNtohq((const uint64_t*)file_data);
            ssd->ftracker.tracker.file.file_size = file_size;
            uint64_t fileId_persistent = alignedNtohq(&(smb_set_info_hdr->fileId_persistent));
            FileContext* file = get_file_context(ssd, fileId_persistent);
            if (file)
            {
                file->set_file_size(ssd->ftracker.tracker.file.file_size);
            }
        }
    }
}

/********************************************************************
 *
 * Process read request
 *
 ********************************************************************/
static void DCE2_Smb2ReadRequest(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    const Smb2ReadRequestHdr* smb_read_hdr, const uint8_t*)
{
    uint64_t message_id, offset;
    uint64_t fileId_persistent;
  
    message_id = alignedNtohq((const uint64_t*)(&(smb_hdr->message_id)));
    offset = alignedNtohq((const uint64_t*)(&(smb_read_hdr->offset)));
    fileId_persistent = alignedNtohq((const uint64_t*)(&(smb_read_hdr->fileId_persistent)));
    DCE2_Smb2StoreRequest(ssd, message_id, offset, fileId_persistent);
    if (fileId_persistent && (ssd->ftracker.fid_v2 != fileId_persistent))
    {
        ssd->ftracker.fid_v2 = fileId_persistent;
    }
    if (ssd->ftracker.tracker.file.file_size && (offset > ssd->ftracker.tracker.file.file_size))
    {
        dce_alert(GID_DCE2, DCE2_SMB_INVALID_FILE_OFFSET, (dce2CommonStats*)&dce2_smb_stats);
    }
}

/********************************************************************
 *
 * Process read response
 *
 ********************************************************************/
static void DCE2_Smb2ReadResponse(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    const Smb2ReadResponseHdr* smb_read_hdr, const uint8_t* end)
{
    const uint8_t* file_data =  (const uint8_t*)smb_read_hdr + SMB2_READ_RESPONSE_STRUC_SIZE - 1;
    int data_size = end - file_data;
    uint32_t total_data_length;
    uint64_t message_id;
    uint16_t data_offset;
    Smb2Request* request;

    message_id = alignedNtohq((const uint64_t*)(&(smb_hdr->message_id)));
    request = DCE2_Smb2GetRequest(ssd, message_id);
    if (!request)
    {
        return;
    }
    data_offset = alignedNtohs((const uint16_t*)(&(smb_read_hdr->data_offset)));
    if (data_offset + (const uint8_t*)smb_hdr > end)
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
    }

    ssd->ftracker.tracker.file.file_offset = request->offset;
    ssd->ftracker.fid_v2 = request->file_id;
    ssd->ftracker.tracker.file.file_direction = DCE2_SMB_FILE_DIRECTION__DOWNLOAD;

    DCE2_Smb2RemoveRequest(ssd, request);

    DCE2_Smb2ProcessFileData(ssd, file_data, data_size, FILE_DOWNLOAD);
    ssd->ftracker.tracker.file.file_offset += data_size;
    total_data_length = alignedNtohl((const uint32_t*)&(smb_read_hdr->length));
    if (total_data_length > (uint32_t)data_size)
        ssd->pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
}

/********************************************************************
 *
 * Process read command
 *
 ********************************************************************/
static void DCE2_Smb2Read(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end)
{
    uint16_t structure_size;
    const Smb2ReadRequestHdr* smb_read_hdr = (const Smb2ReadRequestHdr*)smb_data;
    structure_size = alignedNtohs(&(smb_read_hdr->structure_size));

    /* Using structure size to decide whether it is response or request*/
    if (structure_size == SMB2_READ_REQUEST_STRUC_SIZE)
    {
        if ((const uint8_t*)smb_read_hdr + SMB2_READ_REQUEST_STRUC_SIZE - 1 > end)
            return;
        DCE2_Smb2ReadRequest(ssd, smb_hdr, smb_read_hdr, end);
    }
    else if (structure_size == SMB2_READ_RESPONSE_STRUC_SIZE)
    {
        if ((const uint8_t*)smb_read_hdr + SMB2_READ_RESPONSE_STRUC_SIZE - 1 > end)
            return;
        DCE2_Smb2ReadResponse(ssd, smb_hdr, (const Smb2ReadResponseHdr*)smb_read_hdr, end);
    }
    else
    {
        uint64_t message_id;
        Smb2Request* request;
    
        message_id = alignedNtohq((const uint64_t*)(&(smb_hdr->message_id)));
        request = DCE2_Smb2GetRequest(ssd, message_id);
        if (!request)
        {
            return;
        }
        DCE2_Smb2RemoveRequest(ssd, request);
    }
}

/********************************************************************
 *
 * Process write request
 *
 ********************************************************************/
static void DCE2_Smb2WriteRequest(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    const Smb2WriteRequestHdr* smb_write_hdr, const uint8_t* end)
{
    const uint8_t* file_data =  (const uint8_t*)smb_write_hdr + SMB2_WRITE_REQUEST_STRUC_SIZE - 1;
    int data_size = end - file_data;
    uint64_t fileId_persistent, offset;
    uint16_t data_offset;
    uint32_t total_data_length;

    fileId_persistent = alignedNtohq((const uint64_t*)(&(smb_write_hdr->fileId_persistent)));
    if (fileId_persistent && (ssd->ftracker.fid_v2 != fileId_persistent))
    {
        ssd->ftracker.fid_v2 = fileId_persistent;
    }
    data_offset = alignedNtohs((const uint16_t*)(&(smb_write_hdr->data_offset)));
    if (data_offset + (const uint8_t*)smb_hdr > end)
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats);
    }

    offset = alignedNtohq((const uint64_t*)(&(smb_write_hdr->offset)));
    if (ssd->ftracker.tracker.file.file_size && (offset > ssd->ftracker.tracker.file.file_size))
    {
        dce_alert(GID_DCE2, DCE2_SMB_INVALID_FILE_OFFSET, (dce2CommonStats*)&dce2_smb_stats);
    }
    ssd->ftracker.tracker.file.file_direction = DCE2_SMB_FILE_DIRECTION__UPLOAD;
    ssd->ftracker.tracker.file.file_offset = offset;

    DCE2_Smb2ProcessFileData(ssd, file_data, data_size, FILE_UPLOAD);
    ssd->ftracker.tracker.file.file_offset += data_size;
    total_data_length = alignedNtohl((const uint32_t*)&(smb_write_hdr->length));
    if (total_data_length > (uint32_t)data_size)
        ssd->pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
}


/********************************************************************
 *
 * Process write command
 *
 ********************************************************************/
static void DCE2_Smb2Write(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end)
{
    uint16_t structure_size;
    const Smb2WriteRequestHdr* smb_write_hdr = (const Smb2WriteRequestHdr*)smb_data;
    structure_size = alignedNtohs(&(smb_write_hdr->structure_size));

    /* Using structure size to decide whether it is response or request*/
    if (structure_size == SMB2_WRITE_REQUEST_STRUC_SIZE)
    {
        if ((const uint8_t*)smb_write_hdr + SMB2_WRITE_REQUEST_STRUC_SIZE - 1 > end)
            return;
        DCE2_Smb2WriteRequest(ssd, smb_hdr, smb_write_hdr, end);
    }
}

/********************************************************************
 *
 * Purpose:
 *  Process SMB2 commands.
 *
 * Arguments:
 *  DCE2_SmbSsnData * - the session data structure.
 *  const Smb2Hdr *  - pointer to the SMB2 header.
 *  const uint8_t *  - pointer to end of payload.
 * Returns: None
 *
 ********************************************************************/
static void DCE2_Smb2Inspect(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr, const uint8_t* end)
{
    const uint8_t* smb_data = (const uint8_t*)smb_hdr + SMB2_HEADER_LENGTH;
    uint16_t command = alignedNtohs(&(smb_hdr->command));
    switch (command)
    {
    case SMB2_COM_CREATE:
        dce2_smb_stats.smb2_create++;
        if (DCE2_Smb2FindTid(ssd, smb_hdr) != DCE2_RET__SUCCESS)
            return;
        DCE2_Smb2Create(ssd, smb_hdr, smb_data, end);
        break;
    case SMB2_COM_READ:
        dce2_smb_stats.smb2_read++;
        if (DCE2_Smb2FindTid(ssd, smb_hdr) != DCE2_RET__SUCCESS)
            return;
        DCE2_Smb2Read(ssd, smb_hdr, smb_data, end);
        break;
    case SMB2_COM_WRITE:
        dce2_smb_stats.smb2_write++;
        if (DCE2_Smb2FindTid(ssd, smb_hdr) != DCE2_RET__SUCCESS)
            return;
        DCE2_Smb2Write(ssd, smb_hdr, smb_data, end);
        break;
    case SMB2_COM_SET_INFO:
        dce2_smb_stats.smb2_set_info++;
        if (DCE2_Smb2FindTid(ssd, smb_hdr) != DCE2_RET__SUCCESS)
            return;
        DCE2_Smb2SetInfo(ssd, smb_hdr, smb_data, end);
        break;
    case SMB2_COM_CLOSE:
        dce2_smb_stats.smb2_close++;
        if (DCE2_Smb2FindTid(ssd, smb_hdr) != DCE2_RET__SUCCESS)
            return;
        DCE2_Smb2CloseCmd(ssd, smb_hdr, smb_data, end);
        break;
    case SMB2_COM_TREE_CONNECT:
        dce2_smb_stats.smb2_tree_connect++;
        DCE2_Smb2TreeConnect(ssd, smb_hdr, smb_data, end);
        break;
    case SMB2_COM_TREE_DISCONNECT:
        dce2_smb_stats.smb2_tree_disconnect++;
        DCE2_Smb2TreeDisconnect(ssd, smb_hdr, smb_data, end);
        break;
    default:
        break;
    }
}

// This is the main entry point for SMB2 processing.
void DCE2_Smb2Process(DCE2_SmbSsnData* ssd)
{
    Packet* p = ssd->sd.wire_pkt;
    const uint8_t* data_ptr = p->data;
    uint16_t data_len = p->dsize;

    /*Check header length*/
    if (data_len < sizeof(NbssHdr) + SMB2_HEADER_LENGTH)
        return;

    if (!ssd->ftracker.is_smb2)
    {
        DCE2_Smb2InitFileTracker(&(ssd->ftracker), false, 0);
    }

    /* Process the header */
    if (p->is_pdu_start())
    {
        uint32_t next_command_offset;
        const Smb2Hdr* smb_hdr = (const Smb2Hdr*)(data_ptr + sizeof(NbssHdr));
        next_command_offset = alignedNtohl(&(smb_hdr->next_command));
        if (next_command_offset + sizeof(NbssHdr) > p->dsize)
        {
            dce_alert(GID_DCE2, DCE2_SMB_BAD_NEXT_COMMAND_OFFSET,
                (dce2CommonStats*)&dce2_smb_stats);
        }
        DCE2_Smb2Inspect(ssd, smb_hdr, data_ptr +  data_len);
    }
    else if (ssd->pdu_state == DCE2_SMB_PDU_STATE__RAW_DATA)
    {
        /*continue processing raw data*/
        FileDirection dir = DCE2_SsnFromClient(ssd->sd.wire_pkt) ? FILE_UPLOAD : FILE_DOWNLOAD;
        DCE2_Smb2ProcessFileData(ssd, data_ptr, data_len, dir);
        ssd->ftracker.tracker.file.file_offset += data_len;
    }
}

/* Initialize smb2 file tracker */
DCE2_Ret DCE2_Smb2InitFileTracker(DCE2_SmbFileTracker* ftracker,
    const bool is_ipc, const uint64_t fid)
{
    if (ftracker == nullptr)
        return DCE2_RET__ERROR;

    DCE2_Smb2FreeFileName(ftracker);
    ftracker->fid_v2 = fid;
    ftracker->is_ipc = is_ipc;
    ftracker->is_smb2 = true;

    ftracker->ff_file_size = 0;
    ftracker->ff_file_offset = 0;
    ftracker->ff_file_direction = DCE2_SMB_FILE_DIRECTION__UNKNOWN;

    return DCE2_RET__SUCCESS;
}

/* Check whether the packet is smb2 */
DCE2_SmbVersion DCE2_Smb2Version(const Packet* p)
{
    /* Only check reassembled SMB2 packet*/
    if ( p->has_paf_payload() and
        (p->dsize > sizeof(NbssHdr) + 4) ) // DCE2_SMB_ID is u32
    {
        const Smb2Hdr* smb_hdr = (const Smb2Hdr*)(p->data + sizeof(NbssHdr));
        uint32_t smb_version_id = SmbId((const SmbNtHdr*)smb_hdr);

        if (smb_version_id == DCE2_SMB_ID)
            return DCE2_SMB_VERISON_1;

        else if (smb_version_id == DCE2_SMB2_ID)
            return DCE2_SMB_VERISON_2;
    }

    return DCE2_SMB_VERISON_NULL;
}

void DCE2_Smb2CleanRequests(Smb2Request* requests)
{
    Smb2Request* request = requests;
    while (request)
    {
        Smb2Request* next;
        next = request->next;
        snort_free((void*)request);
        request = next;
    }
}

