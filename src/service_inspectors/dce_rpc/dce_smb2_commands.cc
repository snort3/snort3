//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb2_commands.cc author Bhargava Jandhyala <bjandhya@cisco.com>
// based on work by Todd Wease

// Smb commands processing

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb2_commands.h"

#include "file_api/file_lib.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "packet_io/active.h"
#include "protocols/packet.h"

using namespace snort;
#define UNKNOWN_FILE_SIZE (~0)

#define SMB2_CHECK_HDR_ERROR(smb_data, end, strcuture_size, counter, cmd) \
    { \
        if ((smb_data + (strcuture_size)) > end) \
        { \
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, DetectionEngine::get_current_packet(), \
    "%s : smb truncated data detected\n", smb2_command_string[cmd]); \
            counter++; \
            return; \
        } \
    }

inline FileFlows* DCE2_Smb2GetFileFlow(DCE2_Smb2FileTracker* ftracker)
{
    Packet* p = DetectionEngine::get_current_packet();
    if (p->flow != ftracker->parent_flow)
        ftracker->multi_channel_file = true;
    if (!ftracker->parent_flow)
    {
        //Parent flow is deleted, upgrade the current flow as parent flow
        ftracker->parent_flow = p->flow;
        dce2_smb_stats.v2_updated_file_flows++;
    }
    return FileFlows::get_file_flows(ftracker->parent_flow);
}

inline FileFlows* DCE2_Smb2GetCurrentFileFlow()
{
    Packet* p = DetectionEngine::get_current_packet();
    return FileFlows::get_file_flows(p->flow);
}

static inline FileContext* DCE2_Smb2GetFileContext(DCE2_Smb2SsnData*, DCE2_Smb2FileTracker* ftracker, bool
    to_create = false)
{
    FileFlows* file_flows = DCE2_Smb2GetFileFlow(ftracker);
    if ( !file_flows )
    {
        dce2_smb_stats.v2_inv_file_ctx_err++;
        return nullptr;
    }
    bool is_new_context = false;
    if (ftracker->file_name_hash)
            return file_flows->get_file_context(ftracker->file_name_hash, to_create, is_new_context, ftracker->file_id);
    return file_flows->get_file_context(ftracker->file_id, to_create, is_new_context);
}

inline void DCE2_Smb2UpdateMaxOffset(DCE2_Smb2FileTracker* ftracker, uint64_t offset)
{
    if (ftracker->max_offset < offset)
        ftracker->max_offset = offset;
}

bool DCE2_Smb2ProcessFileData(DCE2_Smb2SsnData* ssd, const uint8_t* file_data,
    uint32_t data_size)
{
    if (ssd->ftracker_tcp->co_tracker)
    {
        DCE2_CoProcess(&ssd->sd, ssd->ftracker_tcp->co_tracker,
            file_data, data_size);
        return true;
    }
    int64_t file_detection_depth = DCE2_ScSmbFileDepth((dce2SmbProtoConf*)ssd->sd.config);
    int64_t detection_size = 0;

    if (file_detection_depth == 0)
        detection_size = data_size;
    else if ( ssd->ftracker_local->file_offset < (uint64_t)file_detection_depth)
    {
        if ( file_detection_depth - ssd->ftracker_local->file_offset < data_size )
            detection_size = file_detection_depth - ssd->ftracker_local->file_offset;
        else
            detection_size = data_size;
    }

    if (detection_size)
    {
        set_file_data(file_data,
            (detection_size > UINT16_MAX) ? UINT16_MAX : (uint16_t)detection_size);

        DCE2_FileDetect();
    }
    Packet* p = DetectionEngine::get_current_packet();
    FileDirection dir = ssd->ftracker_tcp->upload ? FILE_UPLOAD : FILE_DOWNLOAD;

    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
        "file_process fid 0x%" PRIx64 " data_size %" PRIu32 " offset %"
        PRIu64  "\n", ssd->ftracker_tcp->file_id, data_size,
        ssd->ftracker_local->file_offset);

    if (!ssd->ftracker_tcp->ignore)
    {
        // Do not process data beyond file size if file size is known.
        if (ssd->ftracker_tcp->file_size)
        {
            if (ssd->ftracker_local->file_offset > ssd->ftracker_tcp->file_size)
            {
                SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID,
                    TRACE_ERROR_LEVEL, DetectionEngine::get_current_packet(),
                    "file_process: bad offset\n");
                return false;
            }
            else if (ssd->ftracker_local->file_offset + data_size > ssd->ftracker_tcp->file_size)
            {
                //Trim padded data
                data_size = ssd->ftracker_tcp->file_size - ssd->ftracker_local->file_offset;
            }
        }

        FileFlows* file_flows = DCE2_Smb2GetFileFlow(ssd->ftracker_tcp);
        if (!file_flows)
        {
            dce2_smb_stats.v2_extra_file_data_err++;
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                p, "No file flow \n");

            DCE2_Smb2TreeTracker* ttr = ssd->ftracker_tcp->ttr;
            ttr->removeFtracker(ssd->ftracker_tcp->file_id);
            return false;
        }

        // A hack to force to create a file flow for this connection
        // Required for file type detection based on IPS rules.
        if (ssd->flow != ssd->ftracker_tcp->parent_flow)
            DCE2_Smb2GetCurrentFileFlow();

        bool continue_processing = true;
        if (ssd->ftracker_tcp->file_name_hash)
            continue_processing = file_flows->file_process(p, ssd->ftracker_tcp->file_name_hash, file_data, data_size,
                ssd->ftracker_local->file_offset, dir, ssd->ftracker_tcp->file_id);
        else
            continue_processing = file_flows->file_process(p, ssd->ftracker_tcp->file_id, file_data, data_size,
                ssd->ftracker_local->file_offset, dir);
        if (!continue_processing)
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
                p, "file_process completed\n");
        }
    }
    ssd->ftracker_local->file_offset += data_size;
    return true;
}

//-------------------------------------------------------------------------
// Process session setup response to find/create session tracker
//-------------------------------------------------------------------------
void DCE2_Smb2Setup(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr, const uint64_t sid,
    const uint8_t* smb_data, const uint8_t* end)
{
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        if ((alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND) &&
            (alignedNtohl(&(smb_hdr->status)) == SMB2_STATUS_PENDING))
            return;

        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
            DetectionEngine::get_current_packet(), "%s_RESP: error\n",
            smb2_command_string[SMB2_COM_SESSION_SETUP]);
        dce2_smb_stats.v2_setup_err_resp++;
    }
    else if (structure_size == SMB2_SETUP_RESPONSE_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_SETUP_RESPONSE_STRUC_SIZE - 1,
            dce2_smb_stats.v2_setup_resp_hdr_err, SMB2_COM_SESSION_SETUP)
        DCE2_Smb2FindElseCreateSid(ssd, sid);
    }
    else if (structure_size != SMB2_SETUP_REQUEST_STRUC_SIZE)
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s: invalid struct size\n",
            smb2_command_string[SMB2_COM_SESSION_SETUP]);
        dce2_smb_stats.v2_setup_inv_str_sz++;
    }
}

//-------------------------------------------------------------------------
// Process tree connect response to find/create tree tracker
//-------------------------------------------------------------------------
void DCE2_Smb2TreeConnect(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2SessionTracker* str, uint32_t tid)
{
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        if ((alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND) &&
            (alignedNtohl(&(smb_hdr->status)) == SMB2_STATUS_PENDING))
            return;

        dce2_smb_stats.v2_tree_cnct_err_resp++;
    }
    else if (structure_size == SMB2_TREE_CONNECT_RESPONSE_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_TREE_CONNECT_RESPONSE_STRUC_SIZE,
            dce2_smb_stats.v2_tree_cnct_resp_hdr_err, SMB2_COM_TREE_CONNECT)

        if (!DCE2_Smb2InsertTid(ssd, tid,
            ((const Smb2TreeConnectResponseHdr*)smb_data)->share_type, str))
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
                DetectionEngine::get_current_packet(), "%s: ignored %d\n",
                smb2_command_string[SMB2_COM_TREE_CONNECT], tid);
            dce2_smb_stats.v2_tree_cnct_ignored++;
        }
    }
    else if (structure_size != SMB2_TREE_CONNECT_REQUEST_STRUC_SIZE)
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s: invalid struct size\n",
            smb2_command_string[SMB2_COM_TREE_CONNECT]);
        dce2_smb_stats.v2_tree_cnct_inv_str_sz++;
    }
}

//-------------------------------------------------------------------------
// Process tree disconnect request to cleanup tree tracker and its
// corresponding request trackers and file trackers
//-------------------------------------------------------------------------
void DCE2_Smb2TreeDisconnect(DCE2_Smb2SsnData*, const uint8_t* smb_data,
    const uint8_t* end)
{
    if (SMB2_TREE_DISCONNECT_REQUEST_STRUC_SIZE == alignedNtohs((const uint16_t*)smb_data))
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_TREE_DISCONNECT_REQUEST_STRUC_SIZE,
            dce2_smb_stats.v2_tree_discn_req_hdr_err, SMB2_COM_TREE_DISCONNECT)
    }
    else
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s: invalid struct size\n",
            smb2_command_string[SMB2_COM_TREE_DISCONNECT]);
        dce2_smb_stats.v2_tree_discn_inv_str_sz++;
    }
}

bool DCE2_IsSmb2DurableReconnect(const Smb2CreateRequestHdr* smb_create_hdr, const uint8_t* end, uint64_t& file_id)
{
    const uint8_t* data = (const uint8_t*)smb_create_hdr + alignedNtohl(&smb_create_hdr->create_contexts_offset) -
        SMB2_HEADER_LENGTH;
    uint32_t remaining = alignedNtohl(&smb_create_hdr->create_contexts_length);

    while (remaining > sizeof(Smb2CreateRequestHdr) && data < end)
    {
        const Smb2CreateContextHdr* context = (const Smb2CreateContextHdr*)data;
        uint32_t next = alignedNtohl(&context->next);
        uint16_t name_offset = alignedNtohs(&context->name_offset);
        uint16_t name_length = alignedNtohs(&context->name_length);
        uint16_t data_offset = alignedNtohs(&context->data_offset);
        uint32_t data_length =  alignedNtohl(&context->data_length);

        /* Check for general error condition */
        if ((next & 0x7) != 0 or
            next > remaining or
            name_offset != 16 or
            name_length < 4 or
            name_offset + name_length > remaining or
            (data_offset & 0x7) != 0 or
            (data_offset and (data_offset < name_offset + name_length)) or
            (data_offset > remaining) or
            (data_offset + data_length > remaining))
        {
            return false;
        }

        if ((strncmp((const char*)context+name_offset, SMB2_CREATE_DURABLE_RECONNECT_V2, name_length) == 0) or
            (strncmp((const char*)context+name_offset, SMB2_CREATE_DURABLE_RECONNECT, name_length) == 0))
        {
            file_id = alignedNtohq((const uint64_t*)(((const uint8_t*)context) + data_offset));
            return true;
        }

        if (!next)
            break;

        data += next;
        remaining -= next;
    }
    return false;
}

//-------------------------------------------------------------------------
// Process create request to get file name and save it in request tracker
//-------------------------------------------------------------------------
static void DCE2_Smb2CreateRequest(DCE2_Smb2SsnData* ssd,
    const Smb2CreateRequestHdr* smb_create_hdr, const uint8_t* end,
    DCE2_Smb2SessionTracker* str, DCE2_Smb2TreeTracker* ttr, uint64_t mid)
{
    uint16_t name_offset = alignedNtohs(&(smb_create_hdr->name_offset));

    if (name_offset > SMB2_HEADER_LENGTH)
    {
        uint16_t name_len  = 0;

        const uint8_t* file_data =  (const uint8_t*)smb_create_hdr + smb_create_hdr->name_offset -
            SMB2_HEADER_LENGTH;
        if (file_data >= end)
        {
            dce2_smb_stats.v2_crt_inv_file_data++;
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                DetectionEngine::get_current_packet(), "%s_REQ: invalid "
                "file data seen\n", smb2_command_string[SMB2_COM_CREATE]);
            return;
        }

        uint16_t size = alignedNtohs(&(smb_create_hdr->name_length));
        if (!size or (file_data + size > end))
        {
            dce2_smb_stats.v2_crt_inv_file_data++;
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                DetectionEngine::get_current_packet(),
                "%s_REQ: invalid file data seen with size %" PRIu16 "\n",
                smb2_command_string[SMB2_COM_CREATE], size);
            return;
        }

        if (ssd->max_outstanding_requests > ssd->getTotalRequestsPending())
        {
            char* file_name = DCE2_SmbGetFileName(file_data, size, true, &name_len);
            auto rtracker = new DCE2_Smb2RequestTracker(file_name, name_len);
            rtracker->set_session_id(str->session_id);
            rtracker->set_tree_id(ttr->get_tid());
            ssd->insertRtracker(mid, rtracker);
            uint64_t file_id = 0;
            if (DCE2_IsSmb2DurableReconnect(smb_create_hdr, end, file_id))
            {
                //Create a ftracker here to handle compound write case
                auto ftracker = new DCE2_Smb2FileTracker(file_id, ttr, str,
                    DetectionEngine::get_current_packet()->flow);
                if (file_name and name_len)
                {
                    ftracker->file_name_hash = str_to_hash(
                        (const uint8_t*)file_name, name_len);
                }
                else
                {
                    ftracker->ignore = true;
                    dce2_smb_stats.v2_ignored_file_processing++;
                }
                ttr->insertFtracker(file_id, ftracker);
                if (SMB2_SHARE_TYPE_DISK == ttr->get_share_type())
                {
                    FileContext* file = DCE2_Smb2GetFileContext(ssd, ftracker, true);
                    if (file)
                        file->set_file_name(file_name, name_len);
                    else
                    {
                        //Ignore the file processing.
                        ftracker->ignore = true;
                        dce2_smb_stats.v2_ignored_file_processing++;
                    }
                }
                else
                {
                    ftracker->co_tracker = (DCE2_CoTracker*)snort_calloc(sizeof(DCE2_CoTracker));
                    DCE2_CoInitTracker(ftracker->co_tracker);
                }
            }
        }
        else
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                DetectionEngine::get_current_packet(), "%s_REQ: max req exceeded\n",
                smb2_command_string[SMB2_COM_CREATE]);
            dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats,
                ssd->sd);
        }
    }
    else
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
            DetectionEngine::get_current_packet(), "%s_REQ: name_offset %"
            PRIu16 "\n", smb2_command_string[SMB2_COM_CREATE], name_offset);
        dce2_smb_stats.v2_crt_req_hdr_err++;
    }
}

//-------------------------------------------------------------------------
// Process create response to create file tracker with file id and file
// size. Request tracker is cleaned after updating file name in file tracker
//-------------------------------------------------------------------------
static void DCE2_Smb2CreateResponse(DCE2_Smb2SsnData* ssd,
    const Smb2CreateResponseHdr* smb_create_hdr, DCE2_Smb2RequestTracker* rtracker,
    DCE2_Smb2TreeTracker* ttr, DCE2_Smb2SessionTracker* str, uint64_t fileId_persistent)
{
    uint64_t file_size = 0;

    if (smb_create_hdr->end_of_file)
    {
        file_size = alignedNtohq((const uint64_t*)(&(smb_create_hdr->end_of_file)));
    }

    DCE2_Smb2FileTracker* ftracker = ttr->findFtracker(fileId_persistent);
    if (!ftracker)
    {
        ftracker = new DCE2_Smb2FileTracker(fileId_persistent, ttr, str, DetectionEngine::get_current_packet()->flow);
        ttr->insertFtracker(fileId_persistent, ftracker);
    }

    ftracker->file_size = file_size;
    if (SMB2_SHARE_TYPE_DISK == ttr->get_share_type())
    {
        if (rtracker->fname and rtracker->fname_len)
        {
            if (!ftracker->file_name_hash)
                ftracker->file_name_hash = str_to_hash(
                    (const uint8_t*)rtracker->fname, rtracker->fname_len);

            FileContext* file = DCE2_Smb2GetFileContext(ssd, ftracker, true);

            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
                DetectionEngine::get_current_packet(), "%s_RESP: file size %"
                PRIu64 " fid 0x%" PRIx64 " file_name_hash %" PRIu64 " file context %s\n",
                smb2_command_string[SMB2_COM_CREATE], file_size,
                fileId_persistent, ftracker->file_name_hash, (file ? "found" : "not found"));

            if (file)
            {
                if (file->verdict == FILE_VERDICT_UNKNOWN)
                {
                    file->set_file_size(!file_size ? UNKNOWN_FILE_SIZE : file_size);
                    file->set_file_name(rtracker->fname, rtracker->fname_len);
                }
            }
            else
            {
                // could not create file context, hence this file transfer
                // cant be inspected
                ftracker->ignore = true;
                dce2_smb_stats.v2_ignored_file_processing++;
            }
        }
        else
        {
            ftracker->ignore = true; // file can not be inspected as file name is not present
            dce2_smb_stats.v2_ignored_file_processing++;
        }
    }
    else
    {
        ftracker->co_tracker = (DCE2_CoTracker*)snort_calloc(sizeof(DCE2_CoTracker));
        DCE2_CoInitTracker(ftracker->co_tracker);
    }
}

//-------------------------------------------------------------------------
// Process create request to handle mid stream sessions by adding tree
// tracker if not already present. Process create response for only disk
// share type.
//-------------------------------------------------------------------------
void DCE2_Smb2Create(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end, uint64_t mid, uint64_t sid, uint32_t tid)
{
    DCE2_Smb2SessionTracker* str = DCE2_Smb2FindElseCreateSid(ssd, sid);
    DCE2_Smb2TreeTracker* ttr = nullptr;
    if (tid)
        ttr = str->findTtracker(tid);
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        if ((alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND) &&
            (alignedNtohl(&(smb_hdr->status)) == SMB2_STATUS_PENDING))
            return;

        ssd->removeRtracker(mid);

        dce2_smb_stats.v2_crt_err_resp++;
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s_RESP: error\n",
            smb2_command_string[SMB2_COM_CREATE]);
    }
    // Using structure size to decide whether it is response or request
    else if (structure_size == SMB2_CREATE_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_CREATE_REQUEST_STRUC_SIZE - 1,
            dce2_smb_stats.v2_crt_req_hdr_err, SMB2_COM_CREATE)

        if (!ttr)
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
                DetectionEngine::get_current_packet(),
                "%s_REQ: mid stream session detected\n",
                smb2_command_string[SMB2_COM_CREATE]);
            ttr = DCE2_Smb2InsertTid(ssd, tid, SMB2_SHARE_TYPE_DISK, str);
            if (!ttr)
            {
                SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                    DetectionEngine::get_current_packet(),
                    "%s_REQ: insert tree tracker failed\n",
                    smb2_command_string[SMB2_COM_CREATE]);
                return;
            }
        }
        else if (SMB2_SHARE_TYPE_DISK != ttr->get_share_type())
        {
            dce2_smb_stats.v2_crt_req_ipc++;
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                "%s_REQ: processed for ipc share\n",
                smb2_command_string[SMB2_COM_CREATE]);
        }
        DCE2_Smb2CreateRequest(ssd, (const Smb2CreateRequestHdr*)smb_data, end, str, ttr, mid);
    }
    else if (structure_size == SMB2_CREATE_RESPONSE_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_CREATE_RESPONSE_STRUC_SIZE - 1,
            dce2_smb_stats.v2_crt_resp_hdr_err, SMB2_COM_CREATE)
        if (!ttr)
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                DetectionEngine::get_current_packet(),
                "%s_RESP: tree tracker missing\n",
                smb2_command_string[SMB2_COM_CREATE]);
            dce2_smb_stats.v2_crt_tree_trkr_misng++;
            return;
        }

        DCE2_Smb2RequestTracker* rtr = ssd->findRtracker(mid);
        if (!rtr)
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                DetectionEngine::get_current_packet(),
                "%s_RESP: req tracker missing\n",
                smb2_command_string[SMB2_COM_CREATE]);
            dce2_smb_stats.v2_crt_rtrkr_misng++;
            return;
        }

        uint64_t fileId_persistent = alignedNtohq((const uint64_t*)(
                &(((const Smb2CreateResponseHdr*)smb_data)->fileId_persistent)));

        if (((const Smb2CreateResponseHdr*)smb_data)->file_attributes &
            SMB2_CREATE_RESPONSE_DIRECTORY)
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                DetectionEngine::get_current_packet(),
                "%s_RESP: not processing for directory\n",
                smb2_command_string[SMB2_COM_CREATE]);
            ssd->removeRtracker(mid);
            return;
        }

        DCE2_Smb2CreateResponse(ssd, (const Smb2CreateResponseHdr*)smb_data, rtr, ttr,
            str, fileId_persistent);
        ssd->removeRtracker(mid);
    }
    else
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s: invalid struct size\n",
            smb2_command_string[SMB2_COM_CREATE]);
        dce2_smb_stats.v2_crt_inv_str_sz++;
    }
}

//-------------------------------------------------------------------------
// Process close command request to do file processing for an upload or
// download request with unknown size.
//-------------------------------------------------------------------------
void DCE2_Smb2CloseCmd(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2TreeTracker* ttr,
    DCE2_Smb2SessionTracker* str, uint64_t mid)
{
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        if ((alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND) &&
            (alignedNtohl(&(smb_hdr->status)) == SMB2_STATUS_PENDING))
            return;

        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s_RESP: error\n",
            smb2_command_string[SMB2_COM_CLOSE]);
        dce2_smb_stats.v2_cls_err_resp++;
    }
    // Using structure size to decide whether it is response or request
    else if (structure_size == SMB2_CLOSE_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_CLOSE_REQUEST_STRUC_SIZE,
            dce2_smb_stats.v2_cls_req_hdr_err, SMB2_COM_CLOSE)

        uint64_t fileId_persistent = alignedNtohq(&(((const
            Smb2CloseRequestHdr*)smb_data)->fileId_persistent));
        DCE2_Smb2FileTracker* ftracker =  ttr->findFtracker(fileId_persistent);
        if (!ftracker)
        {
            dce2_smb_stats.v2_cls_req_ftrkr_misng++;
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                DetectionEngine::get_current_packet(), "%s_REQ: ftracker missing 0x%"
                PRIx64 "\n", smb2_command_string[SMB2_COM_CLOSE], fileId_persistent);
            return;
        }

        if (ssd->max_outstanding_requests > ssd->getTotalRequestsPending())
        {
            auto rtracker = new DCE2_Smb2RequestTracker(fileId_persistent);
            rtracker->set_session_id(str->session_id);
            rtracker->set_tree_id(ttr->get_tid());
            ssd->insertRtracker(mid, rtracker);
        }

        if (SMB2_SHARE_TYPE_DISK == ttr->get_share_type() and !ftracker->ignore
            and !ftracker->file_size and ftracker->max_offset)
        {
            ftracker->file_size = ftracker->max_offset;
            FileContext* file = DCE2_Smb2GetFileContext(ssd, ftracker);
            if (file)
            {
                file->set_file_size(ftracker->file_size);
            }

            ssd->ftracker_tcp = ftracker;
            ssd->ftracker_local = std::unique_ptr<DCE2_Smb2LocalFileTracker>(new DCE2_Smb2LocalFileTracker());
            ssd->ftracker_local->file_offset = ftracker->max_offset;
            // In case of upload/download of file with UNKNOWN size, we will not be able to
            // detect malicious file during write request or read response. Once the close
            // command request comes, we will go for file inspection and block an subsequent
            // upload/download request for this file even with unknown size
            DCE2_Smb2ProcessFileData(ssd, nullptr, 0);
        }
    }
    else if (structure_size == SMB2_CLOSE_RESPONSE_STRUC_SIZE)
    {
        DCE2_Smb2RequestTracker* rtr = ssd->findRtracker(mid);
        if (!rtr)
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                DetectionEngine::get_current_packet(),
                "%s_RESP: req tracker missing\n",
                smb2_command_string[SMB2_COM_CLOSE]);
            return;
        }
        auto fileId_persistent = rtr->get_file_id();
        ttr->removeFtracker(fileId_persistent);
        ssd->removeRtracker(mid);
    }
    else
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s: invalid struct size\n",
            smb2_command_string[SMB2_COM_CLOSE]);
        dce2_smb_stats.v2_cls_inv_str_sz++;
        DCE2_Smb2RequestTracker* rtr = ssd->findRtracker(mid);
        if (rtr)
        {
            auto fileId_persistent = rtr->get_file_id();
            ttr->removeFtracker(fileId_persistent);
            ssd->removeRtracker(mid);
        }
    }
}

//-------------------------------------------------------------------------
// Process set info request to update file size
//-------------------------------------------------------------------------
void DCE2_Smb2SetInfo(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2TreeTracker* ttr)
{
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    // Using structure size to decide whether it is response or request
    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        if ((alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND) &&
            (alignedNtohl(&(smb_hdr->status)) == SMB2_STATUS_PENDING))
            return;

        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s: error resp\n",
            smb2_command_string[SMB2_COM_SET_INFO]);
        dce2_smb_stats.v2_stinf_err_resp++;
    }
    else if (structure_size == SMB2_SET_INFO_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_SET_INFO_REQUEST_STRUC_SIZE,
            dce2_smb_stats.v2_stinf_req_hdr_err, SMB2_COM_SET_INFO)

        const Smb2SetInfoRequestHdr* smb_set_info_hdr = (const Smb2SetInfoRequestHdr*)smb_data;
        const uint8_t* file_data = (const uint8_t*)smb_set_info_hdr +
            SMB2_SET_INFO_REQUEST_STRUC_SIZE - 1;

        if (smb_set_info_hdr->file_info_class == SMB2_FILE_ENDOFFILE_INFO or
            smb_set_info_hdr->file_info_class == SMB2_FILE_ALLOCATION_INFO)
        {
            uint64_t file_size = alignedNtohq((const uint64_t*)file_data);
            uint64_t fileId_persistent = alignedNtohq(&(smb_set_info_hdr->fileId_persistent));
            DCE2_Smb2FileTracker* ftracker = ttr->findFtracker(fileId_persistent);
            if (ftracker and !ftracker->ignore)
            {
                if (smb_set_info_hdr->file_info_class == SMB2_FILE_ALLOCATION_INFO)
                {
                    if(ftracker->file_size < file_size)
                    {
                        //Then possible ZIP upload in which case we dont know the actual size of the file
                        ftracker->file_size = 0;
                    }
                }
                else
                    ftracker->file_size = file_size;

                FileContext* file = DCE2_Smb2GetFileContext(ssd, ftracker);
                SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
                    DetectionEngine::get_current_packet(),
                    "%s_REQ: set file size %" PRIu64 " fid 0x%" PRIx64 " file context %s\n",
                    smb2_command_string[SMB2_COM_SET_INFO], file_size, fileId_persistent,
                    file ? "found" : "not found");
                if (file)
                {
                    file->set_file_size(ftracker->file_size);
                }
            }
            else
            {
                dce2_smb_stats.v2_stinf_req_ftrkr_misng++;
                SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                    DetectionEngine::get_current_packet(),
                    "%s_REQ: ftracker missing\n",
                    smb2_command_string[SMB2_COM_SET_INFO]);
            }
        }
        else
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                DetectionEngine::get_current_packet(), "%s_REQ: header error\n",
                smb2_command_string[SMB2_COM_SET_INFO]);

            dce2_smb_stats.v2_stinf_req_hdr_err++;
        }
    }
    else if (structure_size != SMB2_SET_INFO_RESPONSE_STRUC_SIZE)
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s: invalid struct size\n",
            smb2_command_string[SMB2_COM_SET_INFO]);
        dce2_smb_stats.v2_stinf_inv_str_sz++;
    }
}

//-------------------------------------------------------------------------
// Process read request to create read request trackers to get file offset
//-------------------------------------------------------------------------
static void DCE2_Smb2ReadRequest(DCE2_Smb2SsnData* ssd,
    const Smb2ReadRequestHdr* smb_read_hdr, const uint8_t*, DCE2_Smb2SessionTracker* str,
    DCE2_Smb2TreeTracker* ttr, uint64_t message_id)
{
    uint64_t offset = alignedNtohq((const uint64_t*)(&(smb_read_hdr->offset)));
    uint64_t fileId_persistent = alignedNtohq((const
        uint64_t*)(&(smb_read_hdr->fileId_persistent)));

    if (ssd->max_outstanding_requests > ssd->getTotalRequestsPending())
    {
        DCE2_Smb2RequestTracker* readtracker = ssd->findRtracker(message_id);
        if (!readtracker)
            readtracker = new DCE2_Smb2RequestTracker(fileId_persistent, offset);
        readtracker->set_session_id(str->session_id);
        readtracker->set_tree_id(ttr->get_tid());
        readtracker->set_file_id(fileId_persistent);
        ssd->insertRtracker(message_id, readtracker);
    }
    else
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL,
            DetectionEngine::get_current_packet(), "%s_REQ: max req exceeded\n",
            smb2_command_string[SMB2_COM_READ]);
        dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats,
            ssd->sd);
        return;
    }

    DCE2_Smb2FileTracker* ftracker =  ttr->findFtracker(fileId_persistent);
    if (!ftracker and ttr->get_share_type() == SMB2_SHARE_TYPE_DISK)
    {
        //At times read is sent after the close, in case of malware block
        // Create a file tracker here
        ftracker = new DCE2_Smb2FileTracker(fileId_persistent, ttr, str, DetectionEngine::get_current_packet()->flow);
        ttr->insertFtracker(fileId_persistent, ftracker);
    }
    if (!ftracker)
    {
        dce2_smb_stats.v2_read_rtrkr_misng++;
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL,
            DetectionEngine::get_current_packet(), "%s_REQ: ftracker missing 0x%"
            PRIx64 "\n", smb2_command_string[SMB2_COM_READ], fileId_persistent);
        return;
    }

    if (ftracker->file_size and (offset > ftracker->file_size))
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL,
            DetectionEngine::get_current_packet(),
            "%s_REQ: invalid file offset\n", smb2_command_string[SMB2_COM_READ]);
        dce_alert(GID_DCE2, DCE2_SMB_INVALID_FILE_OFFSET, (dce2CommonStats*)&dce2_smb_stats,
            ssd->sd);
    }
}

//-------------------------------------------------------------------------
// Process read response to send file data for inspection. read request
// trackers is cleaned after updating file offset in file tracker
//-------------------------------------------------------------------------
static void DCE2_Smb2ReadResponse(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const Smb2ReadResponseHdr* smb_read_hdr, const uint8_t* end, DCE2_Smb2TreeTracker* ttr,
    uint64_t message_id)
{
    const uint8_t* file_data =  (const uint8_t*)smb_read_hdr + SMB2_READ_RESPONSE_STRUC_SIZE - 1;
    int data_size = end - file_data;
    uint16_t data_offset;
    DCE2_Smb2RequestTracker* request = ssd->findRtracker(message_id);

    if (!request)
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL,
            DetectionEngine::get_current_packet(),
            "%s_RESP: request tracker missing\n", smb2_command_string[SMB2_COM_READ]);
        dce2_smb_stats.v2_read_rtrkr_misng++;
        return;
    }
    data_offset = alignedNtohs((const uint16_t*)(&(smb_read_hdr->data_offset)));
    if (data_offset + (const uint8_t*)smb_hdr > end)
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL,
            DetectionEngine::get_current_packet(), "%s_RESP: bad offset\n",
            smb2_command_string[SMB2_COM_READ]);
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats, ssd->sd);
    }

    DCE2_Smb2FileTracker* ftracker =  ttr->findFtracker(request->get_file_id());
    if ( ftracker and !ftracker->ignore )
    {
        ftracker->upload = false;
        ssd->ftracker_local = std::unique_ptr<DCE2_Smb2LocalFileTracker>(new DCE2_Smb2LocalFileTracker());
        ssd->ftracker_local->file_offset = request->get_offset();
        ssd->ftracker_tcp = ftracker;
        if (!ssd->ftracker_local->file_offset and SMB2_SHARE_TYPE_DISK == ttr->get_share_type())
        {
            FileContext* file = DCE2_Smb2GetFileContext(ssd, ftracker, true);
            if (file)
                file->set_file_size(!ftracker->file_size ? UNKNOWN_FILE_SIZE : ftracker->file_size);
        }
        if (!DCE2_Smb2ProcessFileData(ssd, file_data, data_size))
        {
            ssd->removeRtracker(message_id);
            return;
        }

        uint32_t total_data_length = alignedNtohl((const uint32_t*)&(smb_read_hdr->length));
        DCE2_Smb2UpdateMaxOffset(ftracker, request->get_offset() + total_data_length);
        if (total_data_length > (uint32_t)data_size)
        {
            ssd->ftracker_local->smb2_pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
        }
    }
    ssd->removeRtracker(message_id);
}

//-------------------------------------------------------------------------
// Process read message
//-------------------------------------------------------------------------
void DCE2_Smb2Read(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2SessionTracker* str,
    DCE2_Smb2TreeTracker* ttr, uint64_t mid)
{
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        if ((alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND) &&
            (alignedNtohl(&(smb_hdr->status)) == SMB2_STATUS_PENDING))
            return;

        DCE2_Smb2RequestTracker* rtr = ssd->findRtracker(mid);
        if (rtr and rtr->get_file_id())
        {
            DCE2_Smb2FileTracker* ftracker = ttr->findFtracker(rtr->get_file_id());
            if (ftracker)
            {
                ttr->removeFtracker(rtr->get_file_id());
            }
        }
        ssd->removeRtracker(mid);
        dce2_smb_stats.v2_read_err_resp++;
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s_RESP: error\n",
            smb2_command_string[SMB2_COM_WRITE]);
    }
    // Using structure size to decide whether it is response or request
    else if (structure_size == SMB2_READ_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_READ_REQUEST_STRUC_SIZE - 1,
            dce2_smb_stats.v2_read_req_hdr_err, SMB2_COM_READ)
        DCE2_Smb2ReadRequest(ssd, (const Smb2ReadRequestHdr*)smb_data, end, str, ttr, mid);
    }
    else if (structure_size == SMB2_READ_RESPONSE_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_READ_RESPONSE_STRUC_SIZE - 1,
            dce2_smb_stats.v2_read_resp_hdr_err, SMB2_COM_READ)

        DCE2_Smb2ReadResponse(ssd, smb_hdr, (const Smb2ReadResponseHdr*)smb_data, end, ttr, mid);
    }
    else
    {
        dce2_smb_stats.v2_read_inv_str_sz++;
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(),"%s: invalid struct size\n",
            smb2_command_string[SMB2_COM_WRITE]);
    }
}

//-------------------------------------------------------------------------
// Process write request to create write trackers (to enforce credits limit)
// and to send file data for inspection.
//-------------------------------------------------------------------------
static void DCE2_Smb2WriteRequest(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const Smb2WriteRequestHdr* smb_write_hdr, const uint8_t* end, DCE2_Smb2SessionTracker* str,
    DCE2_Smb2TreeTracker* ttr, uint64_t mid)
{
    const uint8_t* file_data =  (const uint8_t*)smb_write_hdr + SMB2_WRITE_REQUEST_STRUC_SIZE - 1;
    int data_size = end - file_data;
    uint64_t fileId_persistent, offset;
    uint16_t data_offset;

    fileId_persistent = alignedNtohq((const uint64_t*)(&(smb_write_hdr->fileId_persistent)));

    if (ssd->max_outstanding_requests > ssd->getTotalRequestsPending())
    {
        DCE2_Smb2RequestTracker* writetracker = ssd->findRtracker(mid);
        if (!writetracker)
            writetracker = new DCE2_Smb2RequestTracker(fileId_persistent);
        writetracker->set_session_id(str->session_id);
        writetracker->set_tree_id(ttr->get_tid());
        writetracker->set_file_id(fileId_persistent);
        ssd->insertRtracker(mid, writetracker);
    }
    else
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL,
            DetectionEngine::get_current_packet(), "%s_REQ: max req exceeded\n",
            smb2_command_string[SMB2_COM_WRITE]);
        dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats,
            ssd->sd);
        return;
    }

    data_offset = alignedNtohs((const uint16_t*)(&(smb_write_hdr->data_offset)));
    if (data_offset + (const uint8_t*)smb_hdr > end)
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL,
            DetectionEngine::get_current_packet(), "%s_REQ: bad offset\n",
            smb2_command_string[SMB2_COM_WRITE]);
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats, ssd->sd);
    }

    offset = alignedNtohq((const uint64_t*)(&(smb_write_hdr->offset)));
    DCE2_Smb2FileTracker* ftracker = ttr->findFtracker(fileId_persistent);

    if (!ftracker and ttr->get_share_type() == SMB2_SHARE_TYPE_DISK)
    {
        ftracker = new DCE2_Smb2FileTracker(fileId_persistent, ttr, str, DetectionEngine::get_current_packet()->flow);
        ttr->insertFtracker(fileId_persistent, ftracker);
    }
    if (!ftracker)
    {
        dce2_smb_stats.v2_read_rtrkr_misng++;
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(),
            "%s_REQ: ftracker missing 0x%" PRIx64 "\n",
            smb2_command_string[SMB2_COM_WRITE], fileId_persistent);
        return;
    }

    if (!ftracker->ignore) // file tracker can not be nullptr here
    {
        if (ftracker->file_size and (offset > ftracker->file_size))
        {
            dce_alert(GID_DCE2, DCE2_SMB_INVALID_FILE_OFFSET, (dce2CommonStats*)&dce2_smb_stats,
                ssd->sd);
        }

        ftracker->upload = true;
        ssd->ftracker_local = std::unique_ptr<DCE2_Smb2LocalFileTracker>(new DCE2_Smb2LocalFileTracker());
        ssd->ftracker_local->file_offset = offset;
        ssd->ftracker_tcp = ftracker;
        if (!ssd->ftracker_local->file_offset and SMB2_SHARE_TYPE_DISK == ttr->get_share_type())
        {
            FileContext* file = DCE2_Smb2GetFileContext(ssd, ftracker, true);
            if (file)
                file->set_file_size(!ftracker->file_size ? UNKNOWN_FILE_SIZE : ftracker->file_size);
        }
        if (!DCE2_Smb2ProcessFileData(ssd, file_data, data_size))
            return;

        uint32_t total_data_length = alignedNtohl((const uint32_t*)&(smb_write_hdr->length));
        DCE2_Smb2UpdateMaxOffset(ftracker, offset + total_data_length);
        if (total_data_length > (uint32_t)data_size)
        {
            ssd->ftracker_local->smb2_pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
        }
    }
}

//-------------------------------------------------------------------------
// Process write message
//-------------------------------------------------------------------------
void DCE2_Smb2Write(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2SessionTracker* str,
    DCE2_Smb2TreeTracker* ttr, uint64_t mid)
{
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        if ((alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND) &&
            (alignedNtohl(&(smb_hdr->status)) == SMB2_STATUS_PENDING))
            return;

        DCE2_Smb2RequestTracker* wtr = ssd->findRtracker(mid);
        if (wtr and wtr->get_file_id())
        {
            DCE2_Smb2FileTracker* ftracker = ttr->findFtracker(wtr->get_file_id());
            if (ftracker)
            {
                ttr->removeFtracker(wtr->get_file_id());
            }
        }
        ssd->removeRtracker(mid);
        dce2_smb_stats.v2_wrt_err_resp++;
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s_RESP: error\n",
            smb2_command_string[SMB2_COM_WRITE]);
    }
    // Using structure size to decide whether it is response or request
    else if (structure_size == SMB2_WRITE_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_WRITE_REQUEST_STRUC_SIZE - 1,
            dce2_smb_stats.v2_wrt_req_hdr_err, SMB2_COM_WRITE)
        DCE2_Smb2WriteRequest(ssd, smb_hdr, (const Smb2WriteRequestHdr*)smb_data, end, str, ttr,
            mid);
    }
    else if (structure_size == SMB2_WRITE_RESPONSE_STRUC_SIZE)
    {
        ssd->removeRtracker(mid);
    }
    else
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s: invalid struct size\n",
            smb2_command_string[SMB2_COM_WRITE]);
        dce2_smb_stats.v2_wrt_inv_str_sz++;
    }
}

//-------------------------------------------------------------------------
// Process logoff to cleanup session tracker and their corresponding tree
// trackers and their corresponding file trackers
//-------------------------------------------------------------------------
void DCE2_Smb2Logoff(DCE2_Smb2SsnData* ssd, const uint8_t* smb_data,
    const uint64_t sid)
{
    if (alignedNtohs((const uint16_t*)smb_data) == SMB2_LOGOFF_REQUEST_STRUC_SIZE)
    {
        auto str = DCE2_Smb2FindSidInSsd(ssd, sid);
        if (str)
        {
            auto session_key = get_key(sid);
            DCE2_SmbSessionCacheRemove(session_key);
        }
    }
    else
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            DetectionEngine::get_current_packet(), "%s: invalid struct size\n",
            smb2_command_string[SMB2_COM_LOGOFF]);
        dce2_smb_stats.v2_logoff_inv_str_sz++;
    }
}

void DCE2_Smb2IoctlCommand(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2SessionTracker* str,
    DCE2_Smb2TreeTracker* ttr, uint64_t mid)
{
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);
    const uint8_t* file_data = (const uint8_t*)smb_data + structure_size - 1;
    int data_size = end - file_data;
    uint64_t fileId_persistent = 0;
    Packet* p = DetectionEngine::get_current_packet();
    if (data_size > UINT16_MAX)
    {
        data_size = UINT16_MAX;
    }
    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        if ((alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND) &&
            (alignedNtohl(&(smb_hdr->status)) == SMB2_STATUS_PENDING))
            return;

        dce2_smb_stats.v2_ioctl_err_resp++;
        ssd->removeRtracker(mid);
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            p, "%s_RESP: error\n",
            smb2_command_string[SMB2_COM_IOCTL]);
    }
    // Using structure size to decide whether it is response or request
    else if (structure_size == SMB2_IOCTL_REQUEST_STRUC_SIZE)
    {
        const Smb2IoctlRequestHdr* ioctl_request = (const Smb2IoctlRequestHdr*)smb_data;
        if ((ioctl_request->ctl_code != FSCTL_PIPE_PEEK) and (ioctl_request->ctl_code !=
            FSCTL_PIPE_WAIT) and (ioctl_request->ctl_code != FSCTL_PIPE_TRANSCEIVE))
        {
            return;
        }
        fileId_persistent = ioctl_request->fileId_persistent;
        if (ssd->max_outstanding_requests > ssd->getTotalRequestsPending())
        {
            DCE2_Smb2RequestTracker* readtracker = ssd->findRtracker(mid);
            if (!readtracker)
                readtracker = new DCE2_Smb2RequestTracker(fileId_persistent, 0);
            readtracker->set_session_id(str->session_id);
            readtracker->set_tree_id(ttr->get_tid());
            readtracker->set_file_id(fileId_persistent);
            ssd->insertRtracker(mid, readtracker);
        }
        else
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL,
                DetectionEngine::get_current_packet(), "%s_REQ: max req exceeded\n",
                smb2_command_string[SMB2_COM_READ]);
            dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats,
                ssd->sd);
            return;
        }
    }
    else if (structure_size == SMB2_IOCTL_RESPONSE_STRUC_SIZE)
    {
        const Smb2IoctlResponseHdr* ioctl_response = (const Smb2IoctlResponseHdr*)smb_data;
        if ((ioctl_response->ctl_code != FSCTL_PIPE_PEEK) and (ioctl_response->ctl_code !=
            FSCTL_PIPE_WAIT) and (ioctl_response->ctl_code != FSCTL_PIPE_TRANSCEIVE))
        {
            return;
        }
        fileId_persistent = ioctl_response->fileId_persistent;
        ssd->removeRtracker(mid);
    }
    else
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            p, "%s: invalid struct size\n",
            smb2_command_string[SMB2_COM_IOCTL]);
        dce2_smb_stats.v2_ioctl_inv_str_sz++;
        return;
    }
    DCE2_Smb2FileTracker* ftracker =  ttr->findFtracker(fileId_persistent);
    if (ftracker and ftracker->co_tracker)
    {
        DCE2_CoProcess(&ssd->sd, ftracker->co_tracker, file_data, data_size);
    }
}

