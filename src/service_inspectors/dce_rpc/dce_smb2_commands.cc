//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "packet_io/active.h"
#include "protocols/packet.h"

using namespace snort;
#define UNKNOWN_FILE_SIZE (~0)

#define SMB2_CHECK_HDR_ERROR(smb_data, end, strcuture_size, counter, cmd) \
    { \
        if ((smb_data + (strcuture_size)) > end) \
        { \
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(), \
                "%s : smb data beyond end detected\n", smb2_command_string[cmd]); \
            counter ++; \
            return; \
        } \
    }

static inline FileContext* get_smb_file_context(uint64_t file_id, uint64_t
    multi_file_processing_id,
    bool to_create = false)
{
    FileFlows* file_flows = FileFlows::get_file_flows(DetectionEngine::get_current_packet()->flow);

    if ( !file_flows )
    {
        dce2_smb_stats.v2_inv_file_ctx_err++;
        return nullptr;
    }

    return file_flows->get_file_context(file_id, to_create, multi_file_processing_id);
}

static void DCE2_Smb2CleanFtrackerTcpRef(DCE2_Smb2SessionTracker* str, uint64_t file_id)
{
    debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
        "updating conn for fid %" PRIu64 "\n", file_id);
    auto all_conn_trackers = str->conn_trackers.get_all_entry();
    for ( auto& h : all_conn_trackers )
    {
        if (h.second->ftracker_tcp)
        {
            if (h.second->ftracker_tcp->file_id == file_id)
            {
                h.second->ftracker_tcp = nullptr;
            }
        }
    }
}

bool DCE2_Smb2ProcessFileData(DCE2_Smb2SsnData* ssd, const uint8_t* file_data,
    uint32_t data_size)
{
    int64_t file_detection_depth = DCE2_ScSmbFileDepth((dce2SmbProtoConf*)ssd->sd.config);
    int64_t detection_size = 0;

    if (file_detection_depth == 0)
        detection_size = data_size;
    else if ( ssd->ftracker_tcp->file_offset < (uint64_t)file_detection_depth)
    {
        if ( file_detection_depth - ssd->ftracker_tcp->file_offset < data_size )
            detection_size = file_detection_depth - ssd->ftracker_tcp->file_offset;
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
    ssd->ftracker_tcp->bytes_processed += detection_size;
    FileDirection dir = ssd->ftracker_tcp->upload ? FILE_UPLOAD : FILE_DOWNLOAD;

    debug_logf(dce_smb_trace, p, "file_process fid %" PRIu64 " data_size %" PRIu32 ""
        " offset %" PRIu64 " bytes processed %" PRIu64 "\n", ssd->ftracker_tcp->file_id,
        data_size, ssd->ftracker_tcp->file_offset, ssd->ftracker_tcp->bytes_processed);

    // Do not process data beyond file size if file size is known.
    FileFlows* file_flows = FileFlows::get_file_flows(p->flow);
    if ( !file_flows or (ssd->ftracker_tcp->file_size and
        ssd->ftracker_tcp->bytes_processed > ssd->ftracker_tcp->file_size) )
    {
        dce2_smb_stats.v2_extra_file_data_err++;
        debug_logf(dce_smb_trace, p, "extra file data\n");

        DCE2_Smb2TreeTracker* ttr = ssd->ftracker_tcp->ttr;
        uint64_t file_id = ssd->ftracker_tcp->file_id;
        DCE2_Smb2CleanFtrackerTcpRef(ssd->ftracker_tcp->str, file_id);
        ttr->removeFtracker(file_id);

        return false;
    }

    if (!file_flows->file_process(p, ssd->ftracker_tcp->file_name_hash, file_data, data_size,
        ssd->ftracker_tcp->file_offset, dir, ssd->ftracker_tcp->file_id) and detection_size)
    {
        debug_logf(dce_smb_trace, p, "file_process completed\n");

        DCE2_Smb2TreeTracker* ttr = ssd->ftracker_tcp->ttr;
        uint64_t file_id = ssd->ftracker_tcp->file_id;
        DCE2_Smb2CleanFtrackerTcpRef(ssd->ftracker_tcp->str, file_id);
        ttr->removeFtracker(file_id);

        return false;
    }
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
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_RESP: error\n", smb2_command_string[SMB2_COM_SESSION_SETUP]);
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
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s: invalid struct size\n", smb2_command_string[SMB2_COM_SESSION_SETUP]);
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
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                "%s: ignored %d\n", smb2_command_string[SMB2_COM_TREE_CONNECT], tid);
            dce2_smb_stats.v2_tree_cnct_ignored++;
        }
    }
    else if (structure_size != SMB2_TREE_CONNECT_REQUEST_STRUC_SIZE)
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s: invalid struct size\n", smb2_command_string[SMB2_COM_TREE_CONNECT]);
        dce2_smb_stats.v2_tree_cnct_inv_str_sz++;
    }
}

//-------------------------------------------------------------------------
// Process tree disconnect request to cleanup tree tracker and its
// corresponding request trackers and file trackers
//-------------------------------------------------------------------------
void DCE2_Smb2TreeDisconnect(DCE2_Smb2SsnData*, const uint8_t* smb_data,
    const uint8_t* end, DCE2_Smb2SessionTracker* str, uint32_t tid)
{
    if (SMB2_TREE_DISCONNECT_REQUEST_STRUC_SIZE == alignedNtohs((const uint16_t*)smb_data))
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_TREE_DISCONNECT_REQUEST_STRUC_SIZE,
            dce2_smb_stats.v2_tree_discn_req_hdr_err, SMB2_COM_TREE_DISCONNECT)
        str->removeTtracker(tid);
    }
    else
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s: invalid struct size\n", smb2_command_string[SMB2_COM_TREE_DISCONNECT]);
        dce2_smb_stats.v2_tree_discn_inv_str_sz++;
    }
}

//-------------------------------------------------------------------------
// Process create request to get file name and save it in request tracker
//-------------------------------------------------------------------------
static void DCE2_Smb2CreateRequest(DCE2_Smb2SsnData* ssd,
    const Smb2CreateRequestHdr* smb_create_hdr,const uint8_t* end,
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
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                "%s_REQ: invalid file data seen\n", smb2_command_string[SMB2_COM_CREATE]);
            return;
        }

        uint16_t size = alignedNtohs(&(smb_create_hdr->name_length));
        if (!size or (file_data + size > end))
        {
            dce2_smb_stats.v2_crt_inv_file_data++;
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                "%s_REQ: invalid file data seen with size %" PRIu16 "\n",
                smb2_command_string[SMB2_COM_CREATE], size);

            return;
        }

        if (ssd->max_outstanding_requests > str->getTotalRequestsPending())
        {
            DCE2_Smb2RequestTracker* rtracker = ttr->findRtracker(mid);
            if (rtracker) // Cleanup existing tracker
                ttr->removeRtracker(mid);

            char* file_name = DCE2_SmbGetFileName(file_data, size, true, &name_len);

            rtracker = new DCE2_Smb2RequestTracker(file_name, name_len);
            ttr->insertRtracker(mid, rtracker);
        }
        else
        {
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                "%s_REQ: max req exceeded\n", smb2_command_string[SMB2_COM_CREATE]);
            dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats,
                ssd->sd);
        }
    }
    else
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_REQ: name_offset %" PRIu16 "\n", smb2_command_string[SMB2_COM_CREATE], name_offset);
        dce2_smb_stats.v2_crt_req_hdr_err++;
    }
}

//-------------------------------------------------------------------------
// Process create response to create file tracker with file id and file
// size. Request tracker is cleaned after updating file name in file tracker
//-------------------------------------------------------------------------
static void DCE2_Smb2CreateResponse(DCE2_Smb2SsnData*,
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
    ftracker->file_name = rtracker->fname;
    ftracker->file_name_len = rtracker->fname_len;
    ftracker->file_size = file_size;

    if (rtracker->fname and rtracker->fname_len)
    {
        ftracker->file_name_hash = str_to_hash(
            (const uint8_t*)rtracker->fname, rtracker->fname_len);

        FileContext* file = get_smb_file_context(ftracker->file_name_hash, fileId_persistent,
            true);

        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_RESP: file size %" PRIu64 " fid %" PRIu64 ""
            "file_name_hash %" PRIu64 " file context %s\n", smb2_command_string[SMB2_COM_CREATE],
            file_size, fileId_persistent, ftracker->file_name_hash, (file ? "found" : "not found"));

        if (file)
        {
            if (file->verdict == FILE_VERDICT_UNKNOWN)
            {
                file->set_file_size(!file_size ? UNKNOWN_FILE_SIZE : file_size);
                file->set_file_name(ftracker->file_name, ftracker->file_name_len);
            }
        }
        else
        {
            ftracker->ignore = true; // could not create file context, hence this file transfer
                                     // cant be inspected
        }
        rtracker->set_file_id(fileId_persistent); // to ensure file tracker will free file name
    }
    else
    {
        ftracker->ignore = true; // file can not be inspected as file name is null
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
    DCE2_Smb2TreeTracker* ttr = str->findTtracker(tid);
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        if (ttr)
            ttr->removeRtracker(mid);

        dce2_smb_stats.v2_crt_err_resp++;
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_RESP: error\n", smb2_command_string[SMB2_COM_CREATE]);
    }
    // Using structure size to decide whether it is response or request
    else if (structure_size == SMB2_CREATE_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_CREATE_REQUEST_STRUC_SIZE - 1,
            dce2_smb_stats.v2_crt_req_hdr_err, SMB2_COM_CREATE)

        if (!ttr)
        {
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                "%s_REQ: mid stream session detected\n", smb2_command_string[SMB2_COM_CREATE]);
            ttr = DCE2_Smb2InsertTid(ssd, tid, SMB2_SHARE_TYPE_DISK, str);
            if (!ttr)
            {
                debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                    "%s_REQ: insert tree tracker failed\n", smb2_command_string[SMB2_COM_CREATE]);
                return;
            }
        }
        else if (SMB2_SHARE_TYPE_DISK != ttr->get_share_type())
        {
            dce2_smb_stats.v2_crt_req_ipc++;
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                "%s_REQ: ignored for ipc share\n", smb2_command_string[SMB2_COM_CREATE]);
            return;
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
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                 "%s_RESP: tree tracker missing\n", smb2_command_string[SMB2_COM_CREATE]);
            dce2_smb_stats.v2_crt_tree_trkr_misng++;
            return;
        }

        DCE2_Smb2RequestTracker* rtr = ttr->findRtracker(mid);
        if (!rtr)
        {
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                 "%s_RESP: req tracker missing\n", smb2_command_string[SMB2_COM_CREATE]);
            dce2_smb_stats.v2_crt_rtrkr_misng++;
            return;
        }

        uint64_t fileId_persistent = alignedNtohq((const uint64_t*)(
                &(((const Smb2CreateResponseHdr*)smb_data)->fileId_persistent)));

        if (((const Smb2CreateResponseHdr*)smb_data)->file_attributes &
            SMB2_CREATE_RESPONSE_DIRECTORY)
        {
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                 "%s_RESP: not processing for directory\n", smb2_command_string[SMB2_COM_CREATE]);
            ttr->removeRtracker(mid);
            DCE2_Smb2CleanFtrackerTcpRef(str, fileId_persistent);
            ttr->removeFtracker(fileId_persistent);
            return;
        }

        DCE2_Smb2CreateResponse(ssd, (const Smb2CreateResponseHdr*)smb_data, rtr, ttr,
            str, fileId_persistent);
        ttr->removeRtracker(mid);
    }
    else
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s: invalid struct size\n", smb2_command_string[SMB2_COM_CREATE]);
        dce2_smb_stats.v2_crt_inv_str_sz++;
    }
}

//-------------------------------------------------------------------------
// Process close command request to do file processing for an upload or
// download request with unknown size.
//-------------------------------------------------------------------------
void DCE2_Smb2CloseCmd(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2TreeTracker* ttr,
    DCE2_Smb2SessionTracker* str)
{
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_RESP: error\n", smb2_command_string[SMB2_COM_CLOSE]);
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
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                "%s_REQ: ftracker missing %" PRIu64 "\n",
                smb2_command_string[SMB2_COM_CLOSE], fileId_persistent);
            return;
        }

        if (!ftracker->ignore and !ftracker->file_size and ftracker->file_offset)
        {
            ftracker->file_size = ftracker->file_offset;
            FileContext* file = get_smb_file_context(ftracker->file_name_hash, fileId_persistent);
            if (file)
            {
                file->set_file_size(ftracker->file_size);
            }

            ssd->ftracker_tcp = ftracker;

            // In case of upload/download of file with UNKNOWN size, we will not be able to
            // detect malicious file during write request or read response. Once the close
            // command request comes, we will go for file inspection and block an subsequent
            // upload/download request for this file even with unknown size
            DCE2_Smb2ProcessFileData(ssd, nullptr, 0);
        }
        else
        {
            DCE2_Smb2CleanFtrackerTcpRef(str, fileId_persistent);
            ttr->removeFtracker(fileId_persistent);
        }
    }
    else if (structure_size != SMB2_CLOSE_RESPONSE_STRUC_SIZE)
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s: invalid struct size\n", smb2_command_string[SMB2_COM_CLOSE]);
        dce2_smb_stats.v2_cls_inv_str_sz++;
    }
}

//-------------------------------------------------------------------------
// Process set info request to update file size
//-------------------------------------------------------------------------
void DCE2_Smb2SetInfo(DCE2_Smb2SsnData*, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2TreeTracker* ttr)
{
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    // Using structure size to decide whether it is response or request
    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s: error resp\n", smb2_command_string[SMB2_COM_SET_INFO]);
        dce2_smb_stats.v2_stinf_err_resp++;
    }
    else if (structure_size == SMB2_SET_INFO_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_SET_INFO_REQUEST_STRUC_SIZE,
            dce2_smb_stats.v2_stinf_req_hdr_err, SMB2_COM_SET_INFO)

        const Smb2SetInfoRequestHdr* smb_set_info_hdr = (const Smb2SetInfoRequestHdr*)smb_data;
        const uint8_t* file_data =  (const uint8_t*)smb_set_info_hdr +
            SMB2_SET_INFO_REQUEST_STRUC_SIZE - 1;

        if (smb_set_info_hdr->file_info_class == SMB2_FILE_ENDOFFILE_INFO)
        {
            uint64_t file_size = alignedNtohq((const uint64_t*)file_data);
            uint64_t fileId_persistent = alignedNtohq(&(smb_set_info_hdr->fileId_persistent));
            DCE2_Smb2FileTracker* ftracker = ttr->findFtracker(fileId_persistent);
            if (ftracker and !ftracker->ignore)
            {
                ftracker->file_size = file_size;
                FileContext* file = get_smb_file_context(ftracker->file_name_hash,
                    fileId_persistent);
                debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                    "%s_REQ: set file size %" PRIu64 " fid %" PRIu64 " file context %s\n",
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
                debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                    "%s_REQ: ftracker missing\n", smb2_command_string[SMB2_COM_SET_INFO]);
            }
        }
        else
        {
            debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
                "%s_REQ: header error\n", smb2_command_string[SMB2_COM_SET_INFO]);
            dce2_smb_stats.v2_stinf_req_hdr_err++;
        }
    }
    else if (structure_size != SMB2_SET_INFO_RESPONSE_STRUC_SIZE)
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s: invalid struct size\n", smb2_command_string[SMB2_COM_SET_INFO]);
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

    if (ssd->max_outstanding_requests > str->getTotalRequestsPending())
    {
        DCE2_Smb2RequestTracker* readtracker = ttr->findRtracker(message_id);
        if (!readtracker)
        {
            readtracker = new DCE2_Smb2RequestTracker(fileId_persistent, offset);
            ttr->insertRtracker(message_id, readtracker);
        }
    }
    else
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_REQ: max req exceeded\n", smb2_command_string[SMB2_COM_READ]);
        dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats,
            ssd->sd);
        return;
    }

    DCE2_Smb2FileTracker* ftracker =  ttr->findFtracker(fileId_persistent);
    if (!ftracker) // compounded create request + read request case
    {
        ftracker = new DCE2_Smb2FileTracker(fileId_persistent, ttr, str, DetectionEngine::get_current_packet()->flow);
        ttr->insertFtracker(fileId_persistent, ftracker);
    }

    if (ftracker->file_size and (offset > ftracker->file_size))
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
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
    DCE2_Smb2RequestTracker* request;

    request = ttr->findRtracker(message_id);
    if (!request)
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_RESP: request tracker missing\n", smb2_command_string[SMB2_COM_READ]);
        dce2_smb_stats.v2_read_rtrkr_misng++;
        return;
    }
    data_offset = alignedNtohs((const uint16_t*)(&(smb_read_hdr->data_offset)));
    if (data_offset + (const uint8_t*)smb_hdr > end)
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_RESP: bad offset\n", smb2_command_string[SMB2_COM_READ]);
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats, ssd->sd);
    }

    DCE2_Smb2FileTracker* ftracker =  ttr->findFtracker(request->get_file_id());
    if ( ftracker and !ftracker->ignore )
    {
        ftracker->file_offset = request->get_offset();
        ttr->removeRtracker(message_id);

        ssd->ftracker_tcp = ftracker;

        if (!DCE2_Smb2ProcessFileData(ssd, file_data, data_size))
            return;
        ftracker->file_offset += data_size;

        uint32_t total_data_length = alignedNtohl((const uint32_t*)&(smb_read_hdr->length));
        if (total_data_length > (uint32_t)data_size)
        {
            ftracker->smb2_pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
        }
    }
}

//-------------------------------------------------------------------------
// Process read message
//-------------------------------------------------------------------------
void DCE2_Smb2Read(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2SessionTracker* str,
    DCE2_Smb2TreeTracker* ttr, uint64_t mid)
{
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    if (Smb2Error(smb_hdr) and structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE)
    {
        DCE2_Smb2RequestTracker* rtr = ttr->findRtracker(mid);
        if (rtr and rtr->get_file_id())
        {
            DCE2_Smb2CleanFtrackerTcpRef(str, rtr->get_file_id());
            ttr->removeFtracker(rtr->get_file_id());
        }
        ttr->removeRtracker(mid);
        dce2_smb_stats.v2_read_err_resp++;
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_RESP: error\n", smb2_command_string[SMB2_COM_WRITE]);
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
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s: invalid struct size\n", smb2_command_string[SMB2_COM_WRITE]);
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

    if (ssd->max_outstanding_requests > str->getTotalRequestsPending())
    {
        DCE2_Smb2RequestTracker* writetracker = ttr->findRtracker(mid);
        if (!writetracker)
        {
            writetracker = new DCE2_Smb2RequestTracker(fileId_persistent);
            ttr->insertRtracker(mid, writetracker);
        }
    }
    else
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_REQ: max req exceeded\n", smb2_command_string[SMB2_COM_WRITE]);
        dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats,
            ssd->sd);
        return;
    }

    data_offset = alignedNtohs((const uint16_t*)(&(smb_write_hdr->data_offset)));
    if (data_offset + (const uint8_t*)smb_hdr > end)
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_REQ: bad offset\n", smb2_command_string[SMB2_COM_WRITE]);
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats, ssd->sd);
    }

    offset = alignedNtohq((const uint64_t*)(&(smb_write_hdr->offset)));
    DCE2_Smb2FileTracker* ftracker = ttr->findFtracker(fileId_persistent);
    if (!ftracker) // compounded create request + write request case
    {
        ftracker = new DCE2_Smb2FileTracker(fileId_persistent, ttr, str, DetectionEngine::get_current_packet()->flow);
        ttr->insertFtracker(fileId_persistent, ftracker);
    }
    if (!ftracker->ignore) // file tracker can not be nullptr here
    {
        if (ftracker->file_size and (offset > ftracker->file_size))
        {
            dce_alert(GID_DCE2, DCE2_SMB_INVALID_FILE_OFFSET, (dce2CommonStats*)&dce2_smb_stats,
                ssd->sd);
        }
        ftracker->file_offset = offset;
        ftracker->upload = true;

        ssd->ftracker_tcp = ftracker;

        if (!DCE2_Smb2ProcessFileData(ssd, file_data, data_size))
            return;
        ftracker->file_offset += data_size;
        uint32_t total_data_length = alignedNtohl((const uint32_t*)&(smb_write_hdr->length));
        if (total_data_length > (uint32_t)data_size)
        {
            ftracker->smb2_pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
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
        DCE2_Smb2RequestTracker* wtr = ttr->findRtracker(mid);
        if (wtr and wtr->get_file_id())
        {
            DCE2_Smb2CleanFtrackerTcpRef(str, wtr->get_file_id());
            ttr->removeFtracker(wtr->get_file_id());
        }
        ttr->removeRtracker(mid);
        dce2_smb_stats.v2_wrt_err_resp++;
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s_RESP: error\n", smb2_command_string[SMB2_COM_WRITE]);
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
        ttr->removeRtracker(mid);
    }
    else
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s: invalid struct size\n", smb2_command_string[SMB2_COM_WRITE]);
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
        DCE2_Smb2SessionTracker* str = DCE2_Smb2FindSidInSsd(ssd, sid);
        if (str)
        {
            str->removeSessionFromAllConnection();
            DCE2_SmbSessionCacheRemove(str->session_key);
        }
    }
    else
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "%s: invalid struct size\n", smb2_command_string[SMB2_COM_LOGOFF]);
        dce2_smb_stats.v2_logoff_inv_str_sz++;
    }
}

