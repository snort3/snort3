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
#include "log/messages.h"
#include "main/snort_debug.h"
#include "packet_io/active.h"
#include "protocols/packet.h"

using namespace snort;
#define UNKNOWN_FILE_SIZE (~0)
#define SMB2_CHECK_HDR_ERROR(smb_data, end, strcuture_size, counter)\
{ \
    if ((smb_data + (strcuture_size)) > end)\
    {\
        counter++;\
        return;\
    }\
}

static inline FileContext* get_smb_file_context(uint64_t file_id)
{
    FileFlows* file_flows = FileFlows::get_file_flows(DetectionEngine::get_current_packet()->flow);

    if ( !file_flows )
    {
        dce2_smb_stats.v2_inv_file_ctx_err++;
        return nullptr;
    }

    return file_flows->get_file_context(file_id, true);
}

void DCE2_Smb2ProcessFileData(DCE2_Smb2SsnData* ssd, const uint8_t* file_data,
    uint32_t data_size, FileDirection dir)
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

    // Do not process data beyond file size if file size is known.
    FileFlows* file_flows = FileFlows::get_file_flows(p->flow);
    if ( !file_flows or ( ssd->ftracker_tcp->file_size and
        ssd->ftracker_tcp->bytes_processed > ssd->ftracker_tcp->file_size ) )
    {
        dce2_smb_stats.v2_extra_file_data_err++;
        return;
    }

    file_flows->file_process(p, ssd->ftracker_tcp->file_id, file_data, data_size,
        ssd->ftracker_tcp->file_offset, dir);
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
        dce2_smb_stats.v2_setup_err_resp++;
    }
    else if (structure_size == SMB2_SETUP_RESPONSE_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_SETUP_RESPONSE_STRUC_SIZE - 1,
            dce2_smb_stats.v2_setup_resp_hdr_err)
        DCE2_Smb2FindElseCreateSid(ssd, sid);
    }
    else if (structure_size != SMB2_SETUP_REQUEST_STRUC_SIZE)
    {
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
            dce2_smb_stats.v2_tree_cnct_resp_hdr_err)

        if (!DCE2_Smb2FindElseCreateTid(ssd, tid,
                ((const Smb2TreeConnectResponseHdr*)smb_data)->share_type, str))
            dce2_smb_stats.v2_tree_cnct_ignored++;
    }
    else if (structure_size != SMB2_TREE_CONNECT_REQUEST_STRUC_SIZE)
    {
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
            dce2_smb_stats.v2_tree_discn_req_hdr_err)
        str->removeTtracker(tid);
    }
    else
    {
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
            return;
        }

        uint16_t size = alignedNtohs(&(smb_create_hdr->name_length));
        if (!size or (file_data + size > end))
        {
            dce2_smb_stats.v2_crt_inv_file_data++;
            return;
        }

        char* file_name = DCE2_SmbGetFileName(file_data, size, true,
            &name_len);

        if (ssd->max_outstanding_requests > str->getTotalRequestsPending())
        {
            DCE2_Smb2RequestTracker* rtracker = str->findRtracker(mid);
            if (rtracker) // Cleanup existing tracker
                str->removeRtracker(mid);

            rtracker = new DCE2_Smb2RequestTracker(0, 0, file_name, name_len, ttr);

            str->insertRtracker(mid, rtracker);
        }
        else
        {
            snort_free(file_name);
            dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats,
                ssd->sd);
        }
    }
    else
    {
        dce2_smb_stats.v2_crt_req_hdr_err++;
    }
}

//-------------------------------------------------------------------------
// Process create response to create file tracker with file id and file
// size. Request tracker is cleaned after updating file name in file tracker 
//-------------------------------------------------------------------------
static void DCE2_Smb2CreateResponse(DCE2_Smb2SsnData*,
    const Smb2CreateResponseHdr* smb_create_hdr,
    DCE2_Smb2RequestTracker* rtracker)
{
    uint64_t file_size = 0;
    uint64_t fileId_persistent = alignedNtohq((const uint64_t*)(&(smb_create_hdr->fileId_persistent)));

    if (smb_create_hdr->end_of_file)
    {
        file_size = alignedNtohq((const uint64_t*)(&(smb_create_hdr->end_of_file)));
    }

    DCE2_Smb2FileTracker* ftracker = rtracker->get_tree_tracker()->findFtracker(fileId_persistent);
    if (!ftracker)
    {
        ftracker = new DCE2_Smb2FileTracker(
            fileId_persistent, rtracker->get_file_name(), file_size);
    }
    else // compounded create request + read request case
    {
        ftracker->file_name.assign(rtracker->get_file_name());
        ftracker->file_size = file_size;
    }

    if (rtracker->get_file_name() and rtracker->get_file_name_len())
    {
        FileContext* file = get_smb_file_context(fileId_persistent);
        if (file)
        {
            file->set_file_size(!file_size ? UNKNOWN_FILE_SIZE : file_size);
            file->set_file_name(rtracker->get_file_name(), rtracker->get_file_name_len());
        }
    }

    rtracker->get_tree_tracker()->insertFtracker(fileId_persistent, ftracker);
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
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        //in case of compound create + read, a ftracker is already created, remove it
        DCE2_Smb2RequestTracker* rtr = str->findRtracker(mid);
        if ( rtr and rtr->get_tree_tracker() and rtr->get_file_id() )
        {
            if (ssd->ftracker_tcp->file_id == rtr->get_file_id())
                ssd->ftracker_tcp = NULL;
            rtr->get_tree_tracker()->removeFtracker(rtr->get_file_id());
        }
        str->removeRtracker(mid);
        dce2_smb_stats.v2_crt_err_resp++;
    }
    // Using structure size to decide whether it is response or request
    else if (structure_size == SMB2_CREATE_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_CREATE_REQUEST_STRUC_SIZE - 1,
            dce2_smb_stats.v2_crt_req_hdr_err)

        DCE2_Smb2TreeTracker* ttr = str->findTtracker(tid);
        if (!ttr)
        {
            ttr = DCE2_Smb2InsertTid(ssd, tid, SMB2_SHARE_TYPE_DISK, str);
        }
        else if (SMB2_SHARE_TYPE_DISK != ttr->get_share_type())
        {
            debug_logf(dce_smb_trace, nullptr, "Not handling create request for IPC with TID (%u)\n",
                tid);
            dce2_smb_stats.v2_crt_req_ipc++;
            return;
        }
        DCE2_Smb2CreateRequest(ssd, (const Smb2CreateRequestHdr*)smb_data, end, str, ttr, mid);
    }
    else if (structure_size == SMB2_CREATE_RESPONSE_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_CREATE_RESPONSE_STRUC_SIZE - 1,
            dce2_smb_stats.v2_crt_resp_hdr_err)

        DCE2_Smb2RequestTracker* rtr = str->findRtracker(mid);
        if (!rtr)
        {
            debug_logf(dce_smb_trace, nullptr,
                "No create request received for this MID (%" PRIu64 ")\n", mid);
            dce2_smb_stats.v2_crt_rtrkr_misng++;
            return;
        }
        // Check required only for null tree tracker since for IPC,
        // the request tracker itself is not added.
        if (!rtr->get_tree_tracker())
        {
            debug_logf(dce_smb_trace, nullptr,
                "Tree tracker is missing for create request\n");
            dce2_smb_stats.v2_crt_tree_trkr_misng++;
            str->removeRtracker(mid);
            return;
        }
        
        DCE2_Smb2CreateResponse(ssd, (const Smb2CreateResponseHdr*)smb_data, rtr);
        str->removeRtracker(mid);
    }
    else
    {
        dce2_smb_stats.v2_crt_inv_str_sz++;
    }
}

//-------------------------------------------------------------------------
// Process close command request to do file processing for an upload or
// download request with unknown size.
//-------------------------------------------------------------------------
void DCE2_Smb2CloseCmd(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2TreeTracker* ttr)
{
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

    if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE and Smb2Error(smb_hdr))
    {
        dce2_smb_stats.v2_cls_err_resp++;
    }
    // Using structure size to decide whether it is response or request
    else if (structure_size == SMB2_CLOSE_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_CLOSE_REQUEST_STRUC_SIZE,
            dce2_smb_stats.v2_cls_req_hdr_err)

        uint64_t fileId_persistent = alignedNtohq(&(((const Smb2CloseRequestHdr*)smb_data)->fileId_persistent));
        DCE2_Smb2FileTracker* ftracker =  ttr->findFtracker(fileId_persistent);
        if (!ftracker)
        {
            dce2_smb_stats.v2_cls_req_ftrkr_misng++;
            return;
        }

        if (!ftracker->file_size and ftracker->file_offset)
        {
            // If close command request comes just after create response, we dont have 
            // information to know the direction, hence below code was included.
            FileDirection dir = DetectionEngine::get_current_packet()->is_from_client() ?
                FILE_UPLOAD : FILE_DOWNLOAD;

            ftracker->file_size = ftracker->file_offset;
            FileContext* file = get_smb_file_context(fileId_persistent);
            if (file)
            {
                file->set_file_size(ftracker->file_size);
            }
           
            // In case of upload/download of file with UNKNOWN size, we will not be able to
            // detect malicious file during write request or read response. Once the close
            // command request comes, we will go for file inspection and block an subsequent
            // upload/download request for this file even with unknown size
            DCE2_Smb2ProcessFileData(ssd, nullptr, 0, dir);
        }

        if (ssd->ftracker_tcp and ssd->ftracker_tcp->file_id == fileId_persistent)
            ssd->ftracker_tcp = nullptr;

        ttr->removeFtracker(fileId_persistent);

    }
    else if (structure_size != SMB2_CLOSE_RESPONSE_STRUC_SIZE)
    {
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
        dce2_smb_stats.v2_stinf_err_resp++;
    }
    else if (structure_size == SMB2_SET_INFO_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_SET_INFO_REQUEST_STRUC_SIZE,
            dce2_smb_stats.v2_stinf_req_hdr_err)

        const Smb2SetInfoRequestHdr* smb_set_info_hdr = (const Smb2SetInfoRequestHdr*)smb_data;
        const uint8_t* file_data =  (const uint8_t*)smb_set_info_hdr +
            SMB2_SET_INFO_REQUEST_STRUC_SIZE - 1;

        if (smb_set_info_hdr->file_info_class == SMB2_FILE_ENDOFFILE_INFO)
        {
            uint64_t file_size = alignedNtohq((const uint64_t*)file_data);
            uint64_t fileId_persistent = alignedNtohq(&(smb_set_info_hdr->fileId_persistent));

            DCE2_Smb2FileTracker* ftracker = ttr->findFtracker(fileId_persistent);
            if (ftracker)
            {
                ftracker->file_size = file_size;

                FileContext* file = get_smb_file_context(fileId_persistent);
                if (file)
                {
                    file->set_file_size(ftracker->file_size);
                }
            }
            else
                dce2_smb_stats.v2_stinf_req_ftrkr_misng++;
        }
        else
            dce2_smb_stats.v2_stinf_req_hdr_err++;
    }
    else if (structure_size != SMB2_SET_INFO_RESPONSE_STRUC_SIZE)
    {
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
    DCE2_Smb2RequestTracker* readtracker = nullptr;

    uint64_t offset = alignedNtohq((const uint64_t*)(&(smb_read_hdr->offset)));
    uint64_t fileId_persistent = alignedNtohq((const uint64_t*)(&(smb_read_hdr->fileId_persistent)));

    if (ssd->max_outstanding_requests > str->getTotalRequestsPending())
    {
         readtracker = new DCE2_Smb2RequestTracker(
             offset, fileId_persistent, nullptr, 0, nullptr);
         ttr->insertDataRtracker(message_id, readtracker);
    }
    else
    {
        dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats,
            ssd->sd);
        return;
    }

    DCE2_Smb2FileTracker* ftracker =  ttr->findFtracker(fileId_persistent);
    if (!ftracker) // compounded create request + read request case
    {
        ftracker = new DCE2_Smb2FileTracker(fileId_persistent, nullptr, 0);
        ttr->insertFtracker(fileId_persistent, ftracker);
    }

    if (ftracker->file_size and (offset > ftracker->file_size))
    {
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

    request = ttr->findDataRtracker(message_id);
    if (!request)
    {
        dce2_smb_stats.v2_read_rtrkr_misng++;
        return;
    }
    data_offset = alignedNtohs((const uint16_t*)(&(smb_read_hdr->data_offset)));
    if (data_offset + (const uint8_t*)smb_hdr > end)
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats, ssd->sd);
    }

    DCE2_Smb2FileTracker* ftracker =  ttr->findFtracker(request->get_file_id());
    if ( ftracker ) // file tracker can never be NULL for read response
    {
        ftracker->file_offset = request->get_offset();
        ttr->removeDataRtracker(message_id);
        ssd->ftracker_tcp = ftracker;

        DCE2_Smb2ProcessFileData(ssd, file_data, data_size, FILE_DOWNLOAD);
        ftracker->file_offset += data_size;

        uint32_t total_data_length = alignedNtohl((const uint32_t*)&(smb_read_hdr->length));
        debug_logf(dce_smb_trace, nullptr, "smbv2 total_data=%d data_size=%d ssd=%p\n", total_data_length,data_size,
           (void*)ssd);
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
        DCE2_Smb2RequestTracker* rtr = ttr->findDataRtracker(mid);
        if (rtr and rtr->get_file_id())
        {
            if (ssd->ftracker_tcp->file_id == rtr->get_file_id())
                ssd->ftracker_tcp = NULL;
            ttr->removeFtracker(rtr->get_file_id());
        }
        ttr->removeDataRtracker(mid);
        dce2_smb_stats.v2_read_err_resp++;
    }
    // Using structure size to decide whether it is response or request
    else if (structure_size == SMB2_READ_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_READ_REQUEST_STRUC_SIZE - 1,
            dce2_smb_stats.v2_read_req_hdr_err)
        DCE2_Smb2ReadRequest(ssd, (const Smb2ReadRequestHdr*)smb_data, end, str, ttr, mid);
    }
    else if (structure_size == SMB2_READ_RESPONSE_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_READ_RESPONSE_STRUC_SIZE - 1,
            dce2_smb_stats.v2_read_resp_hdr_err)

        DCE2_Smb2ReadResponse(ssd, smb_hdr, (const Smb2ReadResponseHdr*)smb_data, end, ttr, mid);
    }
    else
    {
        dce2_smb_stats.v2_read_inv_str_sz++;
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
    DCE2_Smb2RequestTracker* writetracker = nullptr;

    fileId_persistent = alignedNtohq((const uint64_t*)(&(smb_write_hdr->fileId_persistent)));

    if (ssd->max_outstanding_requests > str->getTotalRequestsPending())
    {
         writetracker = new DCE2_Smb2RequestTracker(
              0, fileId_persistent, nullptr, 0, nullptr);
         ttr->insertDataRtracker(mid, writetracker);
    }
    else
    {
        dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats,
            ssd->sd);
        return;
    }

    data_offset = alignedNtohs((const uint16_t*)(&(smb_write_hdr->data_offset)));
    if (data_offset + (const uint8_t*)smb_hdr > end)
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats, ssd->sd);
    }

    offset = alignedNtohq((const uint64_t*)(&(smb_write_hdr->offset)));
    DCE2_Smb2FileTracker* ftracker = ttr->findFtracker(fileId_persistent);
    if (ftracker) // file tracker can not be NULL here
    {
        if (ftracker->file_size and (offset > ftracker->file_size))
        {
            dce_alert(GID_DCE2, DCE2_SMB_INVALID_FILE_OFFSET, (dce2CommonStats*)&dce2_smb_stats,
                ssd->sd);
        }
        ftracker->file_offset = offset;
        ssd->ftracker_tcp = ftracker;
        DCE2_Smb2ProcessFileData(ssd, file_data, data_size, FILE_UPLOAD);
        ftracker->file_offset += data_size;
        uint32_t total_data_length = alignedNtohl((const uint32_t*)&(smb_write_hdr->length));
        debug_logf(dce_smb_trace, nullptr, "smbv2 total_data=%d data_size=%d\n",total_data_length,data_size);
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
        DCE2_Smb2RequestTracker* wtr = ttr->findDataRtracker(mid);
        if (wtr and wtr->get_file_id())
        {
            if (ssd->ftracker_tcp->file_id == wtr->get_file_id())
                ssd->ftracker_tcp = NULL;
            ttr->removeFtracker(wtr->get_file_id());
        }
        ttr->removeDataRtracker(mid);
        dce2_smb_stats.v2_wrt_err_resp++;
    }
    // Using structure size to decide whether it is response or request
    else if (structure_size == SMB2_WRITE_REQUEST_STRUC_SIZE)
    {
        SMB2_CHECK_HDR_ERROR(
            smb_data, end, SMB2_WRITE_REQUEST_STRUC_SIZE - 1,
            dce2_smb_stats.v2_wrt_req_hdr_err)
        DCE2_Smb2WriteRequest(ssd, smb_hdr, (const Smb2WriteRequestHdr*)smb_data, end, str, ttr, mid);
    }
    else if (structure_size == SMB2_WRITE_RESPONSE_STRUC_SIZE)
    {
        ttr->removeDataRtracker(mid);
    }
    else
    {
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
        DCE2_Smb2RemoveSidInSsd(ssd, sid);
    }
    else
    {
        dce2_smb_stats.v2_logoff_inv_str_sz++;
    }
}
