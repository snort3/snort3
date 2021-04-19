//--------------------------------------------------------------------------
// Copyright (C) 2020-2021 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb2_tree.cc author Dipta Pandit <dipandit@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb2_tree.h"

#include "dce_smb2_session.h"

using namespace snort;

#define SMB2_CREATE_DURABLE_RECONNECT "DHnC"
#define SMB2_CREATE_DURABLE_RECONNECT_V2 "DH2C"

uint64_t Smb2Mid(const Smb2Hdr* hdr)
{
    return alignedNtohq(&(hdr->message_id));
}

Dce2Smb2FileTracker* Dce2Smb2TreeTracker::find_file(uint64_t file_id)
{
    auto it_file = opened_files.find(file_id);
    if (it_file != opened_files.end())
        return it_file->second;
    return nullptr;
}

void Dce2Smb2TreeTracker::close_file(uint64_t file_id, bool destroy)
{
    auto it_file = opened_files.find(file_id);
    if (it_file != opened_files.end())
    {
        Dce2Smb2FileTracker* file = it_file->second;
        if (opened_files.erase(file_id) and destroy)
            delete file;
    }
}

Dce2Smb2RequestTracker* Dce2Smb2TreeTracker::find_request(uint64_t message_id)
{
    auto request_it = active_requests.find(message_id);
    return (request_it == active_requests.end()) ?
        nullptr : request_it->second;
}

bool Dce2Smb2TreeTracker::remove_request(uint64_t message_id)
{
    auto request_it = active_requests.find(message_id);
    if (request_it != active_requests.end())
    {
        delete request_it->second;
        return active_requests.erase(message_id);
    }
    return false;
}

void Dce2Smb2TreeTracker::process_set_info_request(const Smb2Hdr* smb_header)
{
    const uint8_t* smb_data = (const uint8_t*)smb_header + SMB2_HEADER_LENGTH;
    const Smb2SetInfoRequestHdr* set_info_hdr = (const Smb2SetInfoRequestHdr*)smb_data;

    if (set_info_hdr->file_info_class == SMB2_FILE_ENDOFFILE_INFO)
    {
        uint64_t file_size = alignedNtohq((const uint64_t*)((const uint8_t*)
            set_info_hdr + SMB2_SET_INFO_REQUEST_STRUC_SIZE - 1));
        uint64_t file_id = alignedNtohq(&(set_info_hdr->fileId_persistent));
        Dce2Smb2FileTracker* file_tracker = find_file(file_id);
        if (file_tracker)
            file_tracker->set_info(nullptr, 0, file_size);
        else
        {
            dce2_smb_stats.v2_stinf_req_ftrkr_misng++;
            debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "%s_REQ: ftracker missing\n",
                smb2_command_string[SMB2_COM_SET_INFO]);
        }
    }
    else
    {
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "%s_REQ: header error\n",
            smb2_command_string[SMB2_COM_SET_INFO]);
        dce2_smb_stats.v2_stinf_req_hdr_err++;
    }
}

void Dce2Smb2TreeTracker::process_close_request(const Smb2Hdr* smb_header)
{
    const uint8_t* smb_data = (const uint8_t*)smb_header + SMB2_HEADER_LENGTH;
    uint64_t file_id = alignedNtohq(&(((const Smb2CloseRequestHdr*)
        smb_data)->fileId_persistent));
    Dce2Smb2FileTracker* file_tracker = find_file(file_id);
    if (!file_tracker)
    {
        dce2_smb_stats.v2_cls_req_ftrkr_misng++;
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "%s_REQ: ftracker missing %" PRIu64 "\n",
            smb2_command_string[SMB2_COM_CLOSE], file_id);
        return;
    }
    if (file_tracker->close())
        close_file(file_id);

    if (share_type != SMB2_SHARE_TYPE_DISK)
        DCE2_CoCleanTracker(co_tracker);
}

uint64_t Dce2Smb2TreeTracker::get_durable_file_id(
    const Smb2CreateRequestHdr* smb_create_hdr, const uint8_t* end)
{
    const uint8_t* data = (const uint8_t*)smb_create_hdr +
        alignedNtohl(&smb_create_hdr->create_contexts_offset) - SMB2_HEADER_LENGTH;
    uint32_t remaining = alignedNtohl(&smb_create_hdr->create_contexts_length);

    while (remaining > sizeof(Smb2CreateContextHdr) and data < end)
    {
        const Smb2CreateContextHdr* context = (const Smb2CreateContextHdr*)data;
        uint32_t next = alignedNtohl(&context->next);
        uint16_t name_offset = alignedNtohs(&context->name_offset);
        uint16_t name_length = alignedNtohs(&context->name_length);
        uint16_t data_offset = alignedNtohs(&context->data_offset);
        uint32_t data_length =  alignedNtohl(&context->data_length);

        /* Check for general error condition */
        if (((next & 0x7) != 0) or (next > remaining) or (name_offset != 16) or
            (name_length != 4) or (name_offset + name_length > remaining) or
            ((data_offset & 0x7) != 0) or
            (data_offset and (data_offset < name_offset + name_length)) or
            (data_offset > remaining) or (data_offset + data_length > remaining))
        {
            return 0;
        }

        if ((strncmp((const char*)context+name_offset,
            SMB2_CREATE_DURABLE_RECONNECT_V2, name_length) == 0) or
            (strncmp((const char*)context+name_offset,
            SMB2_CREATE_DURABLE_RECONNECT, name_length) == 0))
        {
            return alignedNtohq((const uint64_t*)(((const uint8_t*)context) +
                data_offset));
        }

        if (!next)
            break;

        data += next;
        remaining -= next;
    }
    return 0;
}

void Dce2Smb2TreeTracker::process_create_response(uint64_t message_id,
    const Smb2Hdr* smb_header)
{
    const uint8_t* smb_data = (const uint8_t*)smb_header + SMB2_HEADER_LENGTH;
    const Smb2CreateResponseHdr* create_res_hdr = (const Smb2CreateResponseHdr*)smb_data;
    uint64_t file_size = 0;
    uint64_t file_id = alignedNtohq((const uint64_t*)(&(create_res_hdr->fileId_persistent)));
    if (create_res_hdr->end_of_file)
        file_size = alignedNtohq((const uint64_t*)(&(create_res_hdr->end_of_file)));
    if (create_res_hdr->file_attributes & SMB2_CREATE_RESPONSE_DIRECTORY)
    {
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "%s_RESP: not processing for directory\n",
            smb2_command_string[SMB2_COM_CREATE]);
        close_file(file_id);
    }
    else
    {
        Dce2Smb2RequestTracker* create_request = find_request(message_id);
        if (create_request)
        {
            Dce2Smb2FileTracker* file_tracker = find_file(file_id);
            if (!file_tracker)
            {
                file_tracker = new Dce2Smb2FileTracker(file_id, this);
                opened_files.insert(std::make_pair(file_id, file_tracker));
            }
            if (share_type == SMB2_SHARE_TYPE_DISK)
            {
                file_tracker->set_info(create_request->get_file_name(),
                    create_request->get_file_name_size(), file_size, true);
                create_request->reset_file_name();
            }
        }
        else
        {
            debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "%s_RESP: req tracker missing\n",
                smb2_command_string[SMB2_COM_CREATE]);
            dce2_smb_stats.v2_crt_rtrkr_misng++;
        }
    }
}

void Dce2Smb2TreeTracker::process_create_request(uint64_t message_id,
    const Smb2Hdr* smb_header, const uint8_t* end)
{
    const uint8_t* smb_data = (const uint8_t*)smb_header + SMB2_HEADER_LENGTH;
    const Smb2CreateRequestHdr* create_req_hdr = (const Smb2CreateRequestHdr*)smb_data;
    if (alignedNtohs(&(create_req_hdr->name_offset)) <= SMB2_HEADER_LENGTH)
    {
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "%s_REQ: name_offset %" PRIu16 "\n",
            smb2_command_string[SMB2_COM_CREATE], create_req_hdr->name_offset);
        dce2_smb_stats.v2_crt_req_hdr_err++;
        return;
    }
    const uint8_t* file_name_offset = (const uint8_t*)smb_header +
        create_req_hdr->name_offset;
    uint16_t file_name_size = alignedNtohs(&(create_req_hdr->name_length));
    if (!file_name_size or (file_name_offset >= end) or
        (file_name_offset + file_name_size > end))
    {
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
            "%s_REQ: invalid file name data seen with size %" PRIu16 "\n",
            smb2_command_string[SMB2_COM_CREATE], file_name_size);
        dce2_smb_stats.v2_crt_inv_file_data++;
        return;
    }

    uint16_t name_len = 0;
    char* file_name = get_smb_file_name(file_name_offset, file_name_size, true, &name_len);
    //keep a request tracker with the available info
    Dce2Smb2RequestTracker* create_request = new Dce2Smb2RequestTracker(file_name, name_len);
    store_request(message_id, create_request);
    //check if file_id is available form a durable reconnect request.
    //if present we can create a file tracker right now.
    //mostly this is the case for compound request.
    uint64_t file_id = get_durable_file_id(create_req_hdr, end);
    if (file_id)
    {
        Dce2Smb2FileTracker* file_tracker = find_file(file_id);
        if (!file_tracker)
        {
            file_tracker = new Dce2Smb2FileTracker(file_id, this);
            if (share_type == SMB2_SHARE_TYPE_DISK)
            {
                file_tracker->set_info(file_name, name_len, 0, true);
                create_request->reset_file_name();
            }
            opened_files.insert(std::make_pair(file_id, file_tracker));
        }
    }
}

void Dce2Smb2TreeTracker::process_read_response(uint64_t message_id,
    const Smb2Hdr* smb_header, const uint8_t* end)
{
    const uint8_t* smb_data = (const uint8_t*)smb_header + SMB2_HEADER_LENGTH;
    const Smb2ReadResponseHdr* read_resp_hdr = (const Smb2ReadResponseHdr*)smb_data;

    Dce2Smb2RequestTracker* read_request = find_request(message_id);
    if (!read_request)
    {
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
            "SMB2_COM_READ_RESP: request tracker missing\n");
        dce2_smb_stats.v2_read_rtrkr_misng++;
        return;
    }
    uint16_t data_offset = alignedNtohs((const uint16_t*)(&(read_resp_hdr->data_offset)));
    Dce2Smb2SessionData* current_flow = parent_session->get_current_flow();
    if (data_offset + (const uint8_t*)smb_header > end)
    {
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "SMB2_COM_READ_RESP: bad offset\n");
        if (current_flow)
            dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats,
                *current_flow->get_dce2_session_data());
    }
    Dce2Smb2FileTracker* file_tracker = find_file(read_request->get_file_id());
    if (file_tracker)
    {
        const uint8_t* file_data =  (const uint8_t*)read_resp_hdr +
            SMB2_READ_RESPONSE_STRUC_SIZE - 1;
        int data_size = end - file_data;
        if (file_tracker->process_data(file_data, data_size, read_request->get_offset()))
        {
            if ((uint32_t)data_size < alignedNtohl((const uint32_t*)&(read_resp_hdr->length)))
            {
                file_tracker->accept_raw_data_from(current_flow);
            }
        }
        else
            close_file(file_tracker->get_file_id());
    }
    else
    {
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
            "SMB2_COM_READ_RESP: file tracker missing\n");
    }
}

void Dce2Smb2TreeTracker::process_read_request(uint64_t message_id,
    const Smb2Hdr* smb_header)
{
    const uint8_t* smb_data = (const uint8_t*)smb_header + SMB2_HEADER_LENGTH;
    const Smb2ReadRequestHdr* read_req_hdr = (const Smb2ReadRequestHdr*)smb_data;
    uint64_t file_id = alignedNtohq((const uint64_t*)(&(read_req_hdr->fileId_persistent)));
    uint64_t offset = alignedNtohq((const uint64_t*)(&(read_req_hdr->offset)));
    Dce2Smb2RequestTracker* read_request = new Dce2Smb2RequestTracker(file_id, offset);
    store_request(message_id, read_request);
}

void Dce2Smb2TreeTracker::process_write_request(uint64_t message_id,
    const Smb2Hdr* smb_header, const uint8_t* end)
{
    const uint8_t* smb_data = (const uint8_t*)smb_header + SMB2_HEADER_LENGTH;
    const Smb2WriteRequestHdr* write_req_hdr = (const Smb2WriteRequestHdr*)smb_data;
    uint64_t file_id = alignedNtohq((const uint64_t*)(&(write_req_hdr->fileId_persistent)));
    Dce2Smb2SessionData* current_flow = parent_session->get_current_flow();
    if ((alignedNtohs((const uint16_t*)(&(write_req_hdr->data_offset))) +
        (const uint8_t*)smb_header > end) and current_flow)
    {
        dce_alert(GID_DCE2, DCE2_SMB_BAD_OFF, (dce2CommonStats*)&dce2_smb_stats,
            *current_flow->get_dce2_session_data());
    }
    //track this request to clean up opened file in case of error response
    Dce2Smb2RequestTracker* write_request = new Dce2Smb2RequestTracker(file_id);
    store_request(message_id, write_request);
    const uint8_t* file_data = (const uint8_t*)write_req_hdr + SMB2_WRITE_REQUEST_STRUC_SIZE - 1;
    Dce2Smb2FileTracker* file_tracker = find_file(file_id);
    if (file_tracker)
    {
        file_tracker->set_direction(FILE_UPLOAD);
        int data_size = end - file_data;
        uint64_t offset = alignedNtohq((const uint64_t*)(&(write_req_hdr->offset)));
        if (file_tracker->process_data(file_data, data_size, offset))
        {
            if ((uint32_t)data_size < alignedNtohl((const uint32_t*)&(write_req_hdr->length)))
            {
                file_tracker->accept_raw_data_from(current_flow);
            }
        }
        else
            close_file(file_tracker->get_file_id());
    }
    else
    {
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
            "SMB2_COM_WRITE_REQ: file tracker missing\n");
    }
}

void Dce2Smb2TreeTracker::process_ioctl_command(uint8_t command_type, const Smb2Hdr* smb_header,
    const uint8_t* end)
{
    const uint8_t* smb_data = (const uint8_t*)smb_header + SMB2_HEADER_LENGTH;
    const uint8_t structure_size = (command_type == SMB2_CMD_TYPE_REQUEST) ?
        SMB2_IOCTL_REQUEST_STRUC_SIZE : SMB2_IOCTL_RESPONSE_STRUC_SIZE;

    const uint8_t* file_data = (const uint8_t*)smb_data + structure_size - 1;
    int data_size = end - file_data;
    Dce2Smb2SessionData* current_flow = parent_session->get_current_flow();
    if (data_size > UINT16_MAX)
    {
        data_size = UINT16_MAX;
    }

    DCE2_CoProcess(current_flow->get_dce2_session_data(), co_tracker, file_data, data_size);
}

void Dce2Smb2TreeTracker::process(uint16_t command, uint8_t command_type,
    const Smb2Hdr* smb_header, const uint8_t* end)
{
    Dce2Smb2SessionData* current_flow = parent_session->get_current_flow();
    if (SMB2_CMD_TYPE_REQUEST == command_type and current_flow and
        active_requests.size() >= current_flow->get_max_outstanding_requests())
    {
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
            "%s_REQ: max req exceeded\n", smb2_command_string[command]);
        dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats,
            *current_flow->get_dce2_session_data());

        return;
    }
    uint64_t message_id = Smb2Mid(smb_header);

    switch (command)
    {
    case SMB2_COM_CREATE:
        if (SMB2_CMD_TYPE_ERROR_RESPONSE == command_type)
        {
            dce2_smb_stats.v2_crt_err_resp++;
            debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
                "%s_RESP: error\n", smb2_command_string[command]);
        }
        else if (SMB2_CMD_TYPE_REQUEST == command_type)
        {
            if (SMB2_SHARE_TYPE_DISK != share_type)
            {
                debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "%s_REQ:"
                    "processed for ipc share\n", smb2_command_string[command]);
                dce2_smb_stats.v2_crt_req_ipc++;
            }
            process_create_request(message_id, smb_header, end);
        }
        else if (SMB2_CMD_TYPE_RESPONSE == command_type)
            process_create_response(message_id, smb_header);
        break;
    case SMB2_COM_CLOSE:
        process_close_request(smb_header);
        break;
    case SMB2_COM_SET_INFO:
        process_set_info_request(smb_header);
        break;
    case SMB2_COM_READ:
        if (SMB2_CMD_TYPE_ERROR_RESPONSE == command_type)
        {
            dce2_smb_stats.v2_read_err_resp++;
            debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
                "%s_RESP: error\n", smb2_command_string[command]);
            Dce2Smb2RequestTracker* request = find_request(message_id);
            if (request)
                close_file(request->get_file_id());
        }
        else if (SMB2_CMD_TYPE_REQUEST == command_type)
            process_read_request(message_id, smb_header);
        else if (SMB2_CMD_TYPE_RESPONSE == command_type)
            process_read_response(message_id, smb_header, end);
        break;
    case SMB2_COM_WRITE:
        if (SMB2_CMD_TYPE_ERROR_RESPONSE == command_type)
        {
            dce2_smb_stats.v2_wrt_err_resp++;
            debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
                "%s_RESP: error\n", smb2_command_string[command]);
            Dce2Smb2RequestTracker* request = find_request(message_id);
            if (request)
                close_file(request->get_file_id());
        }
        else if (SMB2_CMD_TYPE_REQUEST == command_type)
            process_write_request(message_id, smb_header, end);
        break;
    case SMB2_COM_IOCTL:
        if (SMB2_CMD_TYPE_ERROR_RESPONSE == command_type)
        {
            debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
                "%s_RESP: error\n", smb2_command_string[command]);
        }
        else if (SMB2_SHARE_TYPE_DISK != share_type)
        {
            process_ioctl_command(command_type, smb_header, end);
        }
        break;
    }
    if (SMB2_CMD_TYPE_RESPONSE == command_type or SMB2_CMD_TYPE_ERROR_RESPONSE == command_type)
        remove_request(message_id);
}

Dce2Smb2TreeTracker::~Dce2Smb2TreeTracker(void)
{
    debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
        "tree tracker %" PRIu32 " terminating\n", tree_id);

    if (co_tracker != nullptr)
    {
        DCE2_CoCleanTracker(co_tracker);
        snort_free((void*)co_tracker);
        co_tracker = nullptr;
    }
    if (active_requests.size())
    {
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
            "cleanup pending requests for below MIDs:\n");
        for (auto it_request : active_requests)
        {
            debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
                "mid %" PRIu64 "\n", it_request.first);
            delete it_request.second;
        }
    }

    auto it_file = opened_files.begin();
    while (it_file != opened_files.end())
    {
        Dce2Smb2FileTracker* file = it_file->second;
        it_file = opened_files.erase(it_file);
        delete file;
    }
    parent_session->disconnect_tree(tree_id);
    memory::MemoryCap::update_deallocations(sizeof(*this));
}

