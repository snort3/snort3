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

// dce_smb2_file.cc author Dipta Pandit <dipandit@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb2_file.h"

#include "file_api/file_flows.h"
#include "hash/hash_key_operations.h"

#include "dce_co.h"
#include "dce_smb2_session.h"
#include "dce_smb2_tree.h"

using namespace snort;

#define UNKNOWN_FILE_SIZE  (~0)

void Dce2Smb2FileTracker::accept_raw_data_from(Dce2Smb2SessionData* flow)
{
    if (flow)
    {
        smb2_pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
        flow->set_tcp_file_tracker(this);
    }
}

inline void Dce2Smb2FileTracker::file_detect()
{
    DetectionEngine::detect(DetectionEngine::get_current_packet());
    dce2_detected = 1;
}

void Dce2Smb2FileTracker::set_info(char* file_name_v, uint16_t name_len_v,
    uint64_t size_v, bool create)
{
    if (file_name_v and name_len_v)
    {
        file_name = file_name_v;
        file_name_len = name_len_v;
        file_name_hash = str_to_hash((uint8_t*)file_name, file_name_len);
    }
    file_size = size_v;
    FileContext* file = get_smb_file_context(file_name_hash, file_id, create);
    debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "set file info: file size %"
        PRIu64 " fid %" PRIu64 " file_name_hash %" PRIu64 " file context "
        "%sfound\n", file_size, file_id, file_name_hash, (file ? "" : "not "));
    if (file)
    {
        ignore = false;
        if (file->verdict == FILE_VERDICT_UNKNOWN)
        {
            if (file_name_v and name_len_v)
                file->set_file_name(file_name, file_name_len);
            file->set_file_size(file_size ? file_size : UNKNOWN_FILE_SIZE);
        }
    }
}

bool Dce2Smb2FileTracker::close()
{
    if (!ignore and !file_size and file_offset)
    {
        file_size = file_offset;
        FileContext* file =
            get_smb_file_context(file_name_hash, file_id, false);
        if (file)
            file->set_file_size(file_size);
        return (!process_data(nullptr, 0));
    }
    return true;
}

bool Dce2Smb2FileTracker::process_data(const uint8_t* file_data,
    uint32_t data_size, uint64_t offset)
{
    file_offset = offset;
    return process_data(file_data, data_size);
}

bool Dce2Smb2FileTracker::process_data(const uint8_t* file_data,
    uint32_t data_size)
{
    Dce2Smb2SessionData* current_flow = parent_tree->get_parent()->get_current_flow();

    if (parent_tree->get_share_type() != SMB2_SHARE_TYPE_DISK)
    {
        if (data_size > UINT16_MAX)
        {
            data_size = UINT16_MAX;
        }
        DCE2_CoProcess(current_flow->get_dce2_session_data(), get_parent()->get_cotracker(),
            file_data, data_size);
        return true;
    }

    int64_t file_detection_depth = current_flow->get_smb_file_depth();
    int64_t detection_size = 0;

    if (file_detection_depth == 0)
        detection_size = data_size;
    else if ( file_offset < (uint64_t)file_detection_depth)
    {
        if ( file_detection_depth - file_offset < data_size )
            detection_size = file_detection_depth - file_offset;
        else
            detection_size = data_size;
    }

    if (detection_size)
    {
        set_file_data(file_data, (detection_size > UINT16_MAX) ?
            UINT16_MAX : (uint16_t)detection_size);
        file_detect();
    }

    if (ignore)
        return true;

    Packet* p = DetectionEngine::get_current_packet();

    if (file_size and file_offset > file_size)
    {
        debug_logf(dce_smb_trace, p, "file_process: bad offset\n");
        dce_alert(GID_DCE2, DCE2_SMB_INVALID_FILE_OFFSET, (dce2CommonStats*)
            &dce2_smb_stats, *(current_flow->get_dce2_session_data()));
    }

    debug_logf(dce_smb_trace, p, "file_process fid %" PRIu64 " data_size %"
        PRIu32 " offset %" PRIu64 "\n", file_id, data_size, file_offset);

    FileFlows* file_flows = FileFlows::get_file_flows(p->flow);

    if (!file_flows)
        return true;

    if (!file_flows->file_process(p, file_name_hash, file_data, data_size,
        file_offset, direction, file_id))
    {
        debug_logf(dce_smb_trace, p, "file_process completed\n");
        return false;
    }

    file_offset += data_size;
    return true;
}

Dce2Smb2FileTracker::~Dce2Smb2FileTracker(void)
{
    debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
        "file tracker %" PRIu64 " file name hash %" PRIu64 " terminating\n", file_id, file_name_hash);

    if (file_name)
        snort_free((void*)file_name);

    Dce2Smb2SessionDataMap attached_flows = parent_tree->get_parent()->get_attached_flows();

    for (auto it_flow : attached_flows)
    {
        FileFlows* file_flows = FileFlows::get_file_flows(it_flow.second->get_flow(), false);
        if (file_flows)
            file_flows->remove_processed_file_context(file_name_hash, file_id);
        it_flow.second->reset_matching_tcp_file_tracker(this);
    }

    parent_tree->close_file(file_id, false);

    memory::MemoryCap::update_deallocations(sizeof(*this));
}

