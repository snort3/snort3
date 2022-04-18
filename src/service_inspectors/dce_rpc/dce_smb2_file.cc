//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "dce_smb2.h"
#include "dce_smb2_session.h"
#include "dce_smb2_tree.h"

#include <mutex>
using namespace snort;

#define UNKNOWN_FILE_SIZE  (~0)

void Dce2Smb2FileTracker::accept_raw_data_from(Dce2Smb2SessionData* flow, uint64_t offset, Dce2Smb2FileTrackerPtr file_tracker)
{
    if (flow)
    {
        uint32_t current_flow_key = flow->get_flow_key();
        std::lock_guard<std::mutex> guard(flow_state_mutex);
        tcp_flow_state& current_flow_state = flow_state[current_flow_key];
        if ( (current_flow_state.pdu_state == DCE2_SMB_PDU_STATE__RAW_DATA) and
             (current_flow_state.file_offset == current_flow_state.max_offset))
        {
            current_flow_state.file_offset = offset;
        }

        current_flow_state.pdu_state = DCE2_SMB_PDU_STATE__RAW_DATA;
        flow->set_tcp_file_tracker(file_tracker);
    }
}
void Dce2Smb2FileTracker::stop_accepting_raw_data_from(uint32_t current_flow_key)
{
    std::lock_guard<std::mutex> guard(flow_state_mutex);
    tcp_flow_state& current_flow_state = flow_state[current_flow_key];
    if(current_flow_state.file_offset == current_flow_state.max_offset)
        current_flow_state.pdu_state = DCE2_SMB_PDU_STATE__COMMAND;
}

inline void Dce2Smb2FileTracker::file_detect()
{
    DetectionEngine::detect(DetectionEngine::get_current_packet());
    dce2_detected = 1;
}

std::pair<bool, Dce2Smb2SessionData*> Dce2Smb2FileTracker::update_processing_flow(
    Dce2Smb2SessionData* current_flow,Dce2Smb2SessionTrackerPtr session_tracker)
{
    std::lock_guard<std::mutex> guard(process_file_mutex);
    bool switched = false;
    Dce2Smb2SessionData* processing_flow;
    if (session_tracker)
        processing_flow = session_tracker->get_flow(file_flow_key);
    else
        processing_flow = parent_tree->get_parent()->get_flow(file_flow_key);
    
    if (!processing_flow)
    {
        switched = true;
        if (current_flow)
            processing_flow = current_flow;
        else
        {
            Flow* flow = DetectionEngine::get_current_packet()->flow;
            Dce2SmbFlowData* current_flow_data = (Dce2SmbFlowData*)(flow->get_flow_data(Dce2SmbFlowData::inspector_id));
            processing_flow = (Dce2Smb2SessionData*)current_flow_data->get_smb_session_data();
        }
        file_flow_key = processing_flow->get_flow_key();
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, GET_CURRENT_PACKET, 
            "updating the processing flow key to %u\n", file_flow_key);
    }
    return std::make_pair(switched, processing_flow);
}

void Dce2Smb2FileTracker::set_info(char* file_name_v, uint16_t name_len_v, uint64_t size_v)
{
    if (file_name_v and name_len_v and !file_name)
    {
        file_name = (char*)snort_alloc(name_len_v + 1);
        memcpy(file_name, file_name_v, name_len_v);
        file_name_len = name_len_v;
        file_name_hash = str_to_hash((uint8_t*)file_name, file_name_len);
    }
    file_size = size_v;
    auto updated_flow = update_processing_flow();
    Flow* flow = updated_flow.second->get_tcp_flow();
    {
        std::lock_guard<std::mutex> guard(process_file_mutex);
        FileContext* file = get_smb_file_context(flow, file_name_hash, file_id, true);
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, GET_CURRENT_PACKET,
            "set file info: file size %"
            PRIu64 " fid %" PRIu64 " file_name_hash %" PRIu64 " file context "
            "%sfound\n", size_v, file_id, file_name_hash, (file ? "" : "not "));
        if (file)
        {
            ignore = false;
            if (file->verdict == FILE_VERDICT_UNKNOWN)
            {
                if ((file_name_v and name_len_v) or updated_flow.first)
                    file->set_file_name(file_name, file_name_len);
                file->set_file_size(size_v ? size_v : UNKNOWN_FILE_SIZE);
            }
        }
    }
}

bool Dce2Smb2FileTracker::close(const uint32_t current_flow_key)
{
    flow_state_mutex.lock();
    uint64_t file_offset = flow_state[current_flow_key].file_offset;
    flow_state_mutex.unlock();
    if (!ignore and !file_size and file_offset)
    {
        file_size = file_offset;
        Dce2Smb2SessionData* processing_flow = update_processing_flow().second;
        Flow* flow = processing_flow->get_tcp_flow();
        {
            std::lock_guard<std::mutex> guard(process_file_mutex);
            FileContext* file = get_smb_file_context(flow, file_name_hash, file_id, false);
            if (file)
                file->set_file_size(file_size);
        }
        Dce2Smb2SessionTrackerPtr ses_ptr = processing_flow->find_session(session_id);
        return (!process_data(current_flow_key, nullptr, 0,ses_ptr));
    }
    return true;
}

bool Dce2Smb2FileTracker::process_data(const uint32_t current_flow_key, const uint8_t* file_data,
    uint32_t data_size, const uint64_t offset, uint64_t max_offset)
{
    flow_state_mutex.lock();
    tcp_flow_state& current_flow_state = flow_state[current_flow_key];
    current_flow_state.file_offset = offset;
    current_flow_state.max_offset = offset + max_offset;
    flow_state_mutex.unlock();
    Dce2Smb2SessionTracker* sess = parent_tree->get_parent();
    if (parent_tree->get_share_type() != SMB2_SHARE_TYPE_DISK)
    {
        Dce2Smb2SessionData* current_flow = nullptr;
        if (sess)
        {
            parent_tree->get_parent()->set_do_not_delete(true);
            current_flow = parent_tree->get_parent()->get_flow(current_flow_key);
            if (!current_flow)
            {
                parent_tree->get_parent()->set_do_not_delete(false);
                return false;
            }
        }
        else
        {
            return false;
        }

        if (data_size > UINT16_MAX)
        {
            data_size = UINT16_MAX;
        }
        if (parent_tree->get_cotracker()) 
	{
            sess->co_tracker_mutex.lock();
            DCE2_CoProcess(current_flow->get_dce2_session_data(), parent_tree->get_cotracker(),
                file_data, data_size);
            sess->co_tracker_mutex.unlock(); 
	}
        parent_tree->get_parent()->set_do_not_delete(false);
        return true;
    }
    Dce2Smb2SessionData *current_flow = sess->get_flow(current_flow_key);
    Dce2Smb2SessionTrackerPtr ses_ptr = current_flow->find_session(session_id);
    return process_data(current_flow_key, file_data, data_size,ses_ptr);
}

bool Dce2Smb2FileTracker::process_data(const uint32_t current_flow_key, const uint8_t* file_data,
    uint32_t data_size,Dce2Smb2SessionTrackerPtr session_tracker)
{
    Dce2Smb2SessionData *current_flow;
    if (session_tracker)
    {
           session_tracker->set_do_not_delete(true);
           current_flow = session_tracker->get_flow(current_flow_key); 
    }
    else 
       return false;
    
    if (!current_flow) 
    {
       session_tracker->set_do_not_delete(false);
       return true; 
    }

    int64_t file_detection_depth = current_flow->get_smb_file_depth();
    int64_t detection_size = 0;
    Packet* p = DetectionEngine::get_current_packet();
    flow_state_mutex.lock();
    uint64_t file_offset = flow_state[current_flow_key].file_offset;
    flow_state_mutex.unlock();

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
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, p,
            "file name not set , ignored\n");
        session_tracker->set_do_not_delete(false);
        return true;
    }

    if (file_size and file_offset > file_size)
    {
	    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, p, "file_process: bad offset\n");
        dce_alert(GID_DCE2, DCE2_SMB_INVALID_FILE_OFFSET, (dce2CommonStats*)
            &dce2_smb_stats, *(current_flow->get_dce2_session_data()));
    }

    auto updated_flow = update_processing_flow(current_flow, session_tracker);
    Dce2Smb2SessionData* processing_flow = updated_flow.second;

    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,"file_process fid %" PRIu64 " data_size %"
        PRIu32 " offset %" PRIu64 "\n", file_id, data_size, file_offset);
    {
        std::lock_guard<std::mutex> guard(process_file_mutex);
        FileFlows* file_flows = FileFlows::get_file_flows(processing_flow->get_tcp_flow());

        if (!file_flows)
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL, p, "file_flows not found\n");
            session_tracker->set_do_not_delete(false);
            return true;
        }

        if (updated_flow.first)
        {
            // update the new file context in case of flow switch
            FileContext* file = file_flows->get_file_context(file_name_hash, true, file_id);
            file->set_file_name(file_name, file_name_len);
            file->set_file_size(file_size.load() ? file_size.load() : UNKNOWN_FILE_SIZE);
        }

        bool continue_processing = file_flows->file_process(p, file_name_hash, file_data, data_size,
           file_offset, direction, file_id);
    
        if (!continue_processing)
        {
	        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p, "file_process completed\n");
            session_tracker->set_do_not_delete(false);
            return false;
        }
    }

    file_offset += data_size;
    flow_state_mutex.lock();
    flow_state[current_flow_key].file_offset = file_offset;
    flow_state_mutex.unlock();
    session_tracker->set_do_not_delete(false);
    return true;
}

Dce2Smb2FileTracker::~Dce2Smb2FileTracker(void)
{
    if (file_name)
        snort_free((void*)file_name);

    file_name = nullptr;
    parent_tree = nullptr;
}

