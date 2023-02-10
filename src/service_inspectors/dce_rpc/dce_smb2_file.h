//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb2_file.h author Dipta Pandit <dipandit@cisco.com>

#ifndef DCE_SMB2_FILE_H
#define DCE_SMB2_FILE_H

// This provides file tracker for SMBv2

#include "dce_smb2.h"
#include <atomic>

class Dce2Smb2TreeTracker;
using Dce2Smb2TreeTrackerPtr = std::shared_ptr<Dce2Smb2TreeTracker>;

typedef struct _tcp_flow_state
{
    Dce2SmbPduState pdu_state;
    uint64_t file_offset;
    uint64_t max_offset;
} tcp_flow_state;

class Dce2Smb2FileTracker
{
public:

    Dce2Smb2FileTracker() = delete;
    Dce2Smb2FileTracker(const Dce2Smb2FileTracker& arg) = delete;
    Dce2Smb2FileTracker& operator=(const Dce2Smb2FileTracker& arg) = delete;

    Dce2Smb2FileTracker(uint64_t file_idv, const uint32_t flow_key, Dce2Smb2TreeTrackerPtr p_tree,
        uint64_t sid) :
        ignore(true), file_name_len(0), file_flow_key(flow_key),
        file_id(file_idv), file_size(0), file_name_hash(0), file_name(nullptr),
        direction(FILE_DOWNLOAD), parent_tree(p_tree), session_id(sid)
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
            "file tracker %" PRIu64 " created\n", file_id);
    }

    ~Dce2Smb2FileTracker();
    bool process_data(const uint32_t, const uint8_t*, uint32_t, const uint64_t, uint64_t);
    bool process_data(const uint32_t, const uint8_t*, uint32_t, Dce2Smb2SessionTrackerPtr);
    bool close(const uint32_t);
    void set_info(char*, uint16_t, uint64_t);
    void accept_raw_data_from(Dce2Smb2SessionData*, uint64_t, Dce2Smb2FileTrackerPtr);
    bool accepting_raw_data_from(uint32_t current_flow_key)
    {
        std::lock_guard<std::mutex> guard(flow_state_mutex);
        return (flow_state[current_flow_key].pdu_state == DCE2_SMB_PDU_STATE__RAW_DATA);
    }

    void stop_accepting_raw_data_from(uint32_t);

    void set_direction(FileDirection dir) { direction = dir; }
    Dce2Smb2TreeTrackerPtr get_parent() { return parent_tree; }
    void set_parent(Dce2Smb2TreeTrackerPtr pt) { parent_tree = pt; }
    uint64_t get_file_id() { return file_id; }
    uint64_t get_file_name_hash() { return file_name_hash; }
    uint64_t get_session_id() { return session_id; }
    std::unordered_map<uint32_t, tcp_flow_state, std::hash<uint32_t> > get_flow_state_map()
    {
        return flow_state;
    }

    uint32_t get_flow_key()
    {
        return file_flow_key;
    }

    void set_flow_key(uint32_t key)
    {
        file_flow_key = key;
    }

private:
    void file_detect();
    std::pair<bool, Dce2Smb2SessionData*> update_processing_flow(Dce2Smb2SessionData* = nullptr,
        Dce2Smb2SessionTrackerPtr session_tracker = nullptr);
    bool ignore;
    uint16_t file_name_len;
    uint32_t file_flow_key;
    uint64_t file_id;
    std::atomic<uint64_t> file_size;
    uint64_t file_name_hash;
    char* file_name;
    FileDirection direction;
    Dce2Smb2TreeTrackerPtr parent_tree;
    std::unordered_map<uint32_t, tcp_flow_state, std::hash<uint32_t> > flow_state;
    uint64_t session_id;
    std::mutex process_file_mutex;
    std::mutex flow_state_mutex;
};

using Dce2Smb2FileTrackerPtr = std::shared_ptr<Dce2Smb2FileTracker>;
using Dce2Smb2FileTrackerMap =
        std::unordered_map<uint64_t, Dce2Smb2FileTrackerPtr, std::hash<uint64_t> >;

#endif

