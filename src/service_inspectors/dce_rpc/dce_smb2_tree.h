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

// dce_smb2_tree.h author Dipta Pandit <dipandit@cisco.com>

#ifndef DCE_SMB2_TREE_H
#define DCE_SMB2_TREE_H

// This provides tree trackers for SMBv2.
// Tree trackers are used to identify and track an opened share

#include "dce_co.h"
#include "dce_smb2.h"
#include "dce_smb2_file.h"
#include "dce_smb2_request.h"

using Dce2Smb2RequestTrackerPtr = std::shared_ptr<Dce2Smb2RequestTracker>;

uint64_t Smb2Mid(const Smb2Hdr* hdr);

class Dce2Smb2SessionTracker;

class Dce2Smb2TreeTracker
{
public:
    Dce2Smb2TreeTracker() = delete;
    Dce2Smb2TreeTracker(const Dce2Smb2TreeTracker&) = delete;
    Dce2Smb2TreeTracker& operator=(const Dce2Smb2TreeTracker&) = delete;

    Dce2Smb2TreeTracker(uint32_t tree_id_v, Dce2Smb2SessionTracker* p_session, uint8_t sharetype)
        : tree_id(tree_id_v), share_type(sharetype), parent_session(p_session)
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
            GET_CURRENT_PACKET, "tree tracker %" PRIu32 " created\n", tree_id);
        if (share_type != SMB2_SHARE_TYPE_DISK)
        {
            co_tracker = (DCE2_CoTracker*)snort_calloc(sizeof(DCE2_CoTracker));
            DCE2_CoInitTracker(co_tracker);
        }
        else
        {
            co_tracker = nullptr;
        }
    }

    ~Dce2Smb2TreeTracker();

    Dce2Smb2FileTrackerPtr open_file(const uint64_t, const uint32_t);
    void close_file(uint64_t, bool);
    void close_all_files();
    Dce2Smb2FileTrackerPtr find_file(uint64_t);
    Dce2Smb2RequestTrackerPtr find_request(const uint64_t, const uint32_t);
    void process(uint16_t, uint8_t, const Smb2Hdr*, const uint8_t*, const uint32_t);
    Dce2Smb2SessionTracker* get_parent() { return parent_session; }
    DCE2_CoTracker* get_cotracker() { return co_tracker; }
    uint32_t get_tree_id() { return tree_id; }
    uint8_t get_share_type() { return share_type; }
    std::atomic<bool> do_not_delete_tree { false };
    void set_parent(Dce2Smb2SessionTracker* session_tracker) { parent_session = session_tracker; }

private:
    void process_set_info_request(const Smb2Hdr*);
    void process_close_request(const Smb2Hdr*, const uint32_t);
    void process_create_response(const uint64_t, const uint32_t, const Smb2Hdr*);
    void process_create_request(const uint64_t, const uint32_t, const Smb2Hdr*, const uint8_t*);
    void process_read_response(const uint64_t, const uint32_t, const Smb2Hdr*, const uint8_t*);
    void process_read_request(const uint64_t, const uint32_t, const Smb2Hdr*);
    void process_write_request(const uint64_t, const uint32_t, const Smb2Hdr*, const uint8_t*);
    uint64_t get_durable_file_id(const Smb2CreateRequestHdr*, const uint8_t*);
    bool remove_request(const uint64_t, const uint32_t);
    void process_ioctl_command(const uint8_t, const Smb2Hdr*, const uint8_t*);
    bool store_request(const uint64_t message_id, const uint32_t current_flow_key,
        Dce2Smb2RequestTrackerPtr request)
    {
        Smb2MessageKey message_key = { message_id, current_flow_key, 0 };
        std::lock_guard<std::mutex> guard(tree_tracker_mutex);
        return active_requests.insert(std::make_pair(message_key, request)).second;
    }

    uint32_t tree_id;
    uint8_t share_type;
    DCE2_CoTracker* co_tracker; // Connection-oriented DCE/RPC tracker
    Dce2Smb2FileTrackerMap opened_files;
    Dce2Smb2RequestTrackerMap active_requests;
    Dce2Smb2SessionTracker* parent_session;
    std::mutex tree_tracker_mutex;
};

using Dce2Smb2TreeTrackerPtr = std::shared_ptr<Dce2Smb2TreeTracker>;
using Dce2Smb2TreeTrackerMap =
        std::unordered_map<uint32_t, Dce2Smb2TreeTrackerPtr, std::hash<uint32_t> >;

#endif

