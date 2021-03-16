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

// dce_smb2_tree.h author Dipta Pandit <dipandit@cisco.com>

#ifndef DCE_SMB2_TREE_H
#define DCE_SMB2_TREE_H

// This provides tree trackers for SMBv2.
// Tree trackers are used to identify and track an opened share

#include "dce_smb2.h"
#include "dce_smb2_file.h"
#include "dce_smb2_request.h"

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
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
            "tree tracker %" PRIu32 " created\n", tree_id);
        memory::MemoryCap::update_allocations(sizeof(*this));
    }

    ~Dce2Smb2TreeTracker();

    void open_file(uint64_t);
    void close_file(uint64_t, bool=true);
    Dce2Smb2FileTracker* find_file(uint64_t);
    Dce2Smb2RequestTracker* find_request(uint64_t);
    void process(uint16_t, uint8_t, const Smb2Hdr*, const uint8_t*);
    Dce2Smb2SessionTracker* get_parent() { return parent_session; }

private:
    void process_set_info_request(const Smb2Hdr*);
    void process_close_request(const Smb2Hdr*);
    void process_create_response(uint64_t, const Smb2Hdr*);
    void process_create_request(uint64_t, const Smb2Hdr*, const uint8_t*);
    void process_read_response(uint64_t, const Smb2Hdr*, const uint8_t*);
    void process_read_request(uint64_t, const Smb2Hdr*);
    void process_write_request(uint64_t, const Smb2Hdr*, const uint8_t*);
    uint64_t get_durable_file_id(const Smb2CreateRequestHdr*, const uint8_t*);
    bool remove_request(uint64_t);
    void store_request(uint64_t message_id, Dce2Smb2RequestTracker* request)
    { active_requests.insert(std::make_pair(message_id, request)); }

    uint32_t tree_id;
    uint8_t share_type;
    Dce2Smb2FileTrackerMap opened_files;
    Dce2Smb2RequestTrackerMap active_requests;
    Dce2Smb2SessionTracker* parent_session;
};

using Dce2Smb2TreeTrackerMap =
    std::unordered_map<uint32_t, Dce2Smb2TreeTracker*, std::hash<uint32_t> >;

#endif

