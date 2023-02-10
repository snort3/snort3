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

// dce_smb2_session.h author Dipta Pandit <dipandit@cisco.com>

#ifndef DCE_SMB2_SESSION_H
#define DCE_SMB2_SESSION_H

// This provides session tracker for SMBv2

#include "dce_smb2.h"
#include "dce_smb2_tree.h"

uint32_t Smb2Tid(const Smb2Hdr* hdr);

typedef struct _msgid_state
{
    uint64_t max_req_msg_id;
    uint64_t max_resp_msg_id;
    std::unordered_set<uint64_t> missing_req_msg_ids;
    std::unordered_set<uint64_t> missing_resp_msg_ids;
} msgid_state;

class Dce2Smb2SessionTracker
{
public:
    Dce2Smb2SessionTracker(const Smb2SessionKey& key)
    {
        session_id = key.sid;
        session_key = key;
        reload_prune = false;
        do_not_delete = false;
        file_context_cleaned = false;
        command_prev = SMB2_COM_MAX;
        encryption_flag = false;
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
            "session tracker %" PRIu64 "created\n", session_id);
    }

    ~Dce2Smb2SessionTracker();
    Dce2Smb2TreeTrackerPtr connect_tree(const uint32_t,
        uint8_t=SMB2_SHARE_TYPE_DISK);

    void disconnect_tree()
    {
        std::lock_guard<std::mutex> guard(connected_trees_mutex);
        auto it_tree = connected_trees.begin();
        while (it_tree != connected_trees.end())
        {
            auto next_it_tree = std::next(it_tree);
            it_tree->second->close_all_files();
            connected_trees.erase(it_tree->second->get_tree_id());
            decrease_size(sizeof(Dce2Smb2TreeTracker));
            it_tree = next_it_tree;
        }
    }

    void attach_flow(uint32_t flow_key, Dce2Smb2SessionData* ssd)
    {
        std::lock_guard<std::recursive_mutex> guard(attached_flows_mutex);
        if (attached_flows.find(flow_key) == attached_flows.end())
        {
            attached_flows.insert(std::make_pair(flow_key, ssd));
        }
    }

    bool detach_flow(uint32_t flow_key)
    {
        std::lock_guard<std::recursive_mutex> guard(attached_flows_mutex);
        if (attached_flows.size()<2)
            attached_flows.clear();
        else
        {
            attached_flows.erase(flow_key);
            attached_flows[flow_key] = nullptr;
        }
        free_one_flow_map(flow_key);
        return (0 == attached_flows.size());
    }

    void free_one_flow_map(uint32_t flow_key)
    {
        std::lock_guard<std::mutex> guard(mid_mutex);
        auto it =  mid_map.find(flow_key);
        if (it != mid_map.end())
        {
            delete it->second;
            mid_map.erase(it);
        }
    }

    void free_map()
    {
        std::lock_guard<std::mutex> guard(mid_mutex);
        std::vector<msgid_state*> mid_ptrs;
        auto it_map = mid_map.begin();
        while (it_map != mid_map.end())
        {
            mid_ptrs.push_back(it_map->second);
            it_map = mid_map.erase(it_map);
        }
        for (msgid_state* it_msg_id : mid_ptrs)
        {
            delete it_msg_id;
        }
    }

    Smb2SessionKey get_key() { return session_key; }
    Dce2Smb2SessionData* get_flow(uint32_t);
    void process(const uint16_t, uint8_t, const Smb2Hdr*, const uint8_t*, const uint32_t);
    void increase_size(const size_t size);
    void decrease_size(const size_t size);
    void set_reload_prune(bool flag) { reload_prune = flag; }
    uint64_t get_session_id() { return session_id; }
    void set_do_not_delete(bool flag) { do_not_delete = flag; }
    bool get_do_not_delete() { return do_not_delete; }
    void set_file_context_cleaned(bool flag) { file_context_cleaned = flag; }
    bool get_file_context_cleaned() { return file_context_cleaned; }
    void set_prev_comand(uint16_t cmd) { command_prev = cmd; }
    uint16_t get_prev_command() { return command_prev; }
    std::mutex co_tracker_mutex;
    void set_encryption_flag(bool flag)
    {
        encryption_flag = flag;
        if (flag)
            dce2_smb_stats.total_encrypted_sessions++;
    }

    bool get_encryption_flag() { return encryption_flag; }
    Dce2Smb2TreeTrackerPtr find_tree_for_tree_id(const uint32_t);
    uint32_t fill_map(const uint64_t msg_id, const uint8_t command_type, const uint32_t
        current_flow_key);
    std::recursive_mutex attached_flows_mutex;
    uint16_t vlan_id = 0;
    Dce2Smb2SessionDataMap attached_flows;

private:
    // do_not_delete is to make sure when we are in processing we should not delete the context
    // which is being processed
    bool do_not_delete;
    bool file_context_cleaned;
    Dce2Smb2TreeTrackerPtr find_tree_for_message(const uint64_t, const uint32_t);
    uint64_t session_id;
    //to keep the tab of previous command
    uint16_t command_prev;
    Smb2SessionKey session_key;
    Dce2Smb2TreeTrackerMap connected_trees;
    std::atomic<bool> reload_prune;
    std::atomic<bool> encryption_flag;
    std::mutex connected_trees_mutex;

    // fcfs_mutex is to make sure the mutex is taken at first come first basis if code
    // is being hit by two different paths
    std::mutex fcfs_mutex;
    std::mutex mid_mutex;
    std::unordered_map<uint32_t, msgid_state*, std::hash<uint32_t> > mid_map;
};

#endif

