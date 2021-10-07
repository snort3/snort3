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

// dce_smb2_session.h author Dipta Pandit <dipandit@cisco.com>

#ifndef DCE_SMB2_SESSION_H
#define DCE_SMB2_SESSION_H

// This provides session tracker for SMBv2

#include "dce_smb2.h"
#include "dce_smb2_tree.h"

uint32_t Smb2Tid(const Smb2Hdr* hdr);

class Dce2Smb2SessionTracker
{
public:
    Dce2Smb2SessionTracker(const Smb2SessionKey& key)
    {
        session_id = key.sid;
        session_key = key;
        reload_prune = false;
        do_not_delete = false;
        command_prev = SMB2_COM_MAX;
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
            "session tracker %" PRIu64 "created\n", session_id);
    }

    ~Dce2Smb2SessionTracker();
    Dce2Smb2TreeTracker* connect_tree(const uint32_t, const uint32_t,
        uint8_t=SMB2_SHARE_TYPE_DISK);
    void disconnect_tree(uint32_t tree_id)
    {
        std::lock_guard<std::mutex> guard(connected_trees_mutex);
        connected_trees.erase(tree_id);
        decrease_size(sizeof(Dce2Smb2TreeTracker));
    }

    void attach_flow(uint32_t flow_key, Dce2Smb2SessionData* ssd)
    {
        std::lock_guard<std::mutex> guard(attached_flows_mutex);
        attached_flows.insert(std::make_pair(flow_key,ssd));
    }

    bool detach_flow(uint32_t flow_key)
    {
        std::lock_guard<std::mutex> guard(attached_flows_mutex);
        attached_flows.erase(flow_key);
        return (0 == attached_flows.size());
    }

    Smb2SessionKey get_key() { return session_key; }
    void clean_file_context_from_flow(Dce2Smb2FileTracker*, uint64_t, uint64_t);
    void unlink();
    Dce2Smb2SessionData* get_flow(uint32_t);
    void process(const uint16_t, uint8_t, const Smb2Hdr*, const uint8_t*, const uint32_t);
    void increase_size(const size_t size);
    void decrease_size(const size_t size);
    void set_reload_prune(bool flag) { reload_prune = flag; }
    uint64_t get_session_id() { return session_id; }
    void set_do_not_delete(bool flag) { do_not_delete = flag; }
    bool get_do_not_delete() { return do_not_delete; }
    void set_prev_comand(uint16_t cmd) { command_prev = cmd; }
    uint16_t get_prev_command() { return command_prev; }

private:
    // do_not_delete is to make sure when we are in processing we should not delete the context
    // which is being processed
    bool do_not_delete;
    Dce2Smb2TreeTracker* find_tree_for_message(const uint64_t, const uint32_t);
    uint64_t session_id;
    //to keep the tab of previous command
    uint16_t command_prev;
    Smb2SessionKey session_key;
    Dce2Smb2SessionDataMap attached_flows;
    Dce2Smb2TreeTrackerMap connected_trees;
    std::atomic<bool> reload_prune;
    std::mutex connected_trees_mutex;
    std::mutex attached_flows_mutex;
    // fcfs_mutex is to make sure the mutex is taken at first come first basis if code 
    // is being hit by two different paths
    std::mutex fcfs_mutex;
};

#endif

