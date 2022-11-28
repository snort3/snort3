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

// dce_smb2_session.cc author Dipta Pandit <dipandit@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb2_session.h"

#include "dce_smb2_session_cache.h"

#include "file_api/file_flows.h"

#include <numeric>

uint32_t Smb2Tid(const Smb2Hdr* hdr)
{
    return snort::alignedNtohl(&(((const Smb2SyncHdr*)hdr)->tree_id));
}

Dce2Smb2SessionData* Dce2Smb2SessionTracker::get_flow(uint32_t flow_key)
{
    std::lock_guard<std::recursive_mutex> guard(attached_flows_mutex);
    auto it_flow = attached_flows.find(flow_key);
    return (it_flow != attached_flows.end()) ? it_flow->second : nullptr;
}

Dce2Smb2TreeTrackerPtr Dce2Smb2SessionTracker::find_tree_for_message(
    const uint64_t message_id, const uint32_t flow_key)
{
    std::lock_guard<std::mutex> guard(connected_trees_mutex);
    for (auto it_tree : connected_trees)
    {
        Dce2Smb2RequestTrackerPtr request = it_tree.second->find_request(message_id, flow_key);
        if (request)
            return it_tree.second;
    }
    return nullptr;
}

Dce2Smb2TreeTrackerPtr Dce2Smb2SessionTracker::find_tree_for_tree_id(
    const uint32_t tree_id)
{
    std::lock_guard<std::mutex> guard(connected_trees_mutex);
    auto it_tree = connected_trees.find(tree_id);
    if (it_tree != connected_trees.end())
        return it_tree->second;
    return nullptr;
}

uint32_t Dce2Smb2SessionTracker::fill_map(const uint64_t msg_id, const uint8_t command_type, const
    uint32_t current_flow_key)
{
    std::lock_guard<std::mutex> guard(mid_mutex);
    auto it =  mid_map.find(current_flow_key);
    msgid_state* mid_ptr;
    if (it == mid_map.end())
    {
        mid_ptr = new msgid_state { 0, 0, { 0 }, { 0 }
        };
        mid_map.insert(std::make_pair(current_flow_key, mid_ptr));
    }
    else
        mid_ptr = it->second;
    if (command_type == SMB2_CMD_TYPE_REQUEST)
    {
        if (msg_id > mid_ptr->max_req_msg_id)
        {
            const int size = msg_id-(mid_ptr->max_req_msg_id)-1;
            std::vector<uint64_t> v(size);
            std::iota(v.begin(), v.end(), mid_ptr->max_req_msg_id+1);
            mid_ptr->missing_req_msg_ids.insert(v.begin (), v.end ());
            mid_ptr->max_req_msg_id = msg_id;
        }
        else
        {
            if (mid_ptr->missing_req_msg_ids.find(msg_id) == mid_ptr->missing_req_msg_ids.end())
            {
                return 1;
            }
            else
            {
                mid_ptr->missing_req_msg_ids.erase(msg_id);
            }
        }
    }
    if (command_type == SMB2_CMD_TYPE_RESPONSE)
    {
        if (msg_id > mid_ptr->max_resp_msg_id)
        {
            const int size = msg_id-(mid_ptr->max_resp_msg_id)-1;
            std::vector<uint64_t> v(size);
            std::iota(v.begin(), v.end(), mid_ptr->max_resp_msg_id+1);
            mid_ptr->missing_resp_msg_ids.insert(v.begin (), v.end ());
            mid_ptr->max_resp_msg_id = msg_id;
        }
        else
        {
            if (mid_ptr->missing_resp_msg_ids.find(msg_id) == mid_ptr->missing_resp_msg_ids.end())
            {
                return 1;
            }
            else
            {
                mid_ptr->missing_resp_msg_ids.erase(msg_id);
            }
        }
    }
    return 0;
}

void Dce2Smb2SessionTracker::process(const uint16_t command, uint8_t command_type,
    const Smb2Hdr* smb_header, const uint8_t* end, const uint32_t current_flow_key)
{
    Dce2Smb2TreeTrackerPtr tree;
    uint32_t tree_id = Smb2Tid(smb_header);

    if (tree_id)
    {
        connected_trees_mutex.lock();
        auto it_tree = connected_trees.find(tree_id);
        if (it_tree != connected_trees.end())
            tree = it_tree->second;
        connected_trees_mutex.unlock();
    }
    else
    {
        //async response case
        tree = find_tree_for_message(Smb2Mid(smb_header), current_flow_key);
    }

    if (fill_map(Smb2Mid(smb_header), command_type, current_flow_key))
    {
        dce2_smb_stats.ignore_dup_sessions++;
        return;
    }

    switch (command)
    {
    case SMB2_COM_TREE_CONNECT:
    {
        uint8_t share_type = ((const Smb2TreeConnectResponseHdr*)
            ((const uint8_t*)smb_header + SMB2_HEADER_LENGTH))->share_type;
        connect_tree(tree_id, share_type);
    }
    break;
    case SMB2_COM_TREE_DISCONNECT:
    {
        if (!tree)
            dce2_smb_stats.v2_tree_discn_ignored++;
    }
    break;

    //for all other cases, tree tracker should handle the command
    case SMB2_COM_CREATE:
        if (!tree and SMB2_CMD_TYPE_REQUEST == command_type)
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID,
                TRACE_INFO_LEVEL, GET_CURRENT_PACKET,
                "%s_REQ: mid-stream session detected\n",
                smb2_command_string[command]);
            tree = connect_tree(tree_id);
            if (!tree)
            {
                SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID,
                    TRACE_INFO_LEVEL, GET_CURRENT_PACKET,
                    "%s_REQ: insert tree tracker failed\n",
                    smb2_command_string[command]);
            }
        }
    // fallthrough
    default:
        if (tree)
            tree->process(command, command_type, smb_header, end, current_flow_key);
        else
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID,
                TRACE_ERROR_LEVEL, GET_CURRENT_PACKET,
                "%s: tree tracker missing\n", smb2_command_string[command]);
            dce2_smb_stats.v2_tree_ignored++;
        }
        break;
    }
}

Dce2Smb2TreeTrackerPtr Dce2Smb2SessionTracker::connect_tree(const uint32_t tree_id,
    const uint8_t share_type)
{
    Dce2Smb2TreeTrackerPtr tree;
    connected_trees_mutex.lock();
    auto it_tree = connected_trees.find(tree_id);
    if (it_tree != connected_trees.end())
        tree = it_tree->second;
    connected_trees_mutex.unlock();
    if (!tree)
    {
        tree = std::make_shared<Dce2Smb2TreeTracker>(tree_id, this, share_type);
        connected_trees_mutex.lock();
        connected_trees.insert(std::make_pair(tree_id, tree));
        connected_trees_mutex.unlock();
        increase_size(sizeof(Dce2Smb2TreeTracker));
    }
    return tree;
}

void Dce2Smb2SessionTracker::increase_size(const size_t size)
{
    smb2_session_cache.increase_size(size);
}

void Dce2Smb2SessionTracker::decrease_size(const size_t size)
{
    smb2_session_cache.decrease_size(size);
}

// Session Tracker is created and destroyed only from session cache
Dce2Smb2SessionTracker::~Dce2Smb2SessionTracker(void)
{
    if (!(fcfs_mutex.try_lock()))
        return;

    if (do_not_delete )
    {
        // Dont prune the session in LRU Cache
        smb2_session_cache.find_id(get_key());
        fcfs_mutex.unlock();
        return;
    }
    disconnect_tree();
    free_map();

    do_not_delete = false;
    fcfs_mutex.unlock();
    std::lock_guard<std::recursive_mutex> guard(attached_flows_mutex);
    attached_flows.clear();
}

