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

// dce_smb2_session.cc author Dipta Pandit <dipandit@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb2_session.h"

#include "dce_smb2_session_cache.h"

#include "file_api/file_flows.h"

uint32_t Smb2Tid(const Smb2Hdr* hdr)
{
    return snort::alignedNtohl(&(((const Smb2SyncHdr*)hdr)->tree_id));
}

Dce2Smb2SessionData* Dce2Smb2SessionTracker::get_flow(uint32_t flow_key)
{
    std::lock_guard<std::mutex> guard(attached_flows_mutex);
    auto it_flow = attached_flows.find(flow_key);
    return (it_flow != attached_flows.end()) ? it_flow->second : nullptr;
}

Dce2Smb2TreeTracker* Dce2Smb2SessionTracker::find_tree_for_message(
    const uint64_t message_id, const uint32_t flow_key)
{
    std::lock_guard<std::mutex> guard(connected_trees_mutex);
    for (auto it_tree : connected_trees)
    {
        Dce2Smb2RequestTracker* request = it_tree.second->find_request(message_id, flow_key);
        if (request)
            return it_tree.second;
    }
    return nullptr;
}

void Dce2Smb2SessionTracker::process(const uint16_t command, uint8_t command_type,
    const Smb2Hdr* smb_header, const uint8_t* end, const uint32_t current_flow_key)
{
    Dce2Smb2TreeTracker* tree = nullptr;
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

    switch (command)
    {
    case SMB2_COM_TREE_CONNECT:
    {
        uint8_t share_type = ((const Smb2TreeConnectResponseHdr*)
            ((const uint8_t*)smb_header + SMB2_HEADER_LENGTH))->share_type;
        connect_tree(tree_id, current_flow_key, share_type);
    }
    break;
    case SMB2_COM_TREE_DISCONNECT:
        if (tree)
        {
            delete tree;
            connected_trees_mutex.lock();
            connected_trees.erase(tree_id);
            connected_trees_mutex.unlock();
        }
        else
            dce2_smb_stats.v2_tree_discn_ignored++;
        break;

    //for all other cases, tree tracker should handle the command
    case SMB2_COM_CREATE:
        if (!tree and SMB2_CMD_TYPE_REQUEST == command_type)
        {
	        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, 
	            TRACE_INFO_LEVEL, GET_CURRENT_PACKET,
                "%s_REQ: mid-stream session detected\n",
                smb2_command_string[command]);
            tree = connect_tree(tree_id, current_flow_key);
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

Dce2Smb2TreeTracker* Dce2Smb2SessionTracker::connect_tree(const uint32_t tree_id,
    const uint32_t current_flow_key, const uint8_t share_type)
{
    Dce2Smb2SessionData* current_flow = get_flow(current_flow_key);
    if ((SMB2_SHARE_TYPE_DISK == share_type) and current_flow and
        (-1 == current_flow->get_max_file_depth()) and
        (-1 == current_flow->get_smb_file_depth()))
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, 
	    TRACE_INFO_LEVEL, GET_CURRENT_PACKET, "Not inserting TID (%u) "
            "because it's not IPC and not inspecting normal file data.\n", tree_id);
        dce2_smb_stats.v2_tree_cnct_ignored++;
        return nullptr;
    }
    Dce2Smb2TreeTracker* tree = nullptr;
    connected_trees_mutex.lock();
    auto it_tree = connected_trees.find(tree_id);
    if (it_tree != connected_trees.end())
        tree = it_tree->second;
    connected_trees_mutex.unlock();
    if (!tree)
    {
        tree = new Dce2Smb2TreeTracker(tree_id, this, share_type);
        connected_trees_mutex.lock();
        connected_trees.insert(std::make_pair(tree_id, tree));
        connected_trees_mutex.unlock();
        increase_size(sizeof(Dce2Smb2TreeTracker));
    }
    return tree;
}

void Dce2Smb2SessionTracker::clean_file_context_from_flow(Dce2Smb2FileTracker* file_tracker,
    uint64_t file_id, uint64_t file_name_hash)
{
    for (auto it_flow : attached_flows)
    {
        snort::FileFlows* file_flows = snort::FileFlows::get_file_flows(
            it_flow.second->get_tcp_flow(), false);
        if (file_flows)
            file_flows->remove_processed_file_context(file_name_hash, file_id);
        it_flow.second->reset_matching_tcp_file_tracker(file_tracker);
    }
}

void Dce2Smb2SessionTracker::increase_size(const size_t size)
{
    smb2_session_cache.increase_size(size);
}

void Dce2Smb2SessionTracker::decrease_size(const size_t size)
{
    smb2_session_cache.decrease_size(size);
}

void Dce2Smb2SessionTracker::unlink()
{
    attached_flows_mutex.lock();
    for (auto it_flow : attached_flows)
        it_flow.second->remove_session(session_id, reload_prune.load());
    attached_flows_mutex.unlock();
}

// Session Tracker is created and destroyed only from session cache
Dce2Smb2SessionTracker::~Dce2Smb2SessionTracker()
{
    if (smb_module_is_up and (snort::is_packet_thread()))
    {
	    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, 
	        TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
            "session tracker %" PRIu64 " terminating\n", session_id);
    }

    std::vector<Dce2Smb2TreeTracker*> all_trees;
    connected_trees_mutex.lock();
    auto it_tree = connected_trees.begin();
    while (it_tree != connected_trees.end())
    {
        all_trees.push_back(it_tree->second);
        it_tree = connected_trees.erase(it_tree);
    }
    connected_trees_mutex.unlock();

    for (Dce2Smb2TreeTracker* tree : all_trees)
    {
        delete tree;
    }

}

