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

uint32_t Smb2Tid(const Smb2Hdr* hdr)
{
    return snort::alignedNtohl(&(((const Smb2SyncHdr*)hdr)->tree_id));
}

//init must be called when a session tracker is created.
void Dce2Smb2SessionTracker::init(uint64_t sid,
    const Smb2SessionKey& session_key_v)
{
    session_id = sid;
    session_key = session_key_v;
    debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "session tracker %" PRIu64
        " created\n", session_id);
}

Dce2Smb2SessionData* Dce2Smb2SessionTracker::get_current_flow()
{
    Smb2FlowKey flow_key = get_smb2_flow_key();
    auto it_flow = attached_flows.find(flow_key);
    return (it_flow != attached_flows.end()) ? it_flow->second : nullptr;
}

Dce2Smb2TreeTracker* Dce2Smb2SessionTracker::find_tree_for_message(
    uint64_t message_id)
{
    for (auto it_tree : connected_trees)
    {
        Dce2Smb2RequestTracker* request = it_tree.second->find_request(message_id);
        if (request)
            return it_tree.second;
    }
    return nullptr;
}

void Dce2Smb2SessionTracker::process(uint16_t command, uint8_t command_type,
    const Smb2Hdr* smb_header, const uint8_t* end)
{
    Dce2Smb2TreeTracker* tree = nullptr;
    uint32_t tree_id = Smb2Tid(smb_header);

    if (tree_id)
    {
        auto it_tree = connected_trees.find(tree_id);
        if (it_tree != connected_trees.end())
            tree = it_tree->second;
    }
    else
    {
        //async response case
        tree = find_tree_for_message(Smb2Mid(smb_header));
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
        if (tree)
        {
            delete tree;
            connected_trees.erase(tree_id);
        }
        else
            dce2_smb_stats.v2_tree_discn_ignored++;
        break;

    //for all other cases, tree tracker should handle the command
    case SMB2_COM_CREATE:
        if (!tree and SMB2_CMD_TYPE_REQUEST == command_type)
        {
            debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
                "%s_REQ: mid-stream session detected\n",
                smb2_command_string[command]);
            tree = connect_tree(tree_id);
            if (!tree)
            {
                debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
                    "%s_REQ: insert tree tracker failed\n",
                    smb2_command_string[command]);
            }
        }
    // fallthrough
    default:
        if (tree)
            tree->process(command, command_type, smb_header, end);
        else
        {
            debug_logf(dce_smb_trace, GET_CURRENT_PACKET,
                "%s: tree tracker missing\n", smb2_command_string[command]);
            dce2_smb_stats.v2_tree_ignored++;
        }
        break;
    }
}

Dce2Smb2TreeTracker* Dce2Smb2SessionTracker::connect_tree(uint32_t tree_id,
    uint8_t share_type)
{
    Dce2Smb2SessionData* current_flow = get_current_flow();
    if ((SMB2_SHARE_TYPE_DISK == share_type) and (-1 == current_flow->get_max_file_depth()) and
        (-1 == current_flow->get_smb_file_depth()))
    {
        debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "Not inserting TID (%u) "
            "because it's not IPC and not inspecting normal file data.\n", tree_id);
        dce2_smb_stats.v2_tree_cnct_ignored++;
        return nullptr;
    }
    Dce2Smb2TreeTracker* tree = nullptr;
    auto it_tree = connected_trees.find(tree_id);
    if (it_tree != connected_trees.end())
        tree = it_tree->second;
    if (!tree)
    {
        tree = new Dce2Smb2TreeTracker(tree_id, this, share_type);
        connected_trees.insert(std::make_pair(tree_id, tree));
    }
    return tree;
}

void Dce2Smb2SessionTracker::attach_flow(Smb2FlowKey flow_key,
    Dce2Smb2SessionData* ssd)
{
    attached_flows.insert(std::make_pair(flow_key,ssd));
}

bool Dce2Smb2SessionTracker::detach_flow(Smb2FlowKey& flow_key)
{
    attached_flows.erase(flow_key);
    return (0 == attached_flows.size());
}

// Session Tracker is created and destroyed only from session cache
Dce2Smb2SessionTracker::~Dce2Smb2SessionTracker(void)
{
    debug_logf(dce_smb_trace, GET_CURRENT_PACKET, "session tracker %" PRIu64
        " terminating\n", session_id);
    auto it_tree = connected_trees.begin();
    while (it_tree != connected_trees.end())
    {
        Dce2Smb2TreeTracker* tree = it_tree->second;
        it_tree = connected_trees.erase(it_tree);
        delete tree;
    }

    for (auto it_flow : attached_flows)
        it_flow.second->remove_session(session_id);

    memory::MemoryCap::update_deallocations(sizeof(*this));
}

