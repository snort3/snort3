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
    Dce2Smb2SessionTracker()
    {
        session_id = 0;
        session_key = { };
        memory::MemoryCap::update_allocations(sizeof(*this));
    }

    ~Dce2Smb2SessionTracker();
    void init(uint64_t, const Smb2SessionKey&);
    void attach_flow(Smb2FlowKey, Dce2Smb2SessionData*);
    bool detach_flow(Smb2FlowKey&);
    void process(uint16_t, uint8_t, const Smb2Hdr*, const uint8_t*);
    void disconnect_tree(uint32_t tree_id) { connected_trees.erase(tree_id); }
    Dce2Smb2SessionData* get_current_flow();
    Smb2SessionKey get_key() { return session_key; }
    Dce2Smb2SessionDataMap get_attached_flows() { return attached_flows; }
    Dce2Smb2TreeTracker* connect_tree(uint32_t, uint8_t=SMB2_SHARE_TYPE_DISK);

private:
    Dce2Smb2TreeTracker* find_tree_for_message(uint64_t);
    uint64_t session_id;
    Smb2SessionKey session_key;
    Dce2Smb2SessionDataMap attached_flows;
    Dce2Smb2TreeTrackerMap connected_trees;
};

#endif

