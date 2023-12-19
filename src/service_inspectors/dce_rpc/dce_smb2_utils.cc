//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

// SMB2 utils processing
// dce_smb2_utils.cc author Bhargava Jandhyala <bjandhya@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb_module.h"
#include "dce_smb_utils.h"
#include "dce_smb2_utils.h"
#include "detection/detection_util.h"
#include "flow/flow_key.h"

using namespace snort;

size_t session_cache_size;
THREAD_LOCAL SmbSessionCache* smb2_session_cache;

Smb2SidHashKey get_key(uint64_t sid)
{
    Smb2SidHashKey key = { };
    Flow* flow = DetectionEngine::get_current_packet()->flow;
    if (flow)
    {
        memcpy(key.cip, flow->client_ip.get_ip6_ptr(), 4 * sizeof(uint32_t));
        memcpy(key.sip, flow->server_ip.get_ip6_ptr(), 4 * sizeof(uint32_t));
        key.mplsLabel = flow->key->mplsLabel;
        key.cgroup = flow->client_group;
        key.sgroup = flow->server_group;
        key.addressSpaceId = flow->key->addressSpaceId;
        key.vlan_tag = flow->key->vlan_tag;
        key.sid = sid;
        key.tenant_id = flow->key->tenant_id;
    }
    return key;
}

DCE2_Smb2SessionTracker* DCE2_Smb2FindElseCreateSid(DCE2_Smb2SsnData* ssd, const
    uint64_t sid, bool force_cache_update)
{
    // Local MAP search
    auto stracker = DCE2_Smb2FindSidInSsd(ssd, sid);
    if (!stracker)
    {
        // Global Hash Search
        stracker = DCE2_SmbSessionCacheFindElseCreate(sid);
        DCE2_Smb2InsertSidInSsd(ssd, sid, stracker);
    }
    else if (force_cache_update)
    {
        //find on cache to force update LRU.
        auto key = get_key(sid);
        smb2_session_cache->find(key);
    }
    return stracker.get();
}

DCE2_Smb2TreeTracker* DCE2_Smb2InsertTid(DCE2_Smb2SsnData* ssd, const uint32_t tid, uint8_t
    share_type,
    DCE2_Smb2SessionTracker* str)
{
    if (share_type == SMB2_SHARE_TYPE_DISK and
        ssd->max_file_depth == -1 and DCE2_ScSmbFileDepth((dce2SmbProtoConf*)ssd->sd.config) == -1)
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
            DetectionEngine::get_current_packet(),
            "Not inserting TID (%u) because it's not IPC and not "
            " inspecting normal file data.\n", tid);
        return nullptr;
    }

    DCE2_Smb2TreeTracker* ttracker = str->findTtracker(tid);
    if (!ttracker)
    {
        ttracker = new DCE2_Smb2TreeTracker(tid, share_type);
        str->insertTtracker(tid, ttracker);
    }

    return ttracker;
}

