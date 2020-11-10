//--------------------------------------------------------------------------
// Copyright (C) 2015-2019 Cisco and/or its affiliates. All rights reserved.
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
#include "main/snort_debug.h"

using namespace snort;

size_t session_cache_size;
THREAD_LOCAL SmbSessionCache* smb2_session_cache;

Smb2SidHashKey get_key(uint64_t sid)
{
    Smb2SidHashKey key;
    Flow* flow = DetectionEngine::get_current_packet()->flow;
    memcpy(key.cip, flow->client_ip.get_ip6_ptr(), 4*sizeof(uint32_t));
    memcpy(key.sip, flow->server_ip.get_ip6_ptr(), 4*sizeof(uint32_t));
    key.sid = sid;
    key.cgroup = flow->client_group;
    key.sgroup = flow->server_group;
    key.asid = flow->key->addressSpaceId;
    key.padding = 0;
    return key;
}

DCE2_Smb2SessionTracker* DCE2_Smb2FindElseCreateSid(DCE2_Smb2SsnData* ssd, const
    uint64_t sid)
{
    // Local MAP search
    DCE2_Smb2SessionTracker* stracker = DCE2_Smb2FindSidInSsd(ssd, sid);

    if (!stracker)
    {
        // Global Hash Search
        bool entry_created = false;
        stracker = DCE2_SmbSessionCacheFindElseCreate(sid, &entry_created);
        assert(stracker);
        if (entry_created)
        {
            stracker->set_session_id(sid);
            stracker->session_key = get_key(sid);
        }

        DCE2_Smb2InsertSidInSsd(ssd, sid, stracker);
    }

    return stracker;
}

DCE2_Smb2TreeTracker* DCE2_Smb2InsertTid(DCE2_Smb2SsnData* ssd, const uint32_t tid, uint8_t
    share_type,
    DCE2_Smb2SessionTracker* str)
{
    if (share_type == SMB2_SHARE_TYPE_DISK and
        ssd->max_file_depth == -1 and DCE2_ScSmbFileDepth((dce2SmbProtoConf*)ssd->sd.config) == -1)
    {
        debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
            "Not inserting TID (%u) because it's "
            "not IPC and not inspecting normal file data.\n", tid);
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

void DCE2_Smb2RemoveAllSession(DCE2_Smb2SsnData* ssd)
{
    ssd->ftracker_tcp = nullptr;

    // iterate over smb sessions for this tcp connection and cleanup its instance from them
    auto all_session_trackers = ssd->session_trackers.get_all_entry();
    for ( auto& h : all_session_trackers )
    {
        ssd->session_trackers.Remove(h.second->session_id);  // remove session tracker from this
                                                             // tcp conn
        h.second->removeConnTracker(ssd->flow_key); // remove tcp connection from session tracker
        if (!h.second->getConnTrackerSize()) // if no tcp connection present in session tracker,
                                             // delete session tracker
        {
            DCE2_SmbSessionCacheRemove(h.second->session_key);
        }
    }
}
