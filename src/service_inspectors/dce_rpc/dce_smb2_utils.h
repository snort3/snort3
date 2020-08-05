//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb2_utils.h author Bhargava Jandhyala <bjandhya@cisco.com>
// based on work by Todd Wease

#ifndef DCE_SMB2_UTILS_H
#define DCE_SMB2_UTILS_H

#include "dce_smb.h"
#include "dce_smb2.h"
#include "file_api/file_flows.h"

Smb2SidHashKey get_key(uint64_t sid);

template<typename Key, typename Value, typename Hash>
class SmbSessionCache_map : public LruCacheShared<Key, Value, Hash>
{
public:
    SmbSessionCache_map() = delete;
    SmbSessionCache_map(const SmbSessionCache_map& arg) = delete;
    SmbSessionCache_map& operator=(const SmbSessionCache_map& arg) = delete;
    SmbSessionCache_map(const size_t initial_size) : LruCacheShared<Key, Value, Hash>(initial_size)
    {
    }
    virtual ~SmbSessionCache_map() { }
};

typedef SmbSessionCache_map<Smb2SidHashKey, DCE2_Smb2SessionTracker, SmbKeyHash> SmbSessionCache;

extern THREAD_LOCAL SmbSessionCache* smb2_session_cache;
extern size_t session_cache_size;

// SMB2 Session cache manipulation functions
inline void DCE2_SmbSessionCacheInit(const size_t cache_size)
{
    smb2_session_cache = new SmbSessionCache(cache_size);
}

inline DCE2_Smb2SessionTracker* DCE2_SmbSessionCacheFind(uint64_t sid)
{
    return (smb2_session_cache->find(get_key(sid))).get();
}

inline DCE2_Smb2SessionTracker* DCE2_SmbSessionCacheFindElseCreate(uint64_t sid,
    bool* entry_created)
{
    return (smb2_session_cache->find_else_create(get_key(sid), entry_created)).get();
}

inline bool DCE2_SmbSessionCacheRemove(Smb2SidHashKey key)
{
    return smb2_session_cache->remove(key);
}

// SMB2 functions for fetching sid, tid, request type and so on.
inline uint64_t Smb2Sid(const Smb2Hdr* hdr)
{
    return snort::alignedNtohq(&(((const Smb2SyncHdr*)hdr)->session_id));
}

inline uint32_t Smb2Tid(const Smb2Hdr* hdr)
{
    return snort::alignedNtohl(&(((const Smb2SyncHdr*)hdr)->tree_id));
}

inline uint64_t Smb2Mid(const Smb2Hdr* hdr)
{
    return snort::alignedNtohq(&(((const Smb2SyncHdr*)hdr)->message_id));
}

inline bool Smb2Error(const Smb2Hdr* hdr)
{
    return (SMB_NT_STATUS_SEVERITY__ERROR == (uint8_t)(hdr->status >> 30));
}

inline DCE2_Smb2SessionTracker* DCE2_Smb2FindSidInSsd(DCE2_Smb2SsnData* ssd, const
    uint64_t sid)
{
    return (DCE2_Smb2SessionTracker*)(ssd->session_trackers.Find(sid));
}

inline void DCE2_Smb2InsertSidInSsd(DCE2_Smb2SsnData* ssd, const uint64_t sid,
    DCE2_Smb2SessionTracker* stracker)
{
    // add ssd in session tracker's tcp trackers database
    stracker->insertConnTracker(ssd->flow_key, ssd);

    ssd->session_trackers.Insert(sid, stracker);
}

inline void DCE2_Smb2RemoveSidInSsd(DCE2_Smb2SsnData* ssd, const uint64_t sid)
{
    ssd->session_trackers.Remove(sid);
}

DCE2_Smb2TreeTracker* DCE2_Smb2InsertTid(DCE2_Smb2SsnData*, const uint32_t tid, uint8_t share_type,
    DCE2_Smb2SessionTracker*);

DCE2_Smb2SessionTracker* DCE2_Smb2FindElseCreateSid(DCE2_Smb2SsnData*, const uint64_t sid);

DCE2_Ret DCE2_Smb2InitData(DCE2_Smb2SsnData*);

void DCE2_Smb2RemoveAllSession(DCE2_Smb2SsnData* ssd);

#endif

