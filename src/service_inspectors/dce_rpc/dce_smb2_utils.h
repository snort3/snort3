//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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
class LruCacheLocalSmbMultiChannel : public LruCacheLocal <Key, Value, Hash>
{
public:
    using LruLocal = LruCacheLocal<Key, Value, Hash>;
    using LruLocal::current_size;
    using LruLocal::max_size;
    using LruLocal::list;
    using LruLocal::map;
    using LruLocal::stats;
    using LruMapIter = typename LruLocal::LruMapIter;

    LruCacheLocalSmbMultiChannel(const size_t sz, struct LruCacheLocalStats& st) :   LruLocal(sz, st) { }

    void update(int size)
    {
        if ( size < 0 )
            assert(current_size >= (size_t)-size);
        current_size += size;
        if ( size > 0)
        {
            // Checking 1+ size prevents crash if max_size is too low to hold even a single entry
            if ( current_size > max_size and list.size() > 1 )
                LruLocal::prune();
            if ( stats.cache_max < current_size )
                stats.cache_max = current_size;
        }
    }

    Value find(Key& key)
    {
        LruMapIter it = map.find(key);
        if (it == map.end())
            return nullptr;
        //Move entry to front of LruList
        list.splice(list.begin(), list, it->second);
        return list.begin()->second;
    }
};

typedef LruCacheLocalSmbMultiChannel<Smb2SidHashKey, std::shared_ptr<DCE2_Smb2SessionTracker>,
    SmbKeyHash> SmbSessionCache;

extern THREAD_LOCAL SmbSessionCache* smb2_session_cache;

// SMB2 Session cache manipulation functions
inline void DCE2_SmbSessionCacheInit(const size_t cache_size)
{
    smb2_session_cache = new SmbSessionCache(cache_size, dce2_smb_stats);
}

inline void DCE2_SmbSessionCacheUpdateSize(int size)
{
    smb2_session_cache->update(size);
}

inline std::shared_ptr<DCE2_Smb2SessionTracker> DCE2_SmbSessionCacheFindElseCreate(uint64_t sid)
{
    bool is_new = false;
    auto& session_ptr =  smb2_session_cache->find_else_create(get_key(sid), &is_new);
    if (is_new)
    {
        session_ptr.reset(new DCE2_Smb2SessionTracker(sid));
    }
    return session_ptr;
}

inline bool DCE2_SmbSessionCacheRemove(const Smb2SidHashKey& key)
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
    return (hdr->status != SMB_NT_STATUS__SUCCESS);
}

inline std::shared_ptr<DCE2_Smb2SessionTracker> DCE2_Smb2FindSidInSsd(DCE2_Smb2SsnData* ssd, const
    uint64_t sid)
{
    return ssd->find_session_tracker(sid);
}

inline void DCE2_Smb2InsertSidInSsd(DCE2_Smb2SsnData* ssd, const uint64_t sid,
    std::shared_ptr<DCE2_Smb2SessionTracker> stracker)
{
    // add ssd in session tracker's tcp trackers database
    if (ssd->flow_key)
    {
        stracker->insertConnectionTracker(ssd->flow_key, ssd);
    }
    ssd->insert_session_tracker(sid, stracker);
}

inline void DCE2_Smb2RemoveSidInSsd(DCE2_Smb2SsnData* ssd, const uint64_t sid)
{
    ssd->remove_session_tracker(sid);
}

DCE2_Smb2TreeTracker* DCE2_Smb2InsertTid(DCE2_Smb2SsnData*, const uint32_t tid, uint8_t share_type,
    DCE2_Smb2SessionTracker*);

DCE2_Smb2SessionTracker* DCE2_Smb2FindElseCreateSid(DCE2_Smb2SsnData*, const uint64_t sid, bool
    force_cache_update = true);

#endif

