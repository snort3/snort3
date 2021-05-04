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

// dce_smb2_session_cache.h author Bhargava Jandhyala <bjandhya@cisco.com>

#ifndef DCE_SMB2_SESSION_CACHE_H
#define DCE_SMB2_SESSION_CACHE_H

// This provides a wrapper over LRU cache shared for SMBv2 Session trackers

#include "hash/lru_cache_shared.h"

#include "dce_smb2_session.h"

#define SMB_AVG_FILES_PER_SESSION 5

template<typename Key, typename Value, typename Hash>
class Dce2Smb2SharedCache : public LruCacheShared<Key, Value, Hash>
{
public:
    Dce2Smb2SharedCache() = delete;
    Dce2Smb2SharedCache(const Dce2Smb2SharedCache& arg) = delete;
    Dce2Smb2SharedCache& operator=(const Dce2Smb2SharedCache& arg) = delete;
    Dce2Smb2SharedCache(const size_t initial_size) :
        LruCacheShared<Key, Value, Hash>(initial_size) { }
    virtual ~Dce2Smb2SharedCache() { }

    Value* find_session(Key key)
    { return this->find(key).get(); }
    Value* find_else_create_session(Key key)
    {
        std::shared_ptr<Value> new_session = std::shared_ptr<Value>(new Value());
        return this->find_else_insert(key, new_session, nullptr).get();
    }
};

using Dce2Smb2SessionCache =
    Dce2Smb2SharedCache<Smb2SessionKey, Dce2Smb2SessionTracker, Smb2KeyHash>;

extern THREAD_LOCAL Dce2Smb2SessionCache* smb2_session_cache;

inline void DCE2_SmbSessionCacheInit(const size_t cache_size)
{
    smb2_session_cache = new Dce2Smb2SessionCache(cache_size);
}

#endif

