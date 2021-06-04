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

template<typename Key, typename Value, typename Hash, typename Eq = std::equal_to<Key>,
    typename Purgatory = std::vector<std::shared_ptr<Value> > >
class Dce2Smb2SharedCache : public LruCacheShared<Key, Value, Hash, Eq, Purgatory>
{
public:
    Dce2Smb2SharedCache() = delete;
    Dce2Smb2SharedCache(const Dce2Smb2SharedCache& arg) = delete;
    Dce2Smb2SharedCache& operator=(const Dce2Smb2SharedCache& arg) = delete;
    Dce2Smb2SharedCache(const size_t initial_size) :
        LruCacheShared<Key, Value, Hash, Eq, Purgatory>(initial_size) { }

    Value* find_session(Key key, Dce2Smb2SessionData* ssd)
    {
        flow_mutex.lock();
        Value* session = this->find(key).get();
        if (session)
            session->attach_flow(ssd->get_flow_key(), ssd);
        flow_mutex.unlock();
        return session;
    }

    Value* find_else_create_session(Key& key, Dce2Smb2SessionData* ssd)
    {
        std::shared_ptr<Value> new_session = std::shared_ptr<Value>(new Value(key));
        flow_mutex.lock();
        Value* session = this->find_else_insert(key, new_session, nullptr).get();
        session->attach_flow(ssd->get_flow_key(), ssd);
        flow_mutex.unlock();
        return session;
    }

    size_t mem_size() override
    {
        return current_size;
    }

    void increase_size(size_t size)
    {
        current_size += size;
    }

    void decrease_size(size_t size)
    {
        assert(current_size >= size);
        current_size -= size;
    }

private:
    using LruCacheShared<Key, Value, Hash, Eq, Purgatory>::current_size;
    using LruCacheShared<Key, Value, Hash, Eq, Purgatory>::cache_mutex;
    std::mutex flow_mutex;
    void increase_size(Value* value_ptr=nullptr) override
    {
        if (value_ptr) current_size += sizeof(*value_ptr);
    }

    void decrease_size(Value* value_ptr=nullptr) override
    {
        if (value_ptr)
        {
            assert(current_size >= sizeof(*value_ptr) );
            current_size -= sizeof(*value_ptr);
        }
    }
};

using Dce2Smb2SessionCache =
    Dce2Smb2SharedCache<Smb2SessionKey, Dce2Smb2SessionTracker, Smb2KeyHash>;

extern Dce2Smb2SessionCache smb2_session_cache;

#endif

