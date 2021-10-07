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

    using Data = std::shared_ptr<Value>;

    Data find_id(Key key)
    {
        Data session = this->find(key);
        return session;
    }

    Data find_session(Key key, Dce2Smb2SessionData* ssd)
    {
        Data session = this->find(key);
        if (session)
            session->attach_flow(ssd->get_flow_key(), ssd);
        return session;
    }

    Data find_else_create_session(Key& key, Dce2Smb2SessionData* ssd)
    {
        Data new_session = Data(new Value(key));
        Data session = this->find_else_insert(key, new_session, nullptr);
        session->attach_flow(ssd->get_flow_key(), ssd);
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

    // Since decrease_size() does not account for associated objects in smb2_session_cache,
    // we will over-prune when we reach the new_size here, as more space will be freed up
    // when actual objects are destroyed. We might need to do gradual pruning like how
    // host cache does. For now over pruning is ok.
    void reload_prune(size_t new_size)
    {
        Purgatory data;
        std::lock_guard<std::mutex> cache_lock(cache_mutex);
        max_size = new_size;
        while (current_size > max_size && !list.empty())
        {
            LruListIter list_iter = --list.end();
            data.emplace_back(list_iter->second); // increase reference count
            // This instructs the session_tracker to take a lock before detaching
            // from ssd, when it is getting destroyed.
            list_iter->second->set_reload_prune(true);
            decrease_size(list_iter->second.get());
            map.erase(list_iter->first);
            list.erase(list_iter);
            ++stats.reload_prunes;
        }
    }

private:
    using LruBase = LruCacheShared<Key, Value, Hash, Eq, Purgatory>;
    using LruBase::cache_mutex;
    using LruBase::current_size;
    using LruBase::list;
    using LruBase::map;
    using LruBase::max_size;
    using LruBase::stats;
    using LruListIter = typename LruBase::LruListIter;
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
            //This is going down, remove references from flow here
            value_ptr->unlink();
        }
    }
};

using Dce2Smb2SessionCache =
    Dce2Smb2SharedCache<Smb2SessionKey, Dce2Smb2SessionTracker, Smb2KeyHash>;

extern Dce2Smb2SessionCache smb2_session_cache;

#endif

