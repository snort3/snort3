//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// dce_db.h author Neha Sharma <nehash4@cisco.com>

// This implementation provides interface that can be extended for map, list, etc.
// Currently only map has been implemented to handle multiple smb sessions
// in single tcp connection. This database will modify/change to handle
// single smb session spread across multiple tcp connections.

#ifndef DCE_DB_H
#define DCE_DB_H

#include <unordered_map>
#include <vector>
#include "dce_utils.h"

#include "main/snort_types.h"

template<typename Key, typename Value, typename Hash>
class DCE2_Db
{
public:

    virtual bool Insert(const Key& key, Value data) = 0;
    virtual Value Find(const Key& key) = 0;
    virtual void Remove(const Key& key) = 0;
    virtual int GetSize() = 0;
    virtual std::vector< std::pair<Key, Value> > get_all_entry() = 0;
};

template<typename Key, typename Value, typename Hash>
class DCE2_DbMap : public DCE2_Db<Key, Value, Hash>
{
public:

    DCE2_DbMap(bool gc = true) :   garbage_collection(gc) { }

    ~DCE2_DbMap()
    {
        auto it = Map.cbegin();
        while (it != Map.cend())
        {
            if (garbage_collection)
                delete it->second;
            it = Map.erase(it);
        }
    }

    bool Insert(const Key& key, Value data) override;
    Value Find(const Key& key) override;
    void Remove(const Key& key) override;
    int GetSize() override
    {
        return Map.size();
    }

    std::vector< std::pair<Key, Value> > get_all_entry() override;

private:
    std::unordered_map<Key, Value, Hash> Map;
    bool garbage_collection = true;
};

template<typename Key, typename Value, typename Hash>
bool DCE2_DbMap<Key, Value, Hash>::Insert(const Key& key, Value data)
{
    return Map.insert(std::make_pair(key,data)).second;
}

template<typename Key, typename Value, typename Hash>
Value DCE2_DbMap<Key, Value, Hash>::Find(const Key& key)
{
    auto elem = Map.find(key);
    if (elem != Map.end())
        return elem->second;
    return nullptr;
}

template<typename Key, typename Value, typename Hash>
void DCE2_DbMap<Key, Value, Hash>::Remove(const Key& key)
{
    auto elem = Map.find(key);
    if (elem != Map.end())
    {
        if (garbage_collection)
            delete elem->second;

        Map.erase(elem->first);
    }
}

template<typename Key, typename Value, typename Hash>
std::vector< std::pair<Key, Value> >DCE2_DbMap<Key, Value, Hash>::get_all_entry()
{
    std::vector<std::pair<Key, Value> > vec;
    std::copy(Map.begin(), Map.end(), std::back_inserter(vec));
    return vec;
}

#endif

