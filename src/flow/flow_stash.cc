//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

// flow_stash.cc author Shravan Rangaraju <shrarang@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow_stash.h"

#include <cassert>

#include "pub_sub/stash_events.h"

using namespace snort;
using namespace std;

FlowStash::~FlowStash()
{
    reset();
}

void FlowStash::reset()
{
    for (auto& it : container)
    {
        if (it)
        {
            delete it;
            it = nullptr;
        }
    }
}

void FlowStash::remove(const FlowStashKey& key)
{
    auto& item = container[key];

    if (item)
    {
        delete item;
        item = nullptr;
    }
}

bool FlowStash::get(const int& key, int32_t& val)
{
    return get(key, val, STASH_ITEM_TYPE_INT32);
}

bool FlowStash::get(const int& key, uint32_t& val)
{
    return get(key, val, STASH_ITEM_TYPE_UINT32);
}

bool FlowStash::get(const int& key, string& val)
{
    return get(key, val, STASH_ITEM_TYPE_STRING);
}

bool FlowStash::get(const int& key, string*& val)
{
    auto& it = container[key];

    if (it)
    {
        assert(it->get_type() == STASH_ITEM_TYPE_STRING);
        it->get_val(val);
        return true;
    }
    return false;
}

bool FlowStash::get(const int& key, StashGenericObject* &val)
{
    return get(key, val, STASH_ITEM_TYPE_GENERIC_OBJECT);
}

void FlowStash::store(const int& key, int32_t val)
{
    store(key, val, STASH_ITEM_TYPE_INT32);
}

void FlowStash::store(const int& key, uint32_t val)
{
    store(key, val, STASH_ITEM_TYPE_UINT32);
}

void FlowStash::store(const int& key, const string& val)
{
    store(key, val, STASH_ITEM_TYPE_STRING);
}

void FlowStash::store(const int& key, StashGenericObject* val)
{
    store(key, val, STASH_ITEM_TYPE_GENERIC_OBJECT);
}

void FlowStash::store(const int& key, StashGenericObject* &val, StashItemType type)
{
#ifdef NDEBUG
    UNUSED(type);
#endif
    auto& it = container[key];
    if (it)
        delete it;

    it = new StashItem(val);
    assert(it->get_type() == type);

    StashEvent e(it);
    DataBus::publish(get_key_name(key), e);
}

void FlowStash::store(const int& key, std::string* val)
{
    store(key, val, STASH_ITEM_TYPE_STRING);
}

template<typename T>
bool FlowStash::get(const int& key, T& val, StashItemType type)
{
#ifdef NDEBUG
    UNUSED(type);
#endif
    auto& it = container[key];

    if (it)
    {
        assert(it->get_type() == type);
        it->get_val(val);
        return true;
    }
    return false;
}

template<typename T>
void FlowStash::store(const int& key, T& val, StashItemType type)
{
#ifdef NDEBUG
    UNUSED(type);
#endif
    auto& it = container[key];
    if (it)
        delete it;

    it = new StashItem(val);
    assert(it->get_type() == type);

    StashEvent e(it);
    DataBus::publish(get_key_name(key), e);
}
