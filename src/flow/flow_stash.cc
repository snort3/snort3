//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "pub_sub/auxiliary_ip_event.h"
#include "pub_sub/stash_events.h"

using namespace snort;
using namespace std;

FlowStash::~FlowStash()
{
    reset();
}

void FlowStash::reset()
{
    for(auto it = container.begin(); it != container.end(); ++it)
    {
        delete it->second;
    }
    container.clear();
}

bool FlowStash::get(const string& key, int32_t& val)
{
    return get(key, val, STASH_ITEM_TYPE_INT32);
}

bool FlowStash::get(const string& key, uint32_t& val)
{
    return get(key, val, STASH_ITEM_TYPE_UINT32);
}

bool FlowStash::get(const string& key, string& val)
{
    return get(key, val, STASH_ITEM_TYPE_STRING);
}

bool FlowStash::get(const string& key, StashGenericObject* &val)
{
    return get(key, val, STASH_ITEM_TYPE_GENERIC_OBJECT);
}

void FlowStash::store(const string& key, int32_t val, unsigned pubid, unsigned evid)
{
    store(key, val, STASH_ITEM_TYPE_INT32, pubid, evid);
}

void FlowStash::store(const string& key, uint32_t val, unsigned pubid, unsigned evid)
{
    store(key, val, STASH_ITEM_TYPE_UINT32, pubid, evid);
}

void FlowStash::store(const string& key, const string& val, unsigned pubid, unsigned evid)
{
    store(key, val, STASH_ITEM_TYPE_STRING, pubid, evid);
}

void FlowStash::store(const string& key, string* val, unsigned pubid, unsigned evid)
{
    store(key, val, STASH_ITEM_TYPE_STRING, pubid, evid);
}

void FlowStash::store(const string& key, StashGenericObject* val, unsigned pubid, unsigned evid)
{
    store(key, val, STASH_ITEM_TYPE_GENERIC_OBJECT, pubid, evid);
}

void FlowStash::store(const string& key, StashGenericObject* &val, StashItemType type, unsigned pubid, unsigned evid)
{
#ifdef NDEBUG
    UNUSED(type);
#endif
    auto item = new StashItem(val);
    auto it_and_status = container.emplace(key, item);

    if (!it_and_status.second)
    {
        StashGenericObject* stored_object;
        assert(it_and_status.first->second->get_type() == type);
        it_and_status.first->second->get_val(stored_object);
        assert(stored_object->get_object_type() == val->get_object_type());
        delete it_and_status.first->second;
        it_and_status.first->second = item;
    }

    if (DataBus::valid(pubid))
    {
        StashEvent e(item);
        DataBus::publish(pubid, evid, e);
    }
}

template<typename T>
bool FlowStash::get(const string& key, T& val, StashItemType type)
{
#ifdef NDEBUG
    UNUSED(type);
#endif
    auto it = container.find(key);

    if (it != container.end())
    {
        assert(it->second->get_type() == type);
        it->second->get_val(val);
        return true;
    }
    return false;
}

template<typename T>
void FlowStash::store(const string& key, T& val, StashItemType type, unsigned pubid, unsigned evid)
{
#ifdef NDEBUG
    UNUSED(type);
#endif
    auto item = new StashItem(val);
    auto it_and_status = container.emplace(key, item);

    if (!it_and_status.second)
    {
        assert(it_and_status.first->second->get_type() == type);
        delete it_and_status.first->second;
        it_and_status.first->second = item;
    }

    StashEvent e(item);
    DataBus::publish(pubid, evid, e);
}

bool FlowStash::store(const SfIp& ip, const SnortConfig* sc)
{
    if ( !sc )
        sc = SnortConfig::get_conf();

    if ( sc->max_aux_ip < 0 )
        return false;

    if ( sc->max_aux_ip > 0 )
    {
        if ( std::any_of(aux_ip_fifo.cbegin(), aux_ip_fifo.cend(),
            [ip](const snort::SfIp& aip){ return aip == ip; }) )
            return false;

        if ( aux_ip_fifo.size() == (unsigned)sc->max_aux_ip )
            aux_ip_fifo.pop_back();

        aux_ip_fifo.emplace_front(ip);
    }

    AuxiliaryIpEvent event(ip);
    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::AUXILIARY_IP, event);
    return true;
}
