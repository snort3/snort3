//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/data_bus.h"
#include "main/snort_config.h"
#include "pub_sub/auxiliary_ip_event.h"

using namespace snort;
using namespace std;

bool FlowStash::get(const string& key, int32_t& val) const
{
    return get(key, val, STASH_ITEM_TYPE_INT32);
}

bool FlowStash::get(const string& key, uint32_t& val) const
{
    return get(key, val, STASH_ITEM_TYPE_UINT32);
}

bool FlowStash::get(const string& key, string& val) const
{
    return get(key, val, STASH_ITEM_TYPE_STRING);
}

bool FlowStash::get(const string& key, StashGenericObject* &val) const
{
    return get(key, val, STASH_ITEM_TYPE_GENERIC_OBJECT);
}

void FlowStash::store(const string& key, int32_t val)
{
    internal_store(key, val);
}

void FlowStash::store(const string& key, uint32_t val)
{
    internal_store(key, val);
}

void FlowStash::store(const string& key, const string& val)
{
    internal_store(key, val);
}

void FlowStash::store(const string& key, string* val)
{
    internal_store(key, val);
}

void FlowStash::store(const string& key, StashGenericObject* val)
{
    internal_store(key, val);
}

template<typename T>
bool FlowStash::get(const string& key, T& val, StashItemType type) const
{
    auto lower = lower_bound(container.begin(), container.end(), key,
        [](const unique_ptr<StashItem>& item, const string& key)
        { return 0 > item->get_key().compare(key); });
    if (lower == container.end())
        return false;
    StashItem* item = lower->get();
    if (item->get_key() == key)
    {
        if (item->get_type() == type)
        {
            item->get_val(val);
            return true;
        }
        assert(item->get_type() == type);
    }
    return false;
}

template<typename T>
void FlowStash::internal_store(const string& key, T& val)
{
    if (container.size() == container.capacity())
        container.reserve(container.size() + FLOW_STASH_INCREMENTS);
    StashItem* new_item = new StashItem(key, val);
    auto lower = lower_bound(container.begin(), container.end(), key,
        [](const unique_ptr<StashItem>& item, const string& key)
        { return 0 > item->get_key().compare(key); });
    if (lower == container.end())
        container.emplace_back(new_item);
    else
    {
        unique_ptr<StashItem>& lower_item = *lower;
        if (lower_item->get_key() == key)
            lower_item.reset(new_item);
        else
            container.emplace(lower, new_item);
    }
}

#define STASH_AUX_IP "aux_ip"

class AuxIPStashItem : public StashGenericObject
{
public:
    AuxIPStashItem() = default;
    ~AuxIPStashItem() override = default;
    bool update(const SfIp& ip, const SnortConfig* sc)
    {
        if ( any_of(aux_ip_fifo.cbegin(), aux_ip_fifo.cend(),
            [ip](const snort::SfIp& aip)
            { return aip == ip; }) )
            return false;

        while ( aux_ip_fifo.size() >= (unsigned)sc->max_aux_ip )
            aux_ip_fifo.pop_back();

        aux_ip_fifo.emplace_front(ip);
        return true;
    }

    const list<snort::SfIp>& get_aux_ip_list() const
    { return aux_ip_fifo; }

protected:
    list<snort::SfIp> aux_ip_fifo;
};

bool FlowStash::store(const SfIp& ip, const SnortConfig* sc)
{
    if ( !sc )
        sc = SnortConfig::get_conf();

    if ( sc->max_aux_ip < 0 )
        return false;

    if ( sc->max_aux_ip > 0 )
    {
        AuxIPStashItem* item;
        StashGenericObject* stash_value;
        if (!get(STASH_AUX_IP, stash_value))
        {
            item = new AuxIPStashItem;
            store(STASH_AUX_IP, item);
        }
        else
            item = static_cast<AuxIPStashItem*>(stash_value);

        if (!item->update(ip, sc))
            return false;
    }

    AuxiliaryIpEvent event(ip);
    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::AUXILIARY_IP, event);
    return true;
}

const list<snort::SfIp>* FlowStash::get_aux_ip_list() const
{
    StashGenericObject* stash_value;
    if (!get(STASH_AUX_IP, stash_value))
        return nullptr;
    AuxIPStashItem* item = static_cast<AuxIPStashItem*>(stash_value);
    return &item->get_aux_ip_list();
}
