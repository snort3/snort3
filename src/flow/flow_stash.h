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

// flow_stash.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef FLOW_STASH_H
#define FLOW_STASH_H

// a generic store for shared flow data

#include <algorithm>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include "main/snort_types.h"
#include "sfip/sf_ip.h"

namespace snort
{
class StashItem;
struct SnortConfig;

class StashGenericObject
{
public:
    StashGenericObject() = default;
    virtual ~StashGenericObject() = default;
};

enum StashItemType
{
    STASH_ITEM_TYPE_INT32,
    STASH_ITEM_TYPE_UINT32,
    STASH_ITEM_TYPE_STRING,
    STASH_ITEM_TYPE_GENERIC_OBJECT
};

union StashItemVal
{
    int32_t int32_val;
    uint32_t uint32_val;
    std::string* str_val;
    StashGenericObject* generic_obj_val;
};

class StashItem
{
public:
    StashItem(const std::string& the_key, int32_t int32_val) : key(the_key)
    {
        type = STASH_ITEM_TYPE_INT32;
        val.int32_val = int32_val;
    }

    StashItem(const std::string& the_key, uint32_t uint32_val) : key(the_key)
    {
        type = STASH_ITEM_TYPE_UINT32;
        val.uint32_val = uint32_val;
    }

    StashItem(const std::string& the_key, const std::string& str_val) : key(the_key)
    {
        type = STASH_ITEM_TYPE_STRING;
        val.str_val = new std::string(str_val);
    }

    StashItem(const std::string& the_key, std::string* str_val) : key(the_key)
    {
        type = STASH_ITEM_TYPE_STRING;
        val.str_val = str_val;
    }

    StashItem(const std::string& the_key, StashGenericObject* obj) : key(the_key)
    {
        type = STASH_ITEM_TYPE_GENERIC_OBJECT;
        val.generic_obj_val = obj;
    }

    ~StashItem()
    {
        switch (type)
        {
        case STASH_ITEM_TYPE_STRING:
            delete val.str_val;
            break;
        case STASH_ITEM_TYPE_GENERIC_OBJECT:
            delete val.generic_obj_val;
        default:
            break;
        }
    }

    const std::string& get_key() const
    { return key; }

    StashItemType get_type() const
    { return type; }

    void get_val(int32_t& int32_val) const
    { int32_val = val.int32_val; }

    void get_val(uint32_t& uint32_val) const
    { uint32_val = val.uint32_val; }

    void get_val(std::string& str_val) const
    { str_val = *(val.str_val); }

    void get_val(StashGenericObject* &obj_val) const
    { obj_val = val.generic_obj_val; }

private:
    std::string key;
    StashItemType type;
    StashItemVal val;
};

class SO_PUBLIC FlowStash
{
public:
    FlowStash() = default;
    ~FlowStash()
    { reset(); }

    void reset()
    { container.clear(); }

    bool get(const std::string& key, int32_t& val) const;
    bool get(const std::string& key, uint32_t& val) const;
    bool get(const std::string& key, std::string& val) const;
    bool get(const std::string& key, StashGenericObject* &val) const;

    void store(const std::string& key, int32_t val);
    void store(const std::string& key, uint32_t val);
    void store(const std::string& key, const std::string& val);
    void store(const std::string& key, std::string* val);
    void store(const std::string& key, StashGenericObject* val);

    bool store(const snort::SfIp&, const SnortConfig*);

    const std::list<snort::SfIp>* get_aux_ip_list() const;

private:
    static constexpr unsigned FLOW_STASH_INCREMENTS = 7;

    std::vector<std::unique_ptr<StashItem>> container;

    template<typename T>
    bool get(const std::string& key, T& val, StashItemType type) const;
    template<typename T>
    void internal_store(const std::string& key, T& val);
};

}

#endif
