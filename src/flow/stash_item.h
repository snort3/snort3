//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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

// stash_item.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef STASH_ITEM_H
#define STASH_ITEM_H

#include <cstdint>
#include <string>

#define STASH_APPID_DATA "appid_data"

#define STASH_GENERIC_OBJECT_APPID 1
#define STASH_GENERIC_OBJECT_MIME 2

namespace snort
{

class StashGenericObject
{
public:
    StashGenericObject(int type) : object_type(type)
    { }

    virtual ~StashGenericObject() = default;

    int get_object_type() const
    { return object_type; }

private:
    int object_type;
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
    StashItem(int32_t int32_val)
    {
        type = STASH_ITEM_TYPE_INT32;
        val.int32_val = int32_val;
    }

    StashItem(uint32_t uint32_val)
    {
        type = STASH_ITEM_TYPE_UINT32;
        val.uint32_val = uint32_val;
    }

    StashItem(const std::string& str_val)
    {
        type = STASH_ITEM_TYPE_STRING;
        val.str_val = new std::string(str_val);
    }

    StashItem(std::string* str_val)
    {
        type = STASH_ITEM_TYPE_STRING;
        val.str_val = str_val;
    }

    StashItem(StashGenericObject* obj)
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
    StashItemType type;
    StashItemVal val;
};

}

#endif
