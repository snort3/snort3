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

// flow_stash.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef FLOW_STASH_H
#define FLOW_STASH_H

#include <string>
#include <vector>

#include "main/snort_types.h"

#include "flow_stash_keys.h"
#include "stash_item.h"

namespace snort
{

class SO_PUBLIC FlowStash
{
public:
    FlowStash() : container(STASH_MAX_SIZE, nullptr) { }
    ~FlowStash();
    void reset();
    bool get(const int& key, int32_t& val);
    bool get(const int& key, uint32_t& val);
    bool get(const int& key, std::string& val);
    bool get(const int& key, std::string*& val);
    bool get(const int& key, StashGenericObject* &val);
    void store(const int& key, int32_t val);
    void store(const int& key, uint32_t val);
    void store(const int& key, const std::string& val);
    void store(const int& key, std::string* val);
    void store(const int& key, StashGenericObject* val);
    void remove(const FlowStashKey& key);

private:
    std::vector<StashItem*> container;

    template<typename T>
    bool get(const int& key, T& val, StashItemType type);
    template<typename T>
    void store(const int& key, T& val, StashItemType type);
    void store(const int& key, StashGenericObject* &val, StashItemType type);
};

}

#endif
