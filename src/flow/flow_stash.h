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

#include <map>
#include <string>

#include "main/snort_types.h"

#include "stash_item.h"

namespace snort
{

class SO_PUBLIC FlowStash
{
public:
    ~FlowStash();
    void reset();
    bool get(const std::string& key, int32_t& val);
    bool get(const std::string& key, uint32_t& val);
    bool get(const std::string& key, std::string& val);
    bool get(const std::string& key, StashGenericObject* &val);
    void store(const std::string& key, int32_t val);
    void store(const std::string& key, uint32_t val);
    void store(const std::string& key, const std::string& val);
    void store(const std::string& key, std::string* val);
    void store(const std::string& key, StashGenericObject* val);

private:
    std::map<std::string, StashItem*> container;

    template<typename T>
    bool get(const std::string& key, T& val, StashItemType type);
    template<typename T>
    void store(const std::string& key, T& val, StashItemType type);
    void store(const std::string& key, StashGenericObject* &val, StashItemType type);
};

}

#endif
