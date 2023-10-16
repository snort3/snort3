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

// flow_stash.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef FLOW_STASH_H
#define FLOW_STASH_H

#include <list>
#include <map>
#include <string>
#include <unordered_map>

#include "main/snort_config.h"
#include "main/snort_types.h"
#include "sfip/sf_ip.h"

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

    void store(const std::string& key, int32_t val, unsigned pubid = 0, unsigned evid = 0);
    void store(const std::string& key, uint32_t val, unsigned pubid = 0, unsigned evid = 0);
    void store(const std::string& key, const std::string& val, unsigned pubid = 0, unsigned evid = 0);
    void store(const std::string& key, std::string* val, unsigned pubid = 0, unsigned evid = 0);
    void store(const std::string& key, StashGenericObject* val, unsigned pubid = 0, unsigned evid = 0);

    bool store(const snort::SfIp&, const SnortConfig* sc = nullptr);

    std::list<snort::SfIp>& get_aux_ip_list()
    { return aux_ip_fifo; }

private:
    std::list<snort::SfIp> aux_ip_fifo;
    std::unordered_map<std::string, StashItem*> container;

    template<typename T>
    bool get(const std::string& key, T& val, StashItemType type);
    template<typename T>
    void store(const std::string& key, T& val, StashItemType type, unsigned = 0, unsigned = 0);
    void store(const std::string& key, StashGenericObject* &val, StashItemType type, unsigned, unsigned);
};

}

#endif
