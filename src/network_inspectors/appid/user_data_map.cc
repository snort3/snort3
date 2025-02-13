//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

// user_data_map.cc author Cliff Judge <cljudge@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "user_data_map.h"

UserDataMap::~UserDataMap()
{
    user_data_maps.clear();
}

void UserDataMap::add_user_data(const std::string& table, const std::string& key,
    const std::string& item)
{
    if (user_data_maps.find(table) != user_data_maps.end())
    {
        if (user_data_maps[table].find(key) != user_data_maps[table].end())
        {
            APPID_LOG(nullptr, TRACE_WARNING_LEVEL,"ignoring duplicate key %s in table %s",
                key.c_str(), table.c_str());
            return;
        }
        user_data_maps[table][key] = item;
    }
    else
    {
        std::unordered_map<std::string, std::string> user_map;
        user_map[key] = item;
        user_data_maps[table] = user_map;
    }
}

const char* UserDataMap::get_user_data_value_str(const std::string& table,
    const std::string& key)
{
    if (user_data_maps.find(table) != user_data_maps.end() and
        user_data_maps[table].find(key) != user_data_maps[table].end())
    {
        return user_data_maps[table][key].c_str();
    }
    else
        return nullptr;
}
