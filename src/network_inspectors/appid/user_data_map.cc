//--------------------------------------------------------------------------
// Copyright (C) 2021-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "main/thread.h"

static THREAD_LOCAL bool configuration_completed;

UserDataMap::~UserDataMap()
{
    user_data_maps.clear();
}

bool UserDataMap::add_user_data(const std::string &table, const std::string &key,
                                const std::string &item, bool override_existing)
{

    if (snort::get_thread_type() != SThreadType::STHREAD_TYPE_MAIN)
    {
        if (configuration_completed)
            APPID_LOG(nullptr, TRACE_WARNING_LEVEL, "AppId: ignoring user data with key %s in table %s from non-main thread\n",
                key.c_str(), table.c_str());
        return false;
    }

    auto table_it = user_data_maps.find(table);
    if (table_it != user_data_maps.end())
    {
        if (override_existing)
        {
            table_it->second[key] = item;
        }
        else
        {
            auto insert_result = table_it->second.try_emplace(key, item);
            if (insert_result.second == false)
            {
                APPID_LOG(nullptr, TRACE_WARNING_LEVEL, "AppId: ignoring duplicate key %s in table %s\n",
                    key.c_str(), table.c_str());
                return false;
            }
        }
    }
    else
    {
        std::unordered_map<std::string, std::string> user_map;
        user_map[key] = item;
        user_data_maps[table] = std::move(user_map);
    }

    return true;
}

const char* UserDataMap::get_user_data_value_str(const std::string& table,
    const std::string& key)
{
    auto table_it = user_data_maps.find(table);
    if (table_it != user_data_maps.end())
    {
        auto key_it = table_it->second.find(key);
        if (key_it != table_it->second.end())
        {
            return key_it->second.c_str();
        }
    }
    
    return nullptr;
}

void UserDataMap::set_configuration_completed(bool completed)
{
    configuration_completed = completed;
}
