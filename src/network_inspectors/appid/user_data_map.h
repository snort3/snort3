//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

// user_data_map.h author Cliff Judge <cljudge@cisco.com>

#ifndef USER_DATA_MAP_H
#define USER_DATA_MAP_H

/* User Data Map uses an unordered map to store arbitrary user-defined key value pairs
 * used in lua detectors. Mappings are loaded from appid.conf or userappid.conf using a
 * key that is hardcoded in the detector. The user supplies the value. At runtime, if the lua
 * detector's conditions are met during validation, the lua detector can use its key to
 * retrieve the customer data.
 */

#include <string>
#include <unordered_map>

#include "trace/trace_api.h"

#include "appid_debug.h"

typedef std::unordered_map<std::string, std::unordered_map<std::string, std::string>>
    UserDataMaps;

class UserDataMap
{
public:
    ~UserDataMap();
    void add_user_data(const std::string& table, const std::string& key,
        const std::string& item);
    const char* get_user_data_value_str(const std::string& table, const std::string& key);
private:
    UserDataMaps user_data_maps;
};

#endif
