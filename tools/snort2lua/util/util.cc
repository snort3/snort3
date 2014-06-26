/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// snort2lua_util.h author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>
#include "util/util.h"
#include "conversion_state.h"

namespace util
{




std::vector<std::string> &split(const std::string &s, 
                                char delim, 
                                std::vector<std::string> &elems)
{
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim))
    {
        elems.push_back(item);
    }

    return elems;
}

const ConvertMap* find_map(const std::vector<const ConvertMap*> map, std::string keyword)
{
    for (const ConvertMap *p : map)
        if (p->keyword.compare(0, p->keyword.size(), keyword) == 0)
            return p;

    return nullptr;
}


} // namespace util
