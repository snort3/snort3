//--------------------------------------------------------------------------
// Copyright (C) 2025 Cisco and/or its affiliates. All rights reserved.
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
// detection_events.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "detection_events.h"

using namespace snort;

static const char* merge_with_colon(const char* first, const char* second)
{
    size_t length = std::strlen(first) + std::strlen(second) + 2;
    char* result = new char[length];

    std::sprintf(result, "%s:%s", first, second);

    return result;
}

static std::string strip_msg(const char* msg)
{
    std::string str(msg);
    if (str.front() == '"' and str.back() == '"')
        str = str.substr(1, str.length() - 2);

    return str;
}

const std::vector<const char*>& IpsRuleEvent::get_references() const
{
    if (!references.empty())
        return references;

    unsigned idx = 0;
    const char* name = nullptr;
    const char* id = nullptr;
    const char* url = nullptr;

    while (get_reference(idx++, name, id, url))
    {
        if (url and *url)
            references.push_back(merge_with_colon(url, id));
        else
            references.push_back(merge_with_colon(name, id));
    }

    return references;
}

const std::string& IpsRuleEvent::get_stripped_msg() const
{
    if (stripped_msg.empty())
        stripped_msg = strip_msg(get_msg());

    return stripped_msg;
}

const std::string& IpsQueuingEvent::get_stripped_msg() const
{
    if (stripped_msg.empty())
        stripped_msg = strip_msg(get_msg());

    return stripped_msg;
}
