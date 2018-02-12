//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// lua_util.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lua_util.h"

#define LUA_MSG_BUFSIZE     128

namespace Lua
{
const char* fmt_expected_message(const char* type)
{
    static char buf[LUA_MSG_BUFSIZE];
    snprintf(buf, LUA_MSG_BUFSIZE, "expected %s", type);
    return buf;
}

const char* fmt_range_message(unsigned min, unsigned max)
{
    static char buf[LUA_MSG_BUFSIZE];
    snprintf(
        buf, LUA_MSG_BUFSIZE, "must be between %lld and %lld",
        static_cast<long long>(min), static_cast<long long>(max)
    );

    return buf;
}
}
