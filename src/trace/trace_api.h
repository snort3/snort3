//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// trace_api.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef TRACE_API_H
#define TRACE_API_H

#include <cstdint>

namespace snort
{
struct SnortConfig;

class TraceApi
{
public:
    static void thread_init(const SnortConfig* sc);
    static void thread_reinit(const SnortConfig* sc);
    static void thread_term();

    static void log(const char* log_msg, const char* name,
        uint8_t log_level, const char* trace_option);
};
}

#endif // TRACE_API_H

