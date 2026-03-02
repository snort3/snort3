//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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
// trace_swap.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef TRACE_SWAP_H
#define TRACE_SWAP_H

namespace snort
{
struct Command;
struct Parameter;
}

class TraceParser;

struct lua_State;

class TraceSwapParams
{
public:
    static void set_params(const snort::Parameter*);
    static const snort::Parameter* get_params();

    static int set(lua_State*);
    static int clear(lua_State*);

private:
    static bool set_ntuple(lua_State*, TraceParser&, const snort::Parameter*);
    static bool set_timestamp(lua_State*, TraceParser&, const snort::Parameter*);
    static bool set_output(lua_State*, TraceParser&, const snort::Parameter*);
    static bool set_modules(lua_State*, TraceParser&, const snort::Parameter*);
    static bool set_constraints(lua_State*, TraceParser&, const snort::Parameter*);

    static const snort::Parameter* s_params;
};

#endif

