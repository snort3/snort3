//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

class TraceSwapParams
{
public:
    static void set_params(const snort::Parameter* params);

    static const snort::Command* get_commands();
    static const snort::Parameter* get_params();

private:
    static const snort::Command* s_commands;
    static const snort::Parameter* s_params;
};

#endif // TRACE_SWAP_H

