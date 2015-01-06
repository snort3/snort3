//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// module.cc author Russ Combs <rucombs@cisco.com>

#include "module.h"
#include "parameter.h"
#include "utils/stats.h"

static const Parameter null_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

void Module::init(const char* s, const char* h)
{
    name = s;
    help = h;
    params = null_params;
    list = false;
    cmds = nullptr;
    rules = nullptr;
    num_counts = -1;
}

Module::Module(const char* s, const char* h)
{ init(s, h); }

Module::Module(const char* s, const char* h, const Parameter* p, bool is_list)
{
    init(s, h);
    params = p;
    list = is_list;
}

void Module::sum_stats()
{
    if ( num_counts < 0 )
        reset_stats();

    PegCount* p = get_counts();

    if ( !p )
        return;

    for ( int i = 0; i < num_counts; i++ )
    {
        counts[i] += p[i];
        p[i] = 0;
    }
}

void Module::show_stats()
{
    if ( num_counts > 0 )
        ::show_stats(&counts[0], get_pegs(), num_counts, get_name());
}

void Module::reset_stats()
{
    num_counts = 0;
    const PegInfo* pegs = get_pegs();

    if ( !pegs )
        return;

    while ( pegs[num_counts].name )
        ++num_counts;

    counts.resize(num_counts);

    for ( int i = 0; i < num_counts; i++ )
        counts[i] = 0;
}

const PegInfo simple_pegs[] =
{
    { "packets", "total packets" },
    { nullptr, nullptr }
};

