//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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


static const Parameter defaults[] =
{
    { "trace", Parameter::PT_INT, nullptr, nullptr,
      "mask for enabling debug traces in module"  },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

std::string Command::get_arg_list() const
{
    std::string args = "(";
    const Parameter* p = params;

    while ( p and p->name )
    {
        if ( p != params )
            args += ", ";
        args += p->name;
        ++p;
    }
    args += ")";
    return args;
}

void Module::init(const char* s, const char* h)
{
    name = s;
    help = h;
    params = &defaults[(sizeof(defaults) / sizeof(Parameter)) - 1];
    default_params = params;
    list = false;
    num_counts = -1;
}

Module::Module(const char* s, const char* h)
{ init(s, h); }

Module::Module(const char* s, const char* h, const Parameter* p, bool is_list, Trace* t)
{
    init(s, h);
    list = is_list;
    trace = t;
    params = p;

    // FIXIT-L: This will not be valid after adding more default options
    if ( t )
        default_params = defaults;
}

bool Module::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("trace") )
    {
        if ( trace )
            *trace = v.get_long();
    }
    else
        return false;
    return true;
}

void Module::sum_stats()
{
    if ( num_counts < 0 )
        reset_stats();

    PegCount* p = get_counts();

    if ( !p )
        return;

    if ( global_stats() )
    {
        for ( int i = 0; i < num_counts; i++ )
            counts[i] = p[i];
    }
    else
    {
        for ( int i = 0; i < num_counts; i++ )
        {
            counts[i] += p[i];
            p[i] = 0;
        }
    }
}

void Module::show_interval_stats(IndexVec& peg_idxs, FILE* fh)
{
    if ( num_counts > 0 )
        ::show_stats(get_counts(), get_pegs(), peg_idxs, get_name(), fh);
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

