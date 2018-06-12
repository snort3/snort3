//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "module.h"

using namespace snort;

static const Parameter defaults[] =
{
    { "trace", Parameter::PT_INT, nullptr, nullptr,
      "mask for enabling debug traces in module" },

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

void Module::sum_stats(bool accumulate_now_stats)
{
    if ( num_counts < 0 )
        reset_stats();

    PegCount* p = get_counts();
    const PegInfo* q = get_pegs();

    if ( !p )
        return;

    assert(q);

    if ( global_stats() )
    {
        for ( int i = 0; i < num_counts; i++ )
            set_peg_count(i, p[i]);
    }
    else
    {
        for ( int i = 0; i < num_counts; i++ )
        {
            switch ( q[i].type )
            {
            case CountType::END:
                break;

            case CountType::SUM:
                add_peg_count(i, p[i]);
                p[i] = 0;
                break;

            case CountType::NOW:
                if ( accumulate_now_stats )
                    add_peg_count(i, p[i]);
                break;

            case CountType::MAX:
                set_max_peg_count(i, p[i]);
                break;
            }
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
    if ( num_counts <= 0 )
    {
        num_counts = 0;
        const PegInfo* pegs = get_pegs();

        if ( !pegs )
            return;

        while ( pegs[num_counts].name )
            ++num_counts;

        counts.resize(num_counts);
    }

    for ( int i = 0; i < num_counts; i++ )
        counts[i] = 0;
}

PegCount Module::get_global_count(const char* name) const
{
    const PegInfo* infos = get_pegs();

    for ( unsigned i = 0; infos[i].name; i++ )
    {
        if ( strcmp(name, infos[i].name) == 0 )
            return counts[i];
    }
    assert(false); // wrong name = programmer error
    return 0;
}

bool Module::verified_begin(const char* fqn, int idx, SnortConfig* c)
{
    table_level++;
    return begin(fqn, idx, c);
}

bool Module::verified_set(const char* fqn, Value& v, SnortConfig* c)
{
    if ( list and table_level < 2 )
        return false;

    return set(fqn, v, c);
}

bool Module::verified_end(const char* fqn, int idx, SnortConfig* c)
{
    table_level--;
    return end(fqn, idx, c);
}

void Module::enable_trace()
{
    if ( trace )
        *trace = 1;
}

namespace snort
{
const PegInfo simple_pegs[] =
{
    { CountType::SUM, "packets", "total packets" },
    { CountType::END, nullptr, nullptr }
};
}
