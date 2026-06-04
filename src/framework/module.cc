//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
#include "main/thread_config.h"

#include "trace/trace.h"
#include "utils/stats.h"

using namespace snort;

static const Parameter null_params[] =
{
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
    list = false;
    num_counts = -1;
    params = null_params;
}

Module::Module(const char* s, const char* h)
{ init(s, h); }

Module::Module(const char* s, const char* h, const Parameter* p, bool is_list)
{
    init(s, h);
    list = is_list;
    params = p;
}

void Module::clear_global_active_counters()
{
    PegCount* p = get_counts();

    if ( !p )
        return;

    const PegInfo* q = get_pegs();

    assert(q);
    for ( unsigned thread_index = 0; thread_index < dump_stats_counts.size(); thread_index++)
    {
        for ( int i = 0; i < num_counts; i++ )
        {
            if ( q[i].type == CountType::NOW )
            {
                dump_stats_counts[thread_index][i] = 0;
                counts[thread_index][i] = 0;
                dump_stats_results[i] = 0;
            }
        }
    }
}

void Module::main_accumulate_stats()
{
    const PegInfo* q = get_pegs();

    if ( !q )
        return;

    if ( global_stats() )
        return;

    aggregate_dump_stats_counts(q, num_counts, dump_stats_counts, dump_stats_results);
}

void Module::aggregate_dump_stats_counts(
    const PegInfo* pegs,
    int num_counts,
    const std::vector<std::vector<PegCount>>& per_thread_counts,
    std::vector<PegCount>& out)
{
    if ( !pegs || num_counts <= 0 )
        return;

    std::vector<const std::vector<PegCount>*> ptrs;
    ptrs.reserve(per_thread_counts.size());
    for ( const auto& counts : per_thread_counts )
        ptrs.emplace_back(&counts);

    aggregate_dump_stats_counts(pegs, num_counts, ptrs, out);
}

void Module::aggregate_dump_stats_counts(
    const PegInfo* pegs,
    int num_counts,
    const std::vector<const std::vector<PegCount>*>& per_thread_counts,
    std::vector<PegCount>& out)
{
    if ( !pegs || num_counts <= 0 )
        return;

    out.assign(num_counts, 0);

    for ( const auto* counts : per_thread_counts )
    {
        if ( !counts || (int)counts->size() != num_counts )
            continue;

        for ( int peg_idx = 0; peg_idx < num_counts; peg_idx++ )
        {
            switch ( pegs[peg_idx].type )
            {
            case CountType::END:
                break;

            case CountType::SUM:
            case CountType::NOW:
                out[peg_idx] += (*counts)[peg_idx];
                break;

            case CountType::MAX:
                if ( (*counts)[peg_idx] > out[peg_idx] )
                    out[peg_idx] = (*counts)[peg_idx];
                break;
            }
        }
    }
}


void Module::sum_stats(bool dump_stats)
{
    if ( num_counts < 0 )
        init_stats();

    PegCount* p = get_counts();
    const PegInfo* q = get_pegs();

    if ( !p )
        return;

    assert(q);

    unsigned instance_id = get_instance_id();
    if (dump_stats and !dump_stats_initialized[instance_id])
    {
        dump_stats_counts[instance_id] = counts[instance_id];
        dump_stats_initialized[instance_id] = 1;
    }

    if ( global_stats() )
    {
        for ( int i = 0; i < num_counts; i++ )
        {
            // we need each thread to update the same variable since it is global stats.
            // we need the latest info updated by the last thread
            if (dump_stats)
                dump_stats_results[i] = p[i];
            else
                counts[0][i] = p[i];
        }
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
                add_peg_count(i, p[i], dump_stats);
                if (!dump_stats)
                    p[i] = 0;
                break;

            case CountType::NOW:
                if (dump_stats)
                    add_peg_count(i, p[i], dump_stats);
                break;

            case CountType::MAX:
                set_max_peg_count(i, p[i], dump_stats);
                if (!dump_stats)
                    p[i] = 0;
                break;
            }
        }
    }
}

void Module::collect_dump_stats_counts(std::vector<PegCount>& out)
{
    if ( num_counts < 0 )
        init_stats();

    PegCount* p = get_counts();
    const PegInfo* q = get_pegs();

    if ( !p || !q || num_counts <= 0 )
    {
        out.clear();
        return;
    }

    out.assign(num_counts, 0);

    if ( global_stats() )
    {
        for ( int i = 0; i < num_counts; i++ )
            out[i] = p[i];
        return;
    }

    const unsigned instance_id = get_instance_id();
    if ( instance_id >= counts.size() )
        return;

    for ( int i = 0; i < num_counts; i++ )
    {
        switch ( q[i].type )
        {
        case CountType::END:
            break;

        case CountType::SUM:
        case CountType::NOW:
            out[i] = counts[instance_id][i] + p[i];
            break;

        case CountType::MAX:
            out[i] = (p[i] > counts[instance_id][i]) ? p[i] : counts[instance_id][i];
            break;
        }
    }
}

void Module::set_dump_stats_results(const std::vector<PegCount>& results)
{
    if ( num_counts < 0 )
        init_stats();

    if ( num_counts <= 0 )
        return;

    if ( (int)results.size() != num_counts )
        return;

    dump_stats_results = results;
}

const std::vector<PegCount>& Module::get_dump_stats_results() const
{
    return dump_stats_results;
}

void Module::clear_dump_stats_state()
{
    if ( num_counts > 0 )
        dump_stats_initialized.assign(dump_stats_initialized.size(), 0);
}

void Module::show_interval_stats(std::vector<unsigned>& peg_idxs, FILE* fh)
{
    if ( num_counts > 0 )
        ::show_stats(get_counts(), get_pegs(), peg_idxs, get_name(), fh);
}

void Module::show_stats()
{
    if ( num_counts > 0 )
    {
        ::show_stats(&dump_stats_results[0], get_pegs(), num_counts, get_name());
        clear_dump_stats_state();
    }
}

void Module::init_stats(bool new_thread)
{
    const PegInfo* pegs = get_pegs();

    if ( !pegs )
        return;

    if ( num_counts <= 0 )
    {
        num_counts = 0;

        while ( pegs[num_counts].name )
            ++num_counts;
    }

    unsigned number_of_threads = new_thread ? 1 : ThreadConfig::get_instance_max();

    for ( unsigned thread_index = 0; thread_index < number_of_threads; thread_index++)
    {
        counts.emplace_back(num_counts);
        dump_stats_counts.emplace_back(num_counts);
        dump_stats_initialized.push_back(0);
    }
    dump_stats_results.resize(num_counts);
}


void Module::reset_stats()
{
    PegCount* p = get_counts();

    if ( !p )
        return;

    const PegInfo* pegs = get_pegs();

    if ( !pegs )
        return;


    for ( int i = 0; i < num_counts; i++ )
    {
        counts[get_instance_id()][i] = 0;
        dump_stats_counts[get_instance_id()][i] = 0;

        if ( pegs[i].type != CountType::NOW )
            p[i] = 0;
    }
}

PegCount Module::get_global_count(const char* name) const
{
    const PegInfo* infos = get_pegs();
    assert(infos);

    for ( unsigned i = 0; infos[i].name; i++ )
    {
        if ( strcmp(name, infos[i].name) == 0 )
            return dump_stats_results[i];
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

namespace snort
{
const PegInfo simple_pegs[] =
{
    { CountType::SUM, "packets", "total packets" },
    { CountType::END, nullptr, nullptr }
};
}
