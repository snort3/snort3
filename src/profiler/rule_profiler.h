//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// rule_profiler.h author Joel Cornett <jocornet@cisco.com>

#ifndef RULE_PROFILER_H
#define RULE_PROFILER_H

#include <unordered_map>
#include <vector>

#include "detection/treenodes.h"
#include "main/snort_config.h"
#include "main/thread_config.h"

#include "rule_profiler_defs.h"

struct RuleProfilerConfig;
class ControlConn;
namespace snort
{
    class HashNode;
}

void prepare_rule_profiler_stats(std::vector<snort::HashNode*>&, std::unordered_map<SigInfo*, OtnState>&, unsigned);
void print_rule_profiler_stats(const RuleProfilerConfig&, const std::unordered_map<SigInfo*, OtnState>&,
    ControlConn* = nullptr, OutType = OutType::OUTPUT_TABLE);
void show_rule_profiler_stats(const RuleProfilerConfig&);
void reset_rule_profiler_stats();
void reset_thread_rule_profiler_stats(std::vector<snort::HashNode*>&, unsigned);

namespace rule_stats
{

struct View
{
    OtnState state;
    SigInfo sig_info;

    hr_duration elapsed() const
    { return state.elapsed; }

    hr_duration elapsed_match() const
    { return state.elapsed_match; }

    hr_duration elapsed_no_match() const
    { return elapsed() - elapsed_match(); }

    uint64_t checks() const
    { return state.checks; }

    uint64_t matches() const
    { return state.matches; }

    uint64_t no_matches() const
    { return checks() - matches(); }

    uint64_t alerts() const
    { return state.alerts; }

    uint64_t timeouts() const
    { return state.latency_timeouts; }

    uint64_t suspends() const
    { return state.latency_suspends; }

    hr_duration time_per(hr_duration d, uint64_t v) const
    {
        if ( v  == 0 )
            return CLOCK_ZERO;

        return hr_duration(d / v);
    }

    hr_duration avg_match() const
    { return time_per(elapsed_match(), matches()); }

    hr_duration avg_no_match() const
    { return time_per(elapsed_no_match(), no_matches()); }

    hr_duration avg_check() const
    { return time_per(elapsed(), checks()); }

    double rule_time_per(double total_time_usec) const
    {
        if (total_time_usec < 1.)
            return 100.0;
        return clock_usecs(TO_USECS(elapsed())) / total_time_usec * 100;
    }

    View(const OtnState& otn_state, const SigInfo* si = nullptr) :
        state(otn_state)
    {
        if ( si )
            // FIXIT-L does sig_info need to be initialized otherwise?
            sig_info = *si;
    }
};

}
#endif
