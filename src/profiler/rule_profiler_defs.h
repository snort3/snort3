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

// rule_profiler_defs.h author Joel Cornett <jocornet@cisco.com>

#ifndef RULE_PROFILER_DEFS_H
#define RULE_PROFILER_DEFS_H

#include "time/clock_defs.h"
#include "time/stopwatch.h"

struct dot_node_state_t;

struct RuleProfilerConfig
{
    enum Sort
    {
        SORT_NONE = 0,
        SORT_CHECKS,
        SORT_AVG_CHECK,
        SORT_TOTAL_TIME,
        SORT_MATCHES,
        SORT_NO_MATCHES,
        SORT_AVG_MATCH,
        SORT_AVG_NO_MATCH
    } sort = SORT_TOTAL_TIME;

    bool show = false;
    unsigned count = 0;
};

class RuleContext
{
public:
    RuleContext(dot_node_state_t& stats) :
        stats(stats)
    { start(); }

    ~RuleContext()
    { stop(); }

    void start()
    { sw.start(); }

    void pause()
    { sw.stop(); }

    void stop(bool = false);

    bool active() const
    { return sw.active(); }

private:
    dot_node_state_t& stats;
    Stopwatch<SnortClock> sw;
    bool finished = false;
};

class RulePause
{
public:
    RulePause(RuleContext& ctx) :
        ctx(ctx)
    { ctx.pause(); }

    ~RulePause()
    { ctx.start(); }

private:
    RuleContext& ctx;
};

#endif
