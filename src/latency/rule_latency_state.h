//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// rule_latency_state.h author Joel Cornett <jocornet@cisco.com>

#ifndef RULE_LATENCY_STATE_H
#define RULE_LATENCY_STATE_H

#include "time/clock_defs.h"

struct RuleLatencyState
{
    hr_time suspend_time { };
    unsigned timeouts = 0;
    bool suspended = false;

    void enable()
    {
        timeouts = 0;
        suspended = false;
    }

    void suspend(hr_time cur_time)
    {
        suspend_time = cur_time;
        suspended = true;
    }
};

#endif
