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

// rule_latency_config.h author Joel Cornett <jocornet@cisco.com>

#ifndef RULE_LATENCY_CONFIG_H
#define RULE_LATENCY_CONFIG_H

#include "time/clock_defs.h"

struct RuleLatencyConfig
{
    enum Action
    {
        NONE = 0x00,
        ALERT = 0x01,
        LOG = 0x02,
        ALERT_AND_LOG = ALERT | LOG
    };

    hr_duration max_time = 0_ticks;
    bool suspend = false;
    unsigned suspend_threshold = 0;
    hr_duration max_suspend_time = 0_ticks;
    Action action = NONE;

    bool enabled() const { return max_time > 0_ticks; }
    bool allow_reenable() const { return max_suspend_time > 0_ticks; }
};

#endif
