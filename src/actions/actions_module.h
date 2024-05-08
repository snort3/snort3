//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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

// actions_module.h author Steve Chew <stechew@cisco.com>

// Aggregates counters from all of the IPS actions.

#ifndef ACTIONS_MODULE_H
#define ACTIONS_MODULE_H

#include <map>
#include <vector>

#include "framework/module.h"

#define ACTIONS_ARRAY_SIZE UINT8_MAX
#define MAX_ACTIONS (ACTIONS_ARRAY_SIZE-1)

class ActionsModule : public snort::Module
{
public:
    ActionsModule() : snort::Module("ips_actions", "aggregate action counters")
    { }

    Usage get_usage() const override
    { return GLOBAL; }

    static void add_action(std::string module_name, const PegInfo* pegs);
    void prep_counts(bool) override;
    PegCount* get_counts() const override;
    const PegInfo* get_pegs() const override;

    bool counts_need_prep() const override
    { return true; }

    bool is_aggregator() const override
    { return true; }

private:
    static std::map<std::string, std::vector<PegInfo>> module_peg_info_map;
    static std::array<PegInfo, ACTIONS_ARRAY_SIZE> peg_info_array;
    static THREAD_LOCAL std::array<PegCount, ACTIONS_ARRAY_SIZE> peg_count_array;
    static THREAD_LOCAL std::array<PegCount, ACTIONS_ARRAY_SIZE> prev_peg_count_array;
};

#endif

