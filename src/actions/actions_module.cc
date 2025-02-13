//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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

// actions_module.cc author Steve Chew <stechew@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "actions_module.h"

#include <algorithm>
#include <vector>

#include "log/messages.h"
#include "managers/action_manager.h"
#include "managers/module_manager.h"

const PegInfo end_peg[] =
{
    { CountType::END, nullptr, nullptr }
};

std::map<std::string, std::vector<PegInfo>> ActionsModule::module_peg_info_map { };

std::array<PegInfo, ACTIONS_ARRAY_SIZE> ActionsModule::peg_info_array { {end_peg[0]} };

THREAD_LOCAL std::array<PegCount, ACTIONS_ARRAY_SIZE> ActionsModule::peg_count_array {{0}};
THREAD_LOCAL std::array<PegCount, ACTIONS_ARRAY_SIZE> ActionsModule::prev_peg_count_array {{0}};


void ActionsModule::add_action(std::string module_name, const PegInfo* pegs)
{
    std::vector<PegInfo> aggregated_pegs;
    for (int i = 0; pegs[i].type != CountType::END; i++)
        aggregated_pegs.push_back(pegs[i]);

    module_peg_info_map.emplace(module_name, aggregated_pegs);

    // FIXIT-M: Probably not needed unless things change on a reload?
    std::fill(std::begin(peg_info_array), std::end(peg_info_array), end_peg[0]);

    // Go through the module names alphabetically and add their pegs.
    int i = 0;
    for (const auto& kv : module_peg_info_map)
    {
        for (const auto& peg_info : kv.second)
        {
            peg_info_array[i++] = peg_info;

            // FIXIT-L: Limited by array size.
            assert(i < MAX_ACTIONS);
            if (i >= MAX_ACTIONS)
            {
                snort::WarningMessage("Exceeded max action pegs limit (%u). Ignoring remaining action pegs.\n", MAX_ACTIONS);
                return;
            }
        }
    }

    // Peg info array must terminate with CountType::END.
    peg_info_array[i] = end_peg[0];
}

void ActionsModule::prep_counts(bool dump_stats)
{
    int peg_count = 0;
    for (auto& kv : module_peg_info_map)
    {
        Module* mod = snort::ModuleManager::get_module(kv.first.c_str());
        const PegInfo* pegs = mod->get_pegs();
        const PegCount* counts = mod->get_counts();

        for (int i=0; pegs[i].type != CountType::END; i++)
        {
            for (const auto& peg_info : kv.second)
            {
                if (0 == strcmp(peg_info.name, pegs[i].name))
                {
                    if (dump_stats)
                    {
                        // For dumping stats
                        peg_count_array[peg_count++] = counts[i];
                    }
                    else
                    {
                        // For perf monitor
                        peg_count_array[peg_count] = counts[i] - prev_peg_count_array[peg_count];
                        prev_peg_count_array[peg_count] = counts[i];

                        ++peg_count;
                    }

                    // FIXIT-L: Limited by array size.
                    assert(peg_count < MAX_ACTIONS);
                    if (peg_count >= MAX_ACTIONS)
                        return;
                    break;
                }
            }
        }
    }
}

PegCount* ActionsModule::get_counts() const
{
    return (PegCount*)&peg_count_array[0];
}

const PegInfo* ActionsModule::get_pegs() const
{
    return (PegInfo*)&peg_info_array[0];
}

