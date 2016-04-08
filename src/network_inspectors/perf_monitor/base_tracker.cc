//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// base_tracker.cc author Carter Waxman <cwaxman@cisco.com>

#include "base_tracker.h"
#include "perf_module.h"

#include "framework/counts.h"
#include "framework/module.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "utils/stats.h"

#define BASE_FILE (PERF_NAME ".csv")

using namespace std;

BaseTracker::BaseTracker(PerfConfig* perf) : PerfTracker(perf,
    perf->output == PERF_FILE ? BASE_FILE : nullptr)
{
    for (unsigned i = 0; i < config->modules.size(); i++)
    {
        Module *m = config->modules.at(i);
        vector<unsigned> peg_map = config->mod_peg_idxs.at(i);

        formatter->register_section(m->get_name());
        for (auto& idx : peg_map)
             formatter->register_field(m->get_pegs()[idx].name);
    }
}

void BaseTracker::reset()
{
    formatter->finalize_fields(fh);
}

void BaseTracker::process(bool summary)
{
    for (unsigned i = 0; i < config->modules.size(); i++)
    {
        Module* m = config->modules.at(i);
        vector<unsigned> idxs = config->mod_peg_idxs[i];
        PegCount* pegs = m->get_counts();

        for (unsigned j = 0; j < idxs.size(); j++)
            formatter->set_field(i, j, (PegCount)pegs[idxs[j]]);
        if (!summary)
            m->sum_stats();
    }
    formatter->write(fh, cur_time);
    formatter->clear();
}

