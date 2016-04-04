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
    csv_header.clear();

    csv_header += ("#timestamp");
    for (unsigned i = 0; i < config->modules.size(); i++)
    {
        Module *m = config->modules.at(i);
        vector<unsigned> peg_map = config->mod_peg_idxs.at(i);
        for (auto& idx : peg_map)
        {
            csv_header += ",";
            csv_header += m->get_name();
            csv_header += ".";
            csv_header += m->get_pegs()[idx].name;
        }
    }
    csv_header += "\n";
}

void BaseTracker::reset()
{
    if (fh && config->format == PERF_CSV)
    {
        fwrite(csv_header.c_str(), csv_header.length(), 1, fh);
        fflush(fh);
    }
}

void BaseTracker::process(bool summary)
{
    char buf[32]; // > log10(2^64 - 1)

    if (!fh)
        return;

    string statLine;
    statLine.clear();
    snprintf(buf, sizeof(buf), "%ld", (long)cur_time);
    statLine += buf;

    for (unsigned i = 0; i < config->modules.size(); i++)
    {
        Module* m = config->modules.at(i);
        vector<unsigned> idxs = config->mod_peg_idxs.at(i);
        PegCount* pegs = m->get_counts();

        if (config->format == PERF_CSV)
        {
            for (auto& idx : idxs)
            {
                snprintf(buf, sizeof(buf), ",%" PRIu64, pegs[idx]);
                statLine += buf;
            }
        }
        else if(config->format == PERF_TEXT)
            m->show_interval_stats(idxs, fh);
        if (!summary)
            m->sum_stats();
    }
    if (config->format == PERF_CSV)
    {
        statLine += "\n";
        fwrite(statLine.c_str(), statLine.length(), 1, fh);
        fflush(fh);
    }
}

