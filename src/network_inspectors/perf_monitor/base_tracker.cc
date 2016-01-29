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

#include <dlfcn.h>
#include <iostream>

#include "framework/counts.h"
#include "framework/module.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "utils/stats.h"

using namespace std;

static vector<Module*> modules;
static string csv_header;
static THREAD_LOCAL time_t cur_time;

BaseTracker::BaseTracker(SFPERF* perf) : PerfTracker(perf,
        perf->perf_flags & SFPERF_SUMMARY_BASE, perf->file ? BASE_FILE : nullptr)
{ }

//FIXIT-L should this really be p_init?
void BaseTracker::so_init()
{
    modules.clear();

    for (std::string mod : PluginManager::get_all_available_plugins())
    {
        Module* m = ModuleManager::get_module(mod.c_str());
        if (m)
        {
            m->reset_stats();
            if (m->get_num_counts())
                modules.push_back(m);
        }
    }
}

bool BaseTracker::so_configure() { return true; }

void BaseTracker::so_term() { }

void BaseTracker::reset()
{
    if (fh)
    {
        csv_header.clear();
        csv_header += ("#timestamp");
        for (Module* m : modules)
            for (int i = 0; i < m->get_num_counts(); i++)
            {
                csv_header += ",";
                csv_header += m->get_name();
                csv_header += ".";
                csv_header += m->get_pegs()[i].name;
            }
        csv_header += "\n";
        fwrite(csv_header.c_str(), csv_header.length(), 1, fh);
        fflush(fh);
    }
}

void BaseTracker::update(Packet* p)
{
    cur_time = p->pkth->ts.tv_sec;
}

void BaseTracker::process(bool summary)
{
    char buf[32]; // > log10(2^64 - 1)

    string statLine;
    statLine.clear();
    snprintf(buf, sizeof(buf), "%ld", (long)cur_time);
    statLine += buf;

    for (Module* m : modules)
    {
        PegCount* pegs = m->get_counts();
        const PegInfo* pegInfos = m->get_pegs();

        LogLabel(m->get_name());
        for (int i = 0; i < m->get_num_counts(); i++)
        {
            if (fh)
            {
                snprintf(buf, sizeof(buf), ",%" PRIu64, pegs[i]);
                statLine += buf;
            }
            if (config->perf_flags & SFPERF_CONSOLE)
                LogCount(pegInfos[i].name,  pegs[i]);
        }
        m->sum_stats();
        if (summary && (config->perf_flags & SFPERF_SUMMARY))
            m->show_stats();
    }
    if (fh)
    {
        statLine += "\n";
        fwrite(statLine.c_str(), statLine.length(), 1, fh);
        fflush(fh);
    }
}

