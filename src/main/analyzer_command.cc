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
// analyzer_command.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "analyzer_command.h"

#include <cassert>

#include "log/messages.h"
#include "managers/module_manager.h"
#include "utils/stats.h"

#include "analyzer.h"
#include "snort.h"
#include "snort_config.h"
#include "swapper.h"

void ACStart::execute(Analyzer& analyzer)
{
    analyzer.start();
}

void ACRun::execute(Analyzer& analyzer)
{
    analyzer.run(paused);
    paused = false;
}

void ACStop::execute(Analyzer& analyzer)
{
    analyzer.stop();
}

void ACPause::execute(Analyzer& analyzer)
{
    analyzer.pause();
}

void ACResume::execute(Analyzer& analyzer)
{
    analyzer.resume();
}

void ACRotate::execute(Analyzer&)
{
    snort::Snort::thread_rotate();
}

void ACGetStats::execute(Analyzer&)
{
    // FIXIT-P This incurs locking on all threads to retrieve stats.  It could be reimplemented to
    //  optimize for large thread counts by retrieving stats in the command and accumulating in the
    //  main thread.
    ModuleManager::accumulate(snort::SnortConfig::get_conf());
}

ACGetStats::~ACGetStats()
{
    // FIXIT-L This should track the owner so it can dump stats to the shell instead of the logs
    //  when initiated by a shell command
    DropStats();
}

ACSwap::ACSwap(Swapper* ps) : ps(ps)
{
    assert(Swapper::get_reload_in_progress() == false);
    Swapper::set_reload_in_progress(true);
}

void ACSwap::execute(Analyzer&)
{
    if (ps)
        ps->apply();
}

ACSwap::~ACSwap()
{
    delete ps;
    Swapper::set_reload_in_progress(false);
    snort::LogMessage("== reload complete\n");
}

void ACDAQSwap::execute(Analyzer& analyzer)
{
    analyzer.reload_daq();
}

ACDAQSwap::~ACDAQSwap()
{
    snort::LogMessage("== daq module reload complete\n");
}

