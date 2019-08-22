//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/module.h"
#include "log/messages.h"
#include "managers/module_manager.h"
#include "utils/stats.h"

#include "analyzer.h"
#include "request.h"
#include "snort.h"
#include "snort_config.h"
#include "swapper.h"

bool ACStart::execute(Analyzer& analyzer, void**)
{
    analyzer.start();
    return true;
}

bool ACRun::execute(Analyzer& analyzer, void**)
{
    analyzer.run(paused);
    paused = false;
    return true;
}

bool ACStop::execute(Analyzer& analyzer, void**)
{
    analyzer.stop();
    return true;
}

bool ACPause::execute(Analyzer& analyzer, void**)
{
    analyzer.pause();
    return true;
}

bool ACResume::execute(Analyzer& analyzer, void**)
{
    analyzer.resume(msg_cnt);
    return true;
}

bool ACRotate::execute(Analyzer& analyzer, void**)
{
    analyzer.rotate();
    return true;
}

bool ACGetStats::execute(Analyzer&, void**)
{

    // FIXIT-P This incurs locking on all threads to retrieve stats.  It
    // could be reimplemented to optimize for large thread counts by
    // retrieving stats in the command and accumulating in the main thread.
    snort::ModuleManager::accumulate(snort::SnortConfig::get_conf());
    return true;
}

ACGetStats::~ACGetStats()
{

    // FIXIT-L This should track the owner so it can dump stats to the
    // shell instead of the logs when initiated by a shell command
    DropStats();
}

ACSwap::ACSwap(Swapper* ps, Request* req, bool from_shell) : ps(ps), request(req), from_shell(from_shell)
{
    assert(Swapper::get_reload_in_progress() == false);
    Swapper::set_reload_in_progress(true);
}

bool ACSwap::execute(Analyzer& analyzer, void** ac_state)
{
    if (ps)
    {
        ps->apply(analyzer);

        snort::SnortConfig* sc = ps->get_new_conf();
        if ( sc )
        {
            std::list<snort::ReloadResourceTuner*>* reload_tuners;

            if ( !*ac_state )
            {
                reload_tuners = new std::list<snort::ReloadResourceTuner*>(sc->get_reload_resource_tuners());
                *ac_state = reload_tuners;
            }
            else
                reload_tuners = (std::list<snort::ReloadResourceTuner*>*)*ac_state;

            if ( !reload_tuners->empty() )
            {
                auto rrt = reload_tuners->front();
                if (rrt->tune_resources())
                    reload_tuners->pop_front();
            }

            // check for empty again and free list instance if we are done
            if ( reload_tuners->empty() )
            {
                delete reload_tuners;
                return true;
            }

            return false;
        }
    }

    return true;
}

ACSwap::~ACSwap()
{
    if (ps)
    {
        snort::SnortConfig* sc = ps->get_new_conf();
        if ( sc )
            sc->clear_reload_resource_tuner_list();
    }
    delete ps;
    Swapper::set_reload_in_progress(false);
    snort::LogMessage("== reload complete\n");
    request->respond("== reload complete\n", from_shell, true);
}

bool ACDAQSwap::execute(Analyzer& analyzer, void**)
{
    analyzer.reload_daq();
    return true;
}

ACDAQSwap::~ACDAQSwap()
{
    snort::LogMessage("== daq module reload complete\n");
}

snort::SFDAQInstance* snort::AnalyzerCommand::get_daq_instance(Analyzer& analyzer) 
{
    return analyzer.get_daq_instance();
}
