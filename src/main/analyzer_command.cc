//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "control/control.h"
#include "framework/module.h"
#include "log/messages.h"
#include "managers/module_manager.h"
#include "protocols/packet_manager.h"
#include "target_based/host_attributes.h"
#include "utils/stats.h"
#include "packet_io/sfdaq_instance.h"

#include "analyzer.h"
#include "reload_tracker.h"
#include "reload_tuner.h"
#include "snort.h"
#include "snort_config.h"
#include "thread_config.h"
#include "swapper.h"

using namespace snort;

void AnalyzerCommand::log_message(ControlConn* ctrlcon, const char* format, va_list& ap)
{
    if (ctrlcon && !ctrlcon->is_local())
    {
        va_list rap;
        va_copy(rap, ap);
        ctrlcon->respond(format, rap);
        va_end(rap);
    }
    LogMessage(format, ap);
}

void AnalyzerCommand::log_message(ControlConn* ctrlcon, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    log_message(ctrlcon, format, args);
    va_end(args);
}

void AnalyzerCommand::log_message(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    log_message(ctrlcon, format, args);
    va_end(args);
}

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
    PacketManager::accumulate();
    ModuleManager::accumulate();
    return true;
}

ACGetStats::~ACGetStats()
{
    ModuleManager::accumulate_module("memory");
    // FIXIT-L This should track the owner so it can dump stats to the
    // shell instead of the logs when initiated by a shell command
    DropStats(ctrlcon);
    LogRespond(ctrlcon, "==================================================\n"); // Marking End of stats

    ModuleManager::clear_global_active_counters();
}

bool ACResetStats::execute(Analyzer&, void**)
{
    ModuleManager::reset_stats(requested_type);
    return true;
}

ACResetStats::ACResetStats(clear_counter_type_t requested_type_l) : requested_type(
        requested_type_l) { }

ACResetStats::~ACResetStats()
{
    // Destructor is called only from main thread,
    // main-thread stats are reset here.

    if (requested_type == TYPE_MODULE or requested_type == TYPE_ALL)
        ModuleManager::reset_module_stats("memory");

    if (requested_type == TYPE_SNORT or requested_type == TYPE_ALL)
        ModuleManager::reset_module_stats("snort");
}

bool ACSwap::execute(Analyzer& analyzer, void** ac_state)
{
    if (analyzer.get_state() != Analyzer::State::PAUSED and
        analyzer.get_state() != Analyzer::State::RUNNING)
        return false;

    if (ps)
    {
        ps->apply(analyzer);

        const SnortConfig* sc = ps->get_new_conf();
        if ( sc )
        {
            std::list<ReloadResourceTuner*>* reload_tuners;

            if ( !*ac_state )
            {
                reload_tuners = new std::list<ReloadResourceTuner*>(sc->get_reload_resource_tuners());
                std::list<ReloadResourceTuner*>::iterator rtt = reload_tuners->begin();
                while ( rtt != reload_tuners->end() )
                {
                    if ( (*rtt)->tinit() )
                        ++rtt;
                    else
                        rtt = reload_tuners->erase(rtt);
                }
                *ac_state = reload_tuners;
            }
            else
                reload_tuners = (std::list<ReloadResourceTuner*>*)*ac_state;

            if ( !reload_tuners->empty() )
            {
                auto rrt = reload_tuners->front();
                if ( analyzer.is_idling() )
                {
                    if ( rrt->tune_idle_context() )
                        reload_tuners->pop_front();
                }
                else
                {
                    if ( rrt->tune_packet_context() )
                        reload_tuners->pop_front();
                }
            }

            // check for empty again and free list instance if we are done
            if ( reload_tuners->empty() )
            {
                delete reload_tuners;
                ps->finish(analyzer);
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
        SnortConfig* sc = ps->get_new_conf();
        if ( sc )
            sc->clear_reload_resource_tuner_list();
    }
    delete ps;
    HostAttributesManager::swap_cleanup();

    ReloadTracker::end(ctrlcon);
    log_message("== reload complete\n");
}

bool ACHostAttributesSwap::execute(Analyzer&, void**)
{
    HostAttributesManager::initialize();
    return true;
}

ACHostAttributesSwap::~ACHostAttributesSwap()
{
    HostAttributesManager::swap_cleanup();
    ReloadTracker::end(ctrlcon);
    log_message("== reload host attributes complete\n");
}

bool ACDAQSwap::execute(Analyzer& analyzer, void**)
{
    analyzer.reload_daq();
    return true;
}

ACDAQSwap::~ACDAQSwap()
{
    LogMessage("== daq module reload complete\n");
}

bool ACScratchUpdate::execute(Analyzer&, void**)
{
    for ( auto* s : handlers )
    {
        if ( s )
            s->update(sc);
    }
    return true;
}

ACScratchUpdate::~ACScratchUpdate()
{
    log_message("== scratch update complete\n");
    ReloadTracker::end(ctrlcon, true);
}

SFDAQInstance* AnalyzerCommand::get_daq_instance(Analyzer& analyzer)
{
    return analyzer.get_daq_instance();
}

ACShowSnortCPU::~ACShowSnortCPU()
{
    if (DAQ_SUCCESS == status)
    {
        LogRespond(ctrlcon, "\nSummary \t%.1f%% \t%.1f%% \t%.1f%%\n",
            cpu_usage_30s/instance_num, cpu_usage_120s/instance_num,
            cpu_usage_300s/instance_num);
    }
}

bool ACShowSnortCPU::execute(Analyzer& analyzer, void**)
{
    DIOCTL_GetCpuProfileData get_data = {};

    {
        std::lock_guard<std::mutex> lock(cpu_usage_mutex);
        assert(DAQ_SUCCESS == status);

        SFDAQInstance* instance = get_daq_instance(analyzer);
        ThreadConfig *thread_config = SnortConfig::get_conf()->thread_config;
        int tid = thread_config->get_instance_tid(get_instance_id());

        status = instance->ioctl(
                     (DAQ_IoctlCmd)DIOCTL_GET_CPU_PROFILE_DATA,
                     (void *)(&get_data),
                     sizeof(DIOCTL_GetCpuProfileData));

        if (DAQ_SUCCESS != status)
        {
            LogRespond(ctrlcon, "Fetching profile data failed from DAQ instance\n");
            return true; 
        }

        double cpu_30s = static_cast<double> (get_data.cpu_usage_percent_30s);
        double cpu_120s = static_cast<double> (get_data.cpu_usage_percent_120s);
        double cpu_300s = static_cast<double> (get_data.cpu_usage_percent_300s);

        // Print CPU usage
        LogRespond(ctrlcon, "%-3d \t%-6d \t%.1f%% \t%.1f%% \t%.1f%%\n",
            instance_num, tid, cpu_30s, cpu_120s, cpu_300s);

        // Add CPU usage data
        cpu_usage_30s += cpu_30s;
        cpu_usage_120s += cpu_120s;
        cpu_usage_300s += cpu_300s;
        instance_num++;

    }

    return true;
}
