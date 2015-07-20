//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// thread.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "thread.h"

#ifdef LINUX
# include <sched.h>
#endif

#include <sys/stat.h>
#include <thread>
#include <vector>

#include "snort_config.h"
#include "parser/parser.h"
#include "log/messages.h"

//-------------------------------------------------------------------------
// FIXIT-L instance_id zero indicates main thread during parse time and the
// first packet thread during runtime.  not sure if i'm ok with that.
// works for now.
//-------------------------------------------------------------------------

static unsigned instance_max = 1;
static THREAD_LOCAL unsigned instance_id = 0;

void set_instance_id(unsigned id)
{
    instance_id = id;
}

void set_instance_max(unsigned max)
{
    if ( max )
        instance_max = max;
    else
        instance_max = std::thread::hardware_concurrency();
}

unsigned get_instance_id()
{
    return instance_id;
}

unsigned get_instance_max()
{
    return instance_max;
}

bool set_cpu_affinity(SnortConfig* sc, const std::string& str, int cpu)
{
    std::map<const std::string, int>& sa = *(sc->source_affinity);

    auto search = sa.find(str);
    if (search != sa.end())
        ParseError("Multiple CPU's set for interface %s", str.c_str());

    sa[std::string(str)] = cpu;
    return false;
}

bool set_cpu_affinity(SnortConfig* sc, int thread, int cpu)
{
    std::vector<int>& ta = *(sc->thread_affinity);

    if (ta.size() <= (unsigned)thread)
    {
        const std::size_t curr_size = ta.size();
        const std::size_t new_size = curr_size * 2;
        ta.resize(new_size);

        for (std::size_t i = curr_size; i < new_size; ++i)
            ta[i] = -1;
    }

    if (ta[thread] >= 0)
        ParseError("Multiple CPU's set for thread %d", thread);

    ta[thread] = cpu;
    return true;
}

void pin_thread_to_cpu(const char* source)
{
    std::vector<int>& ta = *(snort_conf->thread_affinity);
    std::map<const std::string, int>& sa = *(snort_conf->source_affinity);
    const std::string src = source;
    int cpu = -1;

    ta.shrink_to_fit();
    auto search = sa.find(src);

    if (search != sa.end())
    {
        cpu = sa[src];
    }
    else if (ta[instance_id] != -1)
    {
        cpu = ta[instance_id];
    }

    if (cpu != -1)
    {
// PREPROCESSOR MACROS -- these are not actually if statements!
#       if LINUX
        {
            static THREAD_LOCAL cpu_set_t cpu_set;

            if (cpu >= CPU_SETSIZE)
                FatalError("maximum CPU value for this Operating System is %d",
                    CPU_SETSIZE);

            CPU_ZERO(&cpu_set);

            if (!sched_getaffinity(0, sizeof(cpu_set), &cpu_set))
                if (!CPU_ISSET(cpu, &cpu_set))
                    FatalError("CPU %d is not part of source %s's and thread "
                        "%d's CPU set\n", cpu, source, instance_id);

            CPU_ZERO(&cpu_set);
            CPU_SET(cpu, &cpu_set);

            if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set))
                FatalError("unable to pin source %s to CPU %d: %s\n",
                    source, cpu, std::strerror(errno));
        }
#       else
        {
            static bool warning_printed = false;
            if (!warning_printed)
            {
                WarningMessage("thread pinning / CPU affinity support is currently"
                    " unsupported for this operating system");
                warning_printed = true;
            }
        }
#       endif
    }
}

//-------------------------------------------------------------------------
// union rules - breaks are mandatory and must be taken in daq thread
//-------------------------------------------------------------------------

static unsigned g_breaks = 0;
static THREAD_LOCAL unsigned t_breaks = 0;

void take_break()
{ g_breaks++; }

bool break_time()
{
    if ( t_breaks == g_breaks )
        return false;

    t_breaks = g_breaks;
    return true;
}

//-------------------------------------------------------------------------
// format is:
//     <logdir>/[<run_prefix>][<id#>][<X>]<name>
//
// where:
// -- <logdir> is ./ if not set
// -- <run_prefix> is optional
// -- <id#> is optionally omitted for instance 0
// -- <X> is either _ or / or nothing
//-------------------------------------------------------------------------

const char* get_instance_file(std::string& file, const char* name)
{
    bool sep = false;
    file = !snort_conf->log_dir.empty() ? snort_conf->log_dir : "./";

    if ( file.back() != '/' )
        file += '/';

    if ( !snort_conf->run_prefix.empty() )
    {
        file += snort_conf->run_prefix;
        sep = true;
    }

    if ( (get_instance_max() > 1) || snort_conf->id_zero )
    {
        char id[8];
        snprintf(id, sizeof(id), "%u", get_instance_id());
        file += id;
        sep = true;
    }

    if ( snort_conf->id_subdir )
    {
        file += '/';
        struct stat s;

        if ( stat(file.c_str(), &s) )
            // FIXIT-L getting random 0750 or 0700 (umask not thread local)?
            mkdir(file.c_str(), 0770);
    }
    else if ( sep )
        file += '_';

    file += name;

    return file.c_str();
}

