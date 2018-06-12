//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "config.h"
#endif

#include "thread.h"

#include <sys/stat.h>

#include "snort_config.h"
#include "thread_config.h"

//-------------------------------------------------------------------------
// FIXIT-L instance_id zero indicates main thread during parse time and the
// first packet thread during runtime.  not sure if i'm ok with that.
// works for now.
//-------------------------------------------------------------------------

static THREAD_LOCAL uint16_t run_num = 0;
static THREAD_LOCAL unsigned instance_id = 0;
static THREAD_LOCAL SThreadType thread_type = STHREAD_TYPE_MAIN;

void set_run_num(uint16_t num)
{ run_num = num; }

uint16_t get_run_num()
{ return run_num; }

void set_instance_id(unsigned id)
{ instance_id = id; }

void set_thread_type(SThreadType type)
{ thread_type = type; }

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

namespace snort
{
unsigned get_instance_id()
{ return instance_id; }

SThreadType get_thread_type()
{ return thread_type; }


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
    file = !snort::SnortConfig::get_conf()->log_dir.empty() ? snort::SnortConfig::get_conf()->log_dir : "./";

    if ( file.back() != '/' )
        file += '/';

    if ( !snort::SnortConfig::get_conf()->run_prefix.empty() )
    {
        file += snort::SnortConfig::get_conf()->run_prefix;
        sep = true;
    }

    if ( (ThreadConfig::get_instance_max() > 1) || snort::SnortConfig::get_conf()->id_zero )
    {
        char id[8];
        snprintf(id, sizeof(id), "%u", get_instance_id() + snort::SnortConfig::get_conf()->id_offset);
        file += id;
        sep = true;
    }

    if ( snort::SnortConfig::get_conf()->id_subdir )
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
}
