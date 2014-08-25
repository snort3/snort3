/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// thread.cc author Russ Combs <rucombs@cisco.com>

#include "thread.h"

#include <sys/stat.h>
#include <thread>
#include "snort.h"

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
    file = snort_conf->log_dir ? snort_conf->log_dir : "./";

    if ( file.back() != '/' )
        file += '/';

    if ( snort_conf->run_prefix )
    {
        file += snort_conf->run_prefix;
        sep = true;
    }

    if ( get_instance_id() || snort_conf->id_zero )
    {
        char id[8];
        snprintf(id, sizeof(id), "%u", get_instance_id());
        file += id;
        sep = true;
    }

    if ( sep )
        file += '_';

    if ( snort_conf->id_subdir )
    {
        file += '/';
        struct stat s;

        if ( stat(file.c_str(), &s) )
            // FIXIT-H getting random 0750 or 0700 (umask not thread local)?
            mkdir(file.c_str(), 0770);
    }

    file += name;

    return file.c_str();
}

