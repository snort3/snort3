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
#include "snort.h"

//-------------------------------------------------------------------------
// FIXIT instance_id zero indicates main thread during parse time and the
// first packet thread during runtime.  not sure if i'm ok with that.
// works for now.
//-------------------------------------------------------------------------

static THREAD_LOCAL unsigned instance_id = 0;

void set_instance_id(unsigned id)
{
    instance_id = id;
}

unsigned get_instance_id()
{
    return instance_id;
}

unsigned get_instance_max()
{
    return snort_conf->max_threads;
}

const char* get_instance_file(std::string& file, const char* name)
{
    char id[8];
    snprintf(id, sizeof(id), "/%u/", get_instance_id());

    file = snort_conf->log_dir ? snort_conf->log_dir : "./";
    file += id;

    struct stat s;

    if ( stat(file.c_str(), &s) )
        // FIXIT getting random 0750 or 0700 (umask not thread local)?
        mkdir(file.c_str(), 0770);

    file += name;

    return file.c_str();
}

