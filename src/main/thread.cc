//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <fstream>
#include <iostream>
#include <sys/stat.h>

#include "log/messages.h"
#include "utils/util.h"

#include "snort.h"
#include "snort_config.h"
#include "thread_config.h"

#define INST_MAP_NAME "instance_mappings.csv"

//-------------------------------------------------------------------------
// FIXIT-L instance_id zero indicates main thread during parse time and the
// first packet thread during runtime.  not sure if i'm ok with that.
// works for now.
//-------------------------------------------------------------------------

static THREAD_LOCAL uint16_t run_num = 0;
THREAD_LOCAL unsigned instance_id = 0;
static THREAD_LOCAL SThreadType thread_type = STHREAD_TYPE_OTHER;

void set_run_num(uint16_t num)
{ run_num = num; }

uint16_t get_run_num()
{ return run_num; }

void set_instance_id(unsigned id)
{ instance_id = id; }

void set_thread_type(SThreadType type)
{ thread_type = type; }

namespace snort
{

void populate_instance_maps()
{
    const SnortConfig* sc = SnortConfig::get_conf();
    if (!sc->create_inst_file())
        return;

    std::string path;

    get_instance_file(path, INST_MAP_NAME);

    std::ofstream inst_file;
    inst_file.open(path);

    inst_file << "pid, snort process number, thread_id, instance_id, relative_instance_id, max_instances\n";
    inst_file << getpid() << ", ";
    inst_file << Snort::get_process_id() << ", ";
    inst_file << ThreadConfig::get_instance_tid(instance_id) << ", ";
    inst_file << instance_id << ", ";
    inst_file << get_relative_instance_number() << ", ";
    inst_file << ThreadConfig::get_instance_max();
    inst_file << "\n";

    inst_file.close();
}

void invalidate_instance_maps()
{
    const SnortConfig* sc = SnortConfig::get_conf();
    if (!sc->create_inst_file())
        return;

    std::string path;

    get_instance_file(path, INST_MAP_NAME);
    std::ofstream inst_file;
    inst_file.open(path);
    inst_file << "(instance is inactive or has terminated)\n";
    inst_file.close();
}

unsigned get_instance_id()
{ return instance_id; }

unsigned get_relative_instance_number()
{
    // Maintain the zero-based counting that we previously used; first pkt thread = 0
    const SnortConfig* sc = SnortConfig::get_conf();
    return instance_id + sc->id_offset;
}

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
    const SnortConfig* sc = SnortConfig::get_conf();

    bool sep = false;
    file = !sc->log_dir.empty() ?  sc->log_dir : "./";

    if ( file.back() != '/' )
        file += '/';

    if ( !sc->run_prefix.empty() )
    {
        file += sc->run_prefix;
        sep = true;
    }

    if ( (ThreadConfig::get_instance_max() > 1) || sc->id_zero )
    {
        char id[8];
        snprintf(id, sizeof(id), "%u",
            get_instance_id() + sc->id_offset);
        file += id;
        sep = true;
    }

    if ( sc->id_subdir )
    {
        file += '/';

        // Explicitly set mode to avoid umask issues (fixes random 0750/0700)
        mode_t old_mask = umask(0);
        if ( mkdir(file.c_str(), 0770) == -1 and errno != EEXIST )
            ParseError("Failed to create directory %s - %s",
                file.c_str(), get_error(errno));
        umask(old_mask);
    }
    else if ( sep )
        file += '_';

    file += name;

    return file.c_str();
}
}
