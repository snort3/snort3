//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// profiler.h author Joel Cornett <jocornet@cisco.com>

#ifndef PROFILER_H
#define PROFILER_H

#include "profiler_defs.h"

namespace snort
{
class Module;
}

class Profiler
{
public:
    static void register_module(snort::Module*);
    static void register_module(const char*, const char*, snort::Module*);
    static void register_module(const char*, const char*, snort::get_profile_stats_fn);

    // FIXIT-L do we need to call on main thread?
    // call from packet threads, just before thread termination
    static void consolidate_stats();
    static void reset_stats();
    static void show_stats();
};


#endif
