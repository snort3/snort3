
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

// tp_appid_module_api.cc author Lukasz Czarnik <lczarnik@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tp_appid_module_api.h"

#include "managers/module_manager.h"
#include "profiler/profiler.h"

#include "appid_module.h"
#include "tp_lib_handler.h"


static void* tp_appid_profiler_malloc(size_t size)
{
    // cppcheck-suppress unreadVariable
    snort::Profile profile(tp_appid_perf_stats);
    return operator new(size);
}

static void tp_appid_profiler_free(void* p)
{
    // cppcheck-suppress unreadVariable
    snort::Profile profile(tp_appid_perf_stats);
    if (p)
        operator delete(p);
}

TPAppidProfilerFunctions get_tp_appid_profiler_functions()
{
    return {tp_appid_profiler_malloc,tp_appid_profiler_free};
}
