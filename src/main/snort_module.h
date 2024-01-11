//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// snort_module.cc author Russ Combs <rucombs@cisco.com>

#ifndef SNORT_MODULE_H
#define SNORT_MODULE_H

// the snort module is for handling command line args,
// shell commands, and basic application stats

#include "main/thread.h"

namespace snort
{
class Module;
class Trace;
}

extern THREAD_LOCAL const snort::Trace* snort_trace;

snort::Module* get_snort_module();

enum
{
    TRACE_INSPECTOR_MANAGER = 0,
    TRACE_MAIN,
};

#endif

