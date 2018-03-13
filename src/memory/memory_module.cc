//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// memory_module.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "memory_module.h"

#include "main/snort_config.h"

#include "memory_config.h"

using namespace snort;

// -----------------------------------------------------------------------------
// memory attributes
// -----------------------------------------------------------------------------

#define s_name "memory"
#define s_help \
    "memory management configuration"

static const Parameter s_params[] =
{
    { "cap", Parameter::PT_INT, "0:", "0",
        "set the per-packet-thread cap on memory (bytes, 0 to disable)" },

    { "soft", Parameter::PT_BOOL, nullptr, "false",
        "always succeed in allocating memory, even if above the cap" },

    { "threshold", Parameter::PT_INT, "0:", "0",
        "set the per-packet-thread threshold for preemptive cleanup actions "
        "(percent, 0 to disable)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

// -----------------------------------------------------------------------------
// memory module
// -----------------------------------------------------------------------------

bool MemoryModule::configured = false;

MemoryModule::MemoryModule() :
    Module(s_name, s_help, s_params)
{ }

bool MemoryModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("cap") )
        sc->memory->cap = v.get_long();

    else if ( v.is("soft") )
        sc->memory->soft = v.get_bool();

    else if ( v.is("threshold") )
        sc->memory->threshold = v.get_long();

    else
        return false;

    return true;
}

bool MemoryModule::end(const char*, int, SnortConfig*)
{
    configured = true;
    return true;
}

bool MemoryModule::is_active()
{ return configured; }

