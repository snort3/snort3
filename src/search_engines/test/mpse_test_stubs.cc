////--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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

// mpse_test_stubs.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpse_test_stubs.h"

#include <cassert>

#include "detection/fp_config.h"
#include "framework/base_api.h"
#include "framework/mpse.h"
#include "framework/mpse_batch.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "managers/mpse_manager.h"
#include "profiler/time_profiler_defs.h"

//-------------------------------------------------------------------------
// base stuff
//-------------------------------------------------------------------------

std::vector<void *> s_state;
snort::ScratchAllocator* scratcher = nullptr;

namespace snort
{
SnortConfig s_conf;

THREAD_LOCAL SnortConfig* snort_conf = &s_conf;

const SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

SnortConfig::SnortConfig(const SnortConfig* const, const char*)
    : daq_config(nullptr), fast_pattern_config(new FastPatternConfig()), state(&s_state), num_slots(1),
    thread_config(nullptr)
{ }

SnortConfig::~SnortConfig() = default;

int SnortConfig::request_scratch(ScratchAllocator* s)
{
    scratcher = s;
    s_state.resize(1);
    return 0;
}

void SnortConfig::release_scratch(int)
{
    scratcher = nullptr;
    s_state.clear();
    s_state.shrink_to_fit();
}

DataBus::DataBus() = default;
DataBus::~DataBus() = default;

THREAD_LOCAL bool snort::TimeProfilerStats::enabled;

unsigned get_instance_id() { return 0; }
unsigned ThreadConfig::get_instance_max() { return 1; }

unsigned parse_errors = 0;
void ParseError(const char*, ...)
{ parse_errors++; }
void ErrorMessage(const char*, ...) { }

void LogValue(const char*, const char*, FILE*) { }
void LogMessage(const char*, ...) { }
void ParseWarning(WarningGroup, const char*, ...) { }

[[noreturn]] void FatalError(const char*,...) { exit(1); }

void LogCount(char const*, uint64_t, FILE*) { }
void LogStat(const char*, double, FILE*) { }

void md5(const unsigned char*, size_t, unsigned char*) { }

} // namespace snort

FastPatternConfig::FastPatternConfig()
{ search_api = get_test_api(); }

const char* FastPatternConfig::get_search_method() const
{ return search_api ? search_api->base.name : nullptr; }

using namespace snort;

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }

Mpse* mpse = nullptr;

void* s_user = (void*)"user";
void* s_tree = (void*)"tree";
void* s_list = (void*)"list";

MpseAgent s_agent =
{
    [](struct SnortConfig*, void*, void** ppt)
    {
        *ppt = s_tree;
        return 0;
    },
    [](void*, void** ppl)
    {
        *ppl = s_list;
        return 0;
    },

    [](void*) { },
    [](void** ppt) { assert(*ppt == s_tree); },
    [](void** ppl) { assert(*ppl == s_list); }
};

void MpseManager::delete_search_engine(Mpse* eng)
{
    const MpseApi* api = eng->get_api();
    api->dtor(eng);
}

MpseGroup::~MpseGroup()
{
    if (normal_mpse)
    {
        MpseManager::delete_search_engine(normal_mpse);
        normal_mpse = nullptr;
    }
    if (offload_mpse)
    {
        MpseManager::delete_search_engine(offload_mpse);
        offload_mpse = nullptr;
    }
}

bool MpseGroup::create_normal_mpse(const SnortConfig* sc, const char* type)
{
    const MpseApi* api = sc->fast_pattern_config->get_search_api();
    assert(api and !strcmp(api->base.name, type));

    api->init();
    mpse = api->ctor(sc, nullptr, &s_agent);

    assert(mpse);

    mpse->set_api(api);
    normal_mpse = mpse;

    return true;
}

bool MpseGroup::create_offload_mpse(const SnortConfig*)
{
    offload_mpse = nullptr;
    return false;
}

const ExpectedMatch* s_expect = nullptr;
int s_found = 0;

int check_mpse_match(
    void* pid, void* /*tree*/, int index, void* /*context*/, void* /*neg_list*/)
{
    auto id = reinterpret_cast<std::uintptr_t>(pid);

    if ( s_expect and s_found >= 0 and
        s_expect[s_found].id == (int)id and
        s_expect[s_found].offset == index )
    {
        ++s_found;
    }
    else s_found = -1;

    return s_found == -1;
}

