//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/module.h"
#include "framework/mpse.h"
#include "main/snort_types.h"
#include "profiler/profiler.h"

#include "acsmx2.h"

using namespace snort;

#define MOD_NAME "ac_full"
#define MOD_HELP "Aho-Corasick Full (high memory, best performance), implements search_all()"

struct FullCounts
{
    PegCount searches;
    PegCount matches;
    PegCount bytes;
};

static THREAD_LOCAL FullCounts full_counts;
static THREAD_LOCAL ProfileStats full_stats;

const PegInfo full_pegs[] =
{
    { CountType::SUM, "searches", "number of search attempts" },
    { CountType::SUM, "matches", "number of times a match was found" },
    { CountType::SUM, "bytes", "total bytes searched" },

    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class AcFullModule : public Module
{
public:
    AcFullModule() : Module(MOD_NAME, MOD_HELP) { }

    ProfileStats* get_profile() const override
    { return &full_stats; }

    const PegInfo* get_pegs() const override
    { return full_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&full_counts; }

    Usage get_usage() const override
    { return GLOBAL; }
};

//-------------------------------------------------------------------------
// mpse
//-------------------------------------------------------------------------

class AcfMpse : public Mpse
{
private:
    ACSM_STRUCT2* obj;

public:
    AcfMpse(const MpseAgent* agent) : Mpse("ac_full")
    { obj = acsmNew2(agent); }

    ~AcfMpse() override
    { acsmFree2(obj); }

    int add_pattern(const uint8_t* P, unsigned m, const PatternDescriptor& desc, void* user) override
    { return acsmAddPattern2(obj, P, m, desc.no_case, desc.negated, user); }

    int prep_patterns(SnortConfig* sc) override
    { return acsmCompile2(sc, obj); }

    int print_info() override
    { return acsmPrintDetailInfo2(obj); }

    int get_pattern_count() const override
    { return acsmPatternCount2(obj); }

    int search(const uint8_t*, int, MpseMatch, void*, int*) override;
    int search_all(const uint8_t*, int n, MpseMatch, void*, int*) override;
};

int AcfMpse::search(const uint8_t* T, int n, MpseMatch match, void* context, int* current_state)
{
    Profile profile(full_stats);  // cppcheck-suppress unreadVariable

    full_counts.searches++;
    full_counts.bytes += n;

    int found = acsm_search_dfa_full(obj, T, n, match, context, current_state);

    full_counts.matches += found;
    return found;
}

int AcfMpse::search_all(const uint8_t* T, int n, MpseMatch match, void* context, int* current_state)
{
    full_counts.searches++;
    full_counts.bytes += n;

    int found = acsm_search_dfa_full_all(obj, T, n, match, context, current_state);

    full_counts.matches += found;
    return found;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new AcFullModule;
}

static void mod_dtor(Module* p)
{
    delete p;
}

static Mpse* acf_ctor(
    const SnortConfig*, class Module*, const MpseAgent* agent)
{
    return new AcfMpse(agent);
}

static void acf_dtor(Mpse* p)
{
    delete p;
}

static void acf_init()
{
    acsmx2_init_xlatcase();
    acsm_init_summary();
}

static void acf_print()
{
    acsmPrintSummaryInfo2();
}

static const MpseApi acf_api =
{
    {
        PT_SEARCH_ENGINE,
        sizeof(MpseApi),
        SEAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MOD_NAME,
        MOD_HELP,
        mod_ctor,
        mod_dtor
    },
    MPSE_BASE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    acf_ctor,
    acf_dtor,
    acf_init,
    acf_print,
    nullptr,
};

const BaseApi* se_ac_full[] =
{
    &acf_api.base,
    nullptr
};

