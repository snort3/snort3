//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
/*
*   An abstracted interface to the Multi-Pattern Matching routines,
*   thats why we're passing 'void *' objects around.
*
*   Marc A Norton <mnorton@sourcefire.com>
*
*   Updates:
*   3/06 - Added AC_BNFA search
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/module.h"
#include "framework/mpse.h"
#include "main/snort_types.h"
#include "profiler/profiler.h"

#include "bnfa_search.h"

using namespace snort;

#define MOD_NAME "ac_bnfa"
#define MOD_HELP "Aho-Corasick Binary NFA (low memory, low performance) MPSE"

struct BnfaCounts
{
    PegCount searches;
    PegCount matches;
    PegCount bytes;
};

static THREAD_LOCAL BnfaCounts bnfa_counts;
static THREAD_LOCAL ProfileStats bnfa_stats;

const PegInfo bnfa_pegs[] =
{
    { CountType::SUM, "searches", "number of search attempts" },
    { CountType::SUM, "matches", "number of times a match was found" },
    { CountType::SUM, "bytes", "total bytes searched" },

    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class AcBnfaModule : public Module
{
public:
    AcBnfaModule() : Module(MOD_NAME, MOD_HELP) { }

    ProfileStats* get_profile() const override
    { return &bnfa_stats; }

    const PegInfo* get_pegs() const override
    { return bnfa_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&bnfa_counts; }

    Usage get_usage() const override
    { return GLOBAL; }
};

//-------------------------------------------------------------------------
// mpse
//-------------------------------------------------------------------------

class AcBnfaMpse : public Mpse
{
private:
    bnfa_struct_t* obj;

public:
    AcBnfaMpse(const MpseAgent* agent) : Mpse("ac_bnfa")
    {
        obj=bnfaNew(agent);
        if ( obj ) obj->bnfaMethod = 1;
    }

    ~AcBnfaMpse() override
    {
        if (obj)
            bnfaFree(obj);
    }

    int add_pattern(const uint8_t* P, unsigned m, const PatternDescriptor& desc, void* user) override
    { return bnfaAddPattern(obj, P, m, desc.no_case, desc.negated, user); }

    int prep_patterns(SnortConfig* sc) override
    { return bnfaCompile(sc, obj); }

    int get_pattern_count() const override
    { return bnfaPatternCount(obj); }

    int print_info() override
    {
        bnfaPrintInfo(obj);
        return 0;
    }

    int search(const uint8_t*, int, MpseMatch, void*, int*) override;
    //  FIXIT-L Implement search_all method for AC_BNFA.
};

int AcBnfaMpse::search( const uint8_t* T, int n, MpseMatch match, void* context, int* current_state)
{
    Profile profile(bnfa_stats);  // cppcheck-suppress unreadVariable

    bnfa_counts.searches++;
    bnfa_counts.bytes += n;

    int found = _bnfa_search_csparse_nfa(
        obj, T, n, match, context, 0 /* start-state */, current_state);

    bnfa_counts.matches += found;
    return found;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new AcBnfaModule;
}

static void mod_dtor(Module* p)
{
    delete p;
}

static Mpse* bnfa_ctor(
    const SnortConfig*, class Module*, const MpseAgent* agent)
{
    return new AcBnfaMpse(agent);
}

static void bnfa_dtor(Mpse* p)
{
    delete p;
}

static void bnfa_init()
{
    bnfa_init_xlatcase();
    bnfaInitSummary();
}

static void bnfa_print()
{
    bnfaPrintSummary();
}

static const MpseApi bnfa_api =
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
    bnfa_ctor,
    bnfa_dtor,
    bnfa_init,
    bnfa_print,
    nullptr,
};

const BaseApi* se_ac_bnfa[] =
{
    &bnfa_api.base,
    nullptr
};

