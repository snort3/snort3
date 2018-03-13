//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/mpse.h"

#include "acsmx2.h"

using namespace snort;

//-------------------------------------------------------------------------
// "ac_sparse_bands"
//-------------------------------------------------------------------------

class AcsbMpse : public Mpse
{
private:
    ACSM_STRUCT2* obj;

public:
    AcsbMpse(SnortConfig*, const MpseAgent* agent)
        : Mpse("ac_sparse_bands")
    {
        obj = acsmNew2(agent, ACF_SPARSE_BANDS);
    }

    ~AcsbMpse() override
    { acsmFree2(obj); }

    void set_opt(int) override
    { obj->enable_dfa(); }

    int add_pattern(
        SnortConfig*, const uint8_t* P, unsigned m,
        const PatternDescriptor& desc, void* user) override
    {
        return acsmAddPattern2(obj, P, m, desc.no_case, desc.negated, user);
    }

    int prep_patterns(SnortConfig* sc) override
    { return acsmCompile2(sc, obj); }

    int _search(
        const uint8_t* T, int n, MpseMatch match,
        void* context, int* current_state) override
    {
        if ( obj->dfa_enabled() )
            return acsm_search_dfa_sparse(obj, T, n, match, context, current_state);

        return acsm_search_nfa(obj, T, n, match, context, current_state);
    }

    int print_info() override
    { return acsmPrintDetailInfo2(obj); }

    int get_pattern_count() override
    { return acsmPatternCount2(obj); }
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Mpse* acsb_ctor(
    SnortConfig* sc, class Module*, const MpseAgent* agent)
{
    return new AcsbMpse(sc, agent);
}

static void acsb_dtor(Mpse* p)
{
    delete p;
}

static void acsb_init()
{
    acsmx2_init_xlatcase();
    acsm_init_summary();
}

static void acsb_print()
{
    acsmPrintSummaryInfo2();
}

static const MpseApi acsb_api =
{
    {
        PT_SEARCH_ENGINE,
        sizeof(MpseApi),
        SEAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "ac_sparse_bands",
        "Aho-Corasick Sparse-Banded (high memory, moderate performance) MPSE",
        nullptr,
        nullptr
    },
    MPSE_BASE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    acsb_ctor,
    acsb_dtor,
    acsb_init,
    acsb_print,
};

const BaseApi* se_ac_sparse_bands = &acsb_api.base;

