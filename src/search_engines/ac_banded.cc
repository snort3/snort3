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
// "ac_banded"
//-------------------------------------------------------------------------

class AcbMpse : public Mpse
{
private:
    ACSM_STRUCT2* obj;

public:
    AcbMpse(
        SnortConfig*, const MpseAgent* agent)
        : Mpse("ac_banded")
    {
        obj = acsmNew2(agent, ACF_BANDED);
    }

    ~AcbMpse() override
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
#if 1
        return acsm_search_dfa_banded(obj, T, n, match, context, current_state);
#else
        if ( obj->dfa_enabled() )
            return acsm_search_dfa_banded(obj, T, n, match, context, current_state);

        // FIXIT-L banded will crash in get_next_state_nfa()
        return acsm_search_nfa(obj, T, n, match, context, current_state);
#endif
    }

    int print_info() override
    { return acsmPrintDetailInfo2(obj); }

    int get_pattern_count() override
    { return acsmPatternCount2(obj); }
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Mpse* acb_ctor(
    SnortConfig* sc, class Module*, const MpseAgent* agent)
{
    return new AcbMpse(sc, agent);
}

static void acb_dtor(Mpse* p)
{
    delete p;
}

static void acb_init()
{
    acsmx2_init_xlatcase();
    acsm_init_summary();
}

static void acb_print()
{
    acsmPrintSummaryInfo2();
}

static const MpseApi acb_api =
{
    {
        PT_SEARCH_ENGINE,
        sizeof(MpseApi),
        SEAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "ac_banded",
        "Aho-Corasick Banded (high memory, moderate performance)",
        nullptr,
        nullptr
    },
    MPSE_BASE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    acb_ctor,
    acb_dtor,
    acb_init,
    acb_print,
};

const BaseApi* se_ac_banded = &acb_api.base;

