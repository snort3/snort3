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

#include "acsmx.h"

using namespace snort;

//-------------------------------------------------------------------------
// "ac_std"
//-------------------------------------------------------------------------

class AcMpse : public Mpse
{
private:
    ACSM_STRUCT* obj;

public:
    AcMpse(SnortConfig*, const MpseAgent* agent)
        : Mpse("ac_std")
    { obj = acsmNew(agent); }

    ~AcMpse() override
    { acsmFree(obj); }

    int add_pattern(
        SnortConfig*, const uint8_t* P, unsigned m,
        const PatternDescriptor& desc, void* user) override
    {
        return acsmAddPattern(obj, P, m, desc.no_case, desc.negated, user);
    }

    int prep_patterns(SnortConfig* sc) override
    { return acsmCompile(sc, obj); }

    int _search(
        const uint8_t* T, int n, MpseMatch match,
        void* context, int* current_state) override
    {
        return acsmSearch(obj, T, n, match, context, current_state);
    }

    int print_info() override
    { return acsmPrintDetailInfo(obj); }

    int get_pattern_count() override
    { return acsmPatternCount(obj); }
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Mpse* ac_ctor(
    SnortConfig* sc, class Module*, const MpseAgent* agent)
{
    return new AcMpse(sc, agent);
}

static void ac_dtor(Mpse* p)
{
    delete p;
}

static void ac_init()
{
    acsmx_init_xlatcase();
}

static void ac_print()
{
    acsmPrintSummaryInfo();
}

static const MpseApi ac_api =
{
    {
        PT_SEARCH_ENGINE,
        sizeof(MpseApi),
        SEAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "ac_std",
        "Aho-Corasick Full (high memory, best performance) MPSE",
        nullptr,
        nullptr
    },
    MPSE_BASE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ac_ctor,
    ac_dtor,
    ac_init,
    ac_print,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* se_ac_std[] =
#endif
{
    &ac_api.base,
    nullptr
};

