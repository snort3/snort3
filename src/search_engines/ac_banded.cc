//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "acsmx.h"
#include "acsmx2.h"

#include "main/snort_debug.h"
#include "main/snort_types.h"
#include "main/snort_config.h"
#include "utils/util.h"
#include "time/profiler.h"
#include "framework/mpse.h"

//-------------------------------------------------------------------------
// "ac_banded"
//-------------------------------------------------------------------------

class AcbMpse : public Mpse
{
private:
    ACSM_STRUCT2* obj;

public:
    AcbMpse(
        SnortConfig*,
        bool use_gc,
        void (* user_free)(void*),
        void (* tree_free)(void**),
        void (* list_free)(void**))
        : Mpse("ac_banded", use_gc)
    {
        obj = acsmNew2(user_free, tree_free, list_free);
        if ( obj ) acsmSelectFormat2(obj, ACF_BANDED);
    }

    ~AcbMpse()
    {
        if (obj)
            acsmFree2(obj);
    }

    int add_pattern(
        SnortConfig*, const uint8_t* P, unsigned m,
        bool noCase, bool negative, void* ID, int IID) override
    {
        return acsmAddPattern2(obj, P, m, noCase, negative, ID, IID);
    }

    int prep_patterns(
        SnortConfig* sc, MpseBuild build_tree, MpseNegate neg_list) override
    {
        return acsmCompile2(sc, obj, build_tree, neg_list);
    }

    int _search(
        const unsigned char* T, int n, MpseMatch match,
        void* data, int* current_state) override
    {
        return acsmSearchSparseDFA_Banded(
            obj, (unsigned char*)T, n, match, data, current_state);
    }

    int print_info() override
    {
        return acsmPrintDetailInfo2(obj);
    }

    int get_pattern_count() override
    {
        return acsmPatternCount2(obj);
    }
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Mpse* acb_ctor(
    SnortConfig* sc,
    class Module*,
    bool use_gc,
    void (* user_free)(void*),
    void (* tree_free)(void**),
    void (* list_free)(void**))
{
    return new AcbMpse(sc, use_gc, user_free, tree_free, list_free);
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
    false,
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

