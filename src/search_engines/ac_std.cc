/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
**  Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "acsmx.h"
#include "acsmx2.h"

#include "snort_debug.h"
#include "snort_types.h"
#include "util.h"
#include "profiler.h"
#include "snort.h"
#include "framework/mpse.h"

//-------------------------------------------------------------------------
// "ac_std"
//-------------------------------------------------------------------------

class AcMpse : public Mpse
{
private:
    ACSM_STRUCT* obj;

public:
    AcMpse(
        SnortConfig*,
        bool use_gc,
        void (*user_free)(void*),
        void (*tree_free)(void**),
        void (*list_free)(void**))
    : Mpse("ac_std", use_gc)
    { obj = acsmNew(user_free, tree_free, list_free); };

    ~AcMpse()
    {
        if (obj)
            acsmFree(obj);
    };

    int add_pattern(
        SnortConfig*, void* P, int m,
        unsigned noCase, unsigned offset, unsigned depth,
        unsigned negative, void* ID, int IID) override
    {
        return acsmAddPattern(
            obj, (unsigned char *)P, m,
            noCase, offset, depth, negative, ID, IID );
    };

    int prep_patterns(
        SnortConfig* sc, mpse_build_f build_tree, mpse_negate_f neg_list) override
    {
        return acsmCompileWithSnortConf(
            sc, obj, build_tree, neg_list);
    };

    int _search(
        const unsigned char* T, int n, mpse_action_f action,
        void* data, int* current_state ) override
    {
        return acsmSearch(
            obj, (unsigned char *)T, n, action, data, current_state );
    };

    int print_info() override
    {
        return acsmPrintDetailInfo(obj);
    };

    int get_pattern_count() override
    {
        return acsmPatternCount(obj);
    };
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Mpse* ac_ctor(
    SnortConfig* sc,
    class Module*,
    bool use_gc,
    void (*user_free)(void*),
    void (*tree_free)(void**),
    void (*list_free)(void**))
{
    return new AcMpse(sc, use_gc, user_free, tree_free, list_free);
}

static void ac_dtor(Mpse* p)
{
    delete p;
}

static void ac_init()
{
    acsmx_init_xlatcase();
    // TBD this was never implemented for acsmx (only acsmx2)
    //acsm_init_summary();
}

static void ac_print()
{
    // TBD this was apparently partly cloned from acsmx2 and never finished
    //acsmPrintSummaryInfo();
}

static const MpseApi ac_api =
{
    {
        PT_SEARCH_ENGINE,
        "ac_std",
        "Aho-Corasick Full (high memory, best performance) MPSE",
        SEAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    false,
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
{
    &ac_api.base,
    nullptr
};
#else
const BaseApi* se_ac_std = &ac_api.base;
#endif

