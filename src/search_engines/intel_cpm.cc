/*
*   An abstracted interface to the Multi-Pattern Matching routines,
*   thats why we're passing 'void *' objects around.
*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
*   Copyright (C) 2002-2013 Sourcefire, Inc.
*   Marc A Norton <mnorton@sourcefire.com>
*
*   Updates:
*   3/06 - Added AC_BNFA search
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

#ifdef INTEL_SOFT_CPM
#include "intel_soft_cpm.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bitop.h"
#include "snort_debug.h"
#include "snort_types.h"
#include "util.h"
#include "profiler.h"
#include "snort.h"
#include "framework/mpse.h"

//-------------------------------------------------------------------------
// "intel_cpm"
//-------------------------------------------------------------------------

class IntelCpmMpse : public Mpse
{
private:
    IntelPm* obj;

public:
    IntelCpmMpse(
        SnortConfig* sc,
        bool use_gc,
        void (*user_free)(void*),
        void (*tree_free)(void**),
        void (*list_free)(void**))
    : Mpse("intel_cpm", use_gc)
    {
        obj = IntelPmNew(sc, user_free, tree_free, list_free);
    };
    ~IntelCpmMpse()
    {
        if (obj)
            IntelPmDelete(obj);
    };

    int add_pattern(
        SnortConfig* sc, void* P, int m,
        unsigned noCase, unsigned offset, unsigned depth,
        unsigned negative, void* ID, int IID)
    {
        return IntelPmAddPattern(
            sc, obj, (unsigned char *)P, m,
            noCase, negative, ID, IID);
    };

    int prep_patterns(
        SnortConfig* sc, mpse_build_f build_tree, mpse_negate_f neg_list)
    {
        return IntelPmFinishGroup(sc, obj, build_tree, neg_list);
    };

    int _search(
        const unsigned char* T, int n, mpse_action_f action,
        void* data, int* current_state )
    {
        *current_state = 0;
        return IntelPmSearch((IntelPm *)p->obj, (unsigned char *)T, n, action, data);
    };

    int get_pattern_count()
    {
        return IntelGetPatternCount(obj);
    };
};
//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static void cpm_activate(SnortConfig* sc)
{
    IntelPmActivate(sc);
}

static void cpm_setup(SnortConfig* sc)
{
    IntelPmCompile(sc);
}

static void cpm_start()
{
    IntelPmStartInstance();
}

static void cpm_stop()
{
    IntelPmStopInstance();
}

static Mpse* cpm_ctor(
    SnortConfig* sc,
    class Module*,
    bool use_gc,
    void (*user_free)(void*),
    void (*tree_free)(void**),
    void (*list_free)(void**))
{
    return new IntelCpmMpse(sc, use_gc, user_free, tree_free, list_free);
}

static void cpm_dtor(Mpse* p)
{
    delete p;
}

static void cpm_init()
{
}

static void cpm_print()
{
    IntelPmPrintSummary(sc);
}

static const MpseApi cpm_api =
{
    {
        PT_SEARCH_ENGINE,
        "intel_cpm",
        SEAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    false,
    cpm_activate,
    cpm_setup,
    cpm_start,
    cpm_stop,
    cpm_ctor,
    cpm_dtor,
    cpm_init,
    cpm_print,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &cpm_api.base,
    nullptr
};
#else
const BaseApi* se_intel_cpm = &cpm_api.base;
#endif

#endif

