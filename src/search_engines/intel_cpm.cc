//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
//  Copyright (C) 2002-2013 Sourcefire, Inc.
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

#ifdef INTEL_SOFT_CPM
#include "intel_soft_cpm.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_debug.h"
#include "main/snort_types.h"
#include "main/snort_config.h"
#include "utils/util.h"
#include "profiler/profiler.h"
#include "framework/mpse.h"

//-------------------------------------------------------------------------
// "intel_cpm"
//-------------------------------------------------------------------------

class IntelCpmMpse : public Mpse
{
private:
    IntelPm* obj;

public:
    IntelCpmMpse(SnortConfig* sc, bool use_gc, const MpseAgent* agent)
        : Mpse("intel_cpm", use_gc)
    {
        obj = IntelPmNew(sc, agent);
    }

    ~IntelCpmMpse()
    {
        if (obj)
            IntelPmDelete(obj);
    }

    int add_pattern(
        SnortConfig* sc, const uint8_t* P, unsigned m,
        const PatternDescriptor& desc, void* user) override
    {
        return IntelPmAddPattern(sc, obj, P, m, desc.no_case, desc.negated, user);
    }

    int prep_patterns(SnortConfig* sc) override
    {
        return IntelPmFinishGroup(sc, obj);
    }

    int _search(
        const uint8_t* T, int n, MpseMatch match,
        void* context, int* current_state) override
    {
        *current_state = 0;
        return IntelPmSearch((IntelPm*)p->obj, T, n, match, context);
    }

    int get_pattern_count() override
    {
        return IntelGetPatternCount(obj);
    }
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
    SnortConfig* sc, class Module*, bool use_gc, const MpseAgent* agent)
{
    return new IntelCpmMpse(sc, use_gc, agent);
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
        sizeof(MpseApi),
        SEAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "intel_cpm",
        "Intel CPM library",
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

