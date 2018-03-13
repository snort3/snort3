//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/mpse.h"

#include "bnfa_search.h"

using namespace snort;

//-------------------------------------------------------------------------
// "ac_bnfa"
//-------------------------------------------------------------------------

class AcBnfaMpse : public Mpse
{
private:
    bnfa_struct_t* obj;

public:
    AcBnfaMpse(SnortConfig*, const MpseAgent* agent)
        : Mpse("ac_bnfa")
    {
        obj=bnfaNew(agent);
        if ( obj ) obj->bnfaMethod = 1;
    }

    ~AcBnfaMpse() override
    {
        if (obj)
            bnfaFree(obj);
    }

    void set_opt(int flag) override
    {
        if (obj)
            bnfaSetOpt(obj, flag);
    }

    int add_pattern(
        SnortConfig*, const uint8_t* P, unsigned m,
        const PatternDescriptor& desc, void* user) override
    {
        return bnfaAddPattern(obj, P, m, desc.no_case, desc.negated, user);
    }

    int prep_patterns(SnortConfig* sc) override
    {
        return bnfaCompile(sc, obj);
    }

    int _search(
        const uint8_t* T, int n, MpseMatch match,
        void* context, int* current_state) override
    {
        /* return is actually the state */
        return _bnfa_search_csparse_nfa(
            obj, T, n, match, context, 0 /* start-state */, current_state);
    }

    //  FIXIT-L Implement search_all method for AC_BNFA.

    int print_info() override
    {
        bnfaPrintInfo(obj);
        return 0;
    }

    int get_pattern_count() override
    {
        return bnfaPatternCount(obj);
    }
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Mpse* bnfa_ctor(
    SnortConfig* sc, class Module*, const MpseAgent* agent)
{
    return new AcBnfaMpse(sc, agent);
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
        "ac_bnfa",
        "Aho-Corasick Binary NFA (low memory, high performance) MPSE",
        nullptr,
        nullptr
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
};

const BaseApi* se_ac_bnfa[] =
{
    &bnfa_api.base,
    nullptr
};

