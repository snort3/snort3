//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// lowmem.cc author Russ Combs <rucombs@cisco.com>

#include "log/messages.h"
#include "framework/mpse.h"

#include "sfksearch.h"

//-------------------------------------------------------------------------
// "lowmem"
//-------------------------------------------------------------------------

class LowmemMpse : public Mpse
{
private:
    KTRIE_STRUCT* obj;

public:
    LowmemMpse(SnortConfig*, const MpseAgent* agent)
        : Mpse("lowmem")
    { obj = KTrieNew(0, agent); }

    ~LowmemMpse()
    { KTrieDelete(obj); }

    int add_pattern(
        SnortConfig*, const uint8_t* P, unsigned m,
        const PatternDescriptor& desc, void* user) override
    {
        return KTrieAddPattern(obj, P, m, desc.no_case, desc.negated, user);
    }

    int prep_patterns(SnortConfig* sc) override
    {
        return KTrieCompile(sc, obj);
    }

    int _search(
        const uint8_t* T, int n, MpseMatch match,
        void* context, int* current_state) override
    {
        *current_state = 0;
        return KTrieSearch(obj, T, n, match, context);
    }

    int get_pattern_count() override
    { return KTriePatternCount(obj); }
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Mpse* lm_ctor(SnortConfig* sc, class Module*, const MpseAgent* agent)
{
    return new LowmemMpse(sc, agent);
}

static void lm_dtor(Mpse* p)
{
    delete p;
}

static void lm_init()
{
    KTrie_init_xlatcase();
    KTrieInitMemUsed();
}

static void lm_print()
{
    if ( !KTrieMemUsed() )
        return;

    double x = (double)KTrieMemUsed();

    LogMessage("[ LowMem Search-Method Memory Used : %g %s ]\n",
        (x > 1.e+6) ?  x/1.e+6 : x/1.e+3,
        (x > 1.e+6) ? "MBytes" : "KBytes");
}

static const MpseApi lm_api =
{
    {
        PT_SEARCH_ENGINE,
        sizeof(MpseApi),
        SEAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "lowmem",
        "Keyword Trie (low memory, moderate performance) MPSE",
        nullptr,
        nullptr
    },
    MPSE_BASE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    lm_ctor,
    lm_dtor,
    lm_init,
    lm_print,
};

const BaseApi* se_lowmem = &lm_api.base;

