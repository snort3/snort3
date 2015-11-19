//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

// hyperscan.cc author Russ Combs <rucombs@cisco.com>

#include <assert.h>

#include <string>
#include <vector>

#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>

#include "framework/mpse.h"
#include "log/messages.h"
#include "main/snort_config.h"

struct Pattern
{
    std::string pat;
    unsigned len;
    bool no_case;
    bool negate;
    void* user;

    Pattern(const uint8_t* s, unsigned n, bool bc, bool bn, void* u)
    { pat.assign((char*)s, n); len = n; no_case = bc; negate = bn; user = u; }
};

typedef std::vector<Pattern> PatternVector;

// we need to update scratch in the main thread as each pattern is processed
// and then clone to thread specific after all rules are loaded.  s_scratch is
// a prototype that is large enough for all uses.

static hs_scratch_t* s_scratch = nullptr;

//-------------------------------------------------------------------------
// mpse
//-------------------------------------------------------------------------

class HyperscanMpse : public Mpse
{
public:
    HyperscanMpse(SnortConfig*, bool use_gc, const MpseAgent* a)
        : Mpse("hyperscan", use_gc)
    { agent = a; }

    ~HyperscanMpse()
    {
        if ( hs_db )
            hs_free_database(hs_db);
    }

    int add_pattern(
        SnortConfig*, const uint8_t* pat, unsigned len,
        bool no_case, bool negate, void* user) override
    {
        Pattern p(pat, len, no_case, negate, user);
        pvector.push_back(p);
        return 0;
    }

    int prep_patterns(SnortConfig*) override;

    int _search(const uint8_t*, int, MpseMatch, void*, int*) override;

    int get_pattern_count() override
    { return pvector.size(); }

    int match(unsigned id, unsigned long long to);

    static int match(
        unsigned id, unsigned long long from, unsigned long long to,
        unsigned flags, void*);

private:
    const MpseAgent* agent;
    PatternVector pvector;

    hs_database_t* hs_db = nullptr;

    MpseMatch match_cb = nullptr;
    void* match_ctx = nullptr;
};

int HyperscanMpse::prep_patterns(SnortConfig*)
{
    hs_compile_error_t* err = nullptr;
    std::vector<const char*> pats;
    std::vector<unsigned> flags;
    std::vector<unsigned> ids;

    unsigned id = 0;

    for ( auto& p : pvector )
    {
        pats.push_back(p.pat.c_str());
        flags.push_back(p.no_case ? HS_FLAG_CASELESS : 0);
        ids.push_back(id++);
    }

    if ( hs_compile_multi(&pats[0], &flags[0], &ids[0], pvector.size(), HS_MODE_BLOCK,
            nullptr, &hs_db, &err) or !hs_db )
    {
        // FIXIT emit data from err
        ParseError("can't compile pattern database '%s'", "hs_compile_multi");
        hs_free_compile_error(err);
        return -1;
    }

    if ( hs_error_t err = hs_alloc_scratch(hs_db, &s_scratch) )
    {
        ParseError("can't allocate search scratch space (%d)", err);
        return -2;
    }

    return 0;
}

// FIXIT-P first cut does not queue matches which will likley be required
// to improve cache performance.  for now each match results in an
// immediate callback.

int HyperscanMpse::match(unsigned id, unsigned long long to)
{
    assert(id < pvector.size());
    return match_cb(pvector[id].user, nullptr, (int)to, match_ctx, nullptr);
}

int HyperscanMpse::match(
    unsigned id, unsigned long long /*from*/, unsigned long long to,
    unsigned /*flags*/, void* pv)
{
    HyperscanMpse* h = (HyperscanMpse*)pv;
    return  h->match(id, to);
}

int HyperscanMpse::_search(
    const uint8_t* buf, int n, MpseMatch mf, void* pv, int* current_state)
{
    *current_state = 0;

    match_cb = mf;
    match_ctx = pv;

    SnortState* ss = snort_conf->state + get_instance_id();

    // scratch is null for the degenerate case w/o patterns
    assert(!hs_db or ss->hyperscan_scratch);

    hs_scan(hs_db, (char*)buf, n, 0, (hs_scratch_t*)ss->hyperscan_scratch,
        HyperscanMpse::match, this);

    return 0;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

void hyperscan_setup(SnortConfig* sc)
{
    for ( unsigned i = 0; i < sc->num_slots; ++i )
    {
        SnortState* ss = sc->state + i;

        if ( s_scratch )
            hs_clone_scratch(s_scratch, (hs_scratch_t**)&ss->hyperscan_scratch);
        else
            ss->hyperscan_scratch = nullptr;
    }
    if ( s_scratch )
    {
        hs_free_scratch(s_scratch);
        s_scratch = nullptr;
    }
}

void hyperscan_cleanup(SnortConfig* sc)
{
    for ( unsigned i = 0; i < sc->num_slots; ++i )
    {
        SnortState* ss = sc->state + i;

        if ( ss->hyperscan_scratch )
        {
            hs_free_scratch((hs_scratch_t*)ss->hyperscan_scratch);
            ss->hyperscan_scratch = nullptr;
        }
    }
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Mpse* hs_ctor(
    SnortConfig* sc, class Module*, bool use_gc, const MpseAgent* a)
{
    return new HyperscanMpse(sc, use_gc, a);
}

static void hs_dtor(Mpse* p)
{
    delete p;
}

static const MpseApi hs_api =
{
    {
        PT_SEARCH_ENGINE,
        sizeof(MpseApi),
        SEAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "hyperscan",
        "intel hyperscan-based mpse with regex support",
        nullptr,
        nullptr
    },
    false,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    hs_ctor,
    hs_dtor,
    nullptr,
    nullptr,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &hs_api.base,
    nullptr
};
#else
const BaseApi* se_hyperscan = &hs_api.base;
#endif

