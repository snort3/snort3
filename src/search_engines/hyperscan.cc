//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2014-2016 Titan IC Systems Ltd. All rights reserved.
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

#include "hyperscan.h"

#include <assert.h>
#include <ctype.h>
#include <string.h>

#include <string>
#include <vector>

#include <hs_compile.h>
#include <hs_runtime.h>

#include "framework/mpse.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "utils/stats.h"

#include "tics/tics.h"

struct Pattern
{
    std::string pat;
    unsigned len;
    unsigned flags;
    bool no_case;
    bool negate;

    void* user;
    void* user_tree;
    void* user_list;

    Pattern(const uint8_t*, unsigned, const Mpse::PatternDescriptor&, void*);
    void escape(const uint8_t*, unsigned, bool);
};

Pattern::Pattern(
    const uint8_t* s, unsigned n, const Mpse::PatternDescriptor& d, void* u)
{
    escape(s, n, d.literal);

    len = n;
    no_case = d.no_case;
    negate = d.negated;
    flags = d.flags;
    user = u;
    user_tree = user_list = nullptr;

    if ( no_case )
        flags |= HS_FLAG_CASELESS;

    flags |= HS_FLAG_SINGLEMATCH;
}

void Pattern::escape(const uint8_t* s, unsigned n, bool literal)
{
    for ( unsigned i = 0; i < n; ++i )
    {
        if ( !isprint(s[i]) )
        {
            char hex[5];
            snprintf(hex, sizeof(hex), "\\x%02X", s[i]);
            pat += hex;
        }
        else
        {
            const char* special = ".^$*+?()[]{}\\|";

            if ( literal and strchr(special, s[i]) )
                pat += '\\';

            pat += s[i];
        }
    }
}

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
    {
        agent = a;
        ++instances;
    }

    ~HyperscanMpse()
    {
        if ( hs_db )
            hs_free_database(hs_db);

        user_dtor();
    }

    int add_pattern(
        SnortConfig*, const uint8_t* pat, unsigned len,
        const PatternDescriptor& desc, void* user) override
    {
        Pattern p(pat, len, desc, user);
        pvector.push_back(p);
        ++patterns;
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
    void user_ctor(SnortConfig*);
    void user_dtor();

    const MpseAgent* agent;
    PatternVector pvector;

    hs_database_t* hs_db = nullptr;

    static THREAD_LOCAL MpseMatch match_cb;
    static THREAD_LOCAL void* match_ctx;

public:
    static uint64_t instances;
    static uint64_t patterns;
};

THREAD_LOCAL MpseMatch HyperscanMpse::match_cb = nullptr;
THREAD_LOCAL void* HyperscanMpse::match_ctx = nullptr;

uint64_t HyperscanMpse::instances = 0;
uint64_t HyperscanMpse::patterns = 0;

// other mpse have direct access to their fsm match states and populate
// user list and tree with each pattern that leads to the same match state.
// with hyperscan we don't have internal fsm knowledge and each fast
// pattern is considered to be in a distinct match state.  the resulting
// detection option trees for hyperscan are thus just single option chains.

void HyperscanMpse::user_ctor(SnortConfig* sc)
{
    for ( auto& p : pvector )
    {
        if ( p.user )
        {
            if ( p.negate )
                agent->negate_list(p.user, &p.user_list);
            else
                agent->build_tree(sc, p.user, &p.user_tree);
        }
        agent->build_tree(sc, nullptr, &p.user_tree);
    }
}

void HyperscanMpse::user_dtor()
{
    for ( auto& p : pvector )
    {
        if ( p.user )
            agent->user_free(p.user);

        if ( p.user_list )
            agent->list_free(&p.user_list);

        if ( p.user_tree )
            agent->tree_free(&p.user_tree);
    }
}

int HyperscanMpse::prep_patterns(SnortConfig* sc)
{
    hs_compile_error_t* errptr = nullptr;
    std::vector<const char*> pats;
    std::vector<unsigned> flags;
    std::vector<unsigned> ids;

    unsigned id = 0;

    for ( auto& p : pvector )
    {
        pats.push_back(p.pat.c_str());
        flags.push_back(p.flags);
        ids.push_back(id++);
    }

    if ( hs_compile_multi(&pats[0], &flags[0], &ids[0], pvector.size(), HS_MODE_BLOCK,
            nullptr, &hs_db, &errptr) or !hs_db )
    {
        // FIXIT-L emit data from errptr
        ParseError("can't compile pattern database '%s'", "hs_compile_multi");
        hs_free_compile_error(errptr);
        return -1;
    }

    if ( hs_error_t err = hs_alloc_scratch(hs_db, &s_scratch) )
    {
        ParseError("can't allocate search scratch space (%d)", err);
        return -2;
    }

    user_ctor(sc);
    return 0;
}

int HyperscanMpse::match(unsigned id, unsigned long long to)
{
    assert(id < pvector.size());
    Pattern& p = pvector[id];
    return match_cb(p.user, p.user_tree, (int)to, match_ctx, p.user_list);
}

int HyperscanMpse::match(
    unsigned id, unsigned long long /*from*/, unsigned long long to,
    unsigned /*flags*/, void* pv)
{
    HyperscanMpse* h = (HyperscanMpse*)pv;
    return  h->match(id, to);
}

#ifdef TICS_USE_RXP_MATCH
int HyperscanMpse::_search(
    const uint8_t* buf, int n, MpseMatch mf, void* pv, int* current_state)
{
    *current_state = 0;

    match_cb = mf;
    match_ctx = pv;

    SnortState* ss = snort_conf->state + get_instance_id();

    /*Check the match mode*/
#ifdef TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH

    /*If data size is smaller or equal to the limit we scan with hyperscan*/
    if(n <= TICS_MAX_RXP_PACKET_LENGTH||rxp_response_queues_status[PM_TYPE_search]==false)
    {
        pc.tics_hs_searches++;
        /*Count the type of error that lead us to this point*/
        if(n <= TICS_MAX_RXP_PACKET_LENGTH)
        {
            pc.tics_hs_pkt_len_searches++;
        }
        else if(rxp_response_queues_status[PM_TYPE_search]==false)
        {
            pc.tics_hs_rxp_err_searches++;
        }

        /*Count the type of data analyzed by hyperscan*/
        if (PM_TYPE_search == PM_TYPE_PKT)
        {
            pc.tics_hs_pkt_searches++;
        }
        else if (PM_TYPE_search == PM_TYPE_FILE)
        {
            pc.tics_hs_file_searches++;
        }
        else if (PM_TYPE_search == PM_TYPE_KEY)
        {
            pc.tics_hs_key_searches++;
        }
        else if (PM_TYPE_search == PM_TYPE_HEADER)
        {
            pc.tics_hs_header_searches++;
        }
        else if (PM_TYPE_search == PM_TYPE_BODY)
        {
            pc.tics_hs_body_searches++;
        }
        else if (PM_TYPE_search == PM_TYPE_ALT)
        {
            pc.tics_hs_alt_searches++;
        }
        else
        {
            fprintf(stdout,"Error: TICS The job analyzed belong to type (%d)\n",PM_TYPE_search);
            exit(-1);
        }

        // scratch is null for the degenerate case w/o patterns
        assert(!hs_db or ss->hyperscan_scratch);

        hs_scan(hs_db, (char*)buf, n, 0, (hs_scratch_t*)ss->hyperscan_scratch,
            HyperscanMpse::match, this);
    }
    else

#endif /* TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH */

    {
        pc.tics_rxp_searches++;

        /* Check if matches were found by rxp */
        if (rxp_response_queues[PM_TYPE_search][port_group_search].index != 0)
        {
            /*Check the list of matches from rxp*/
            uint32_t i = 0;
            for (i = 0; i < rxp_response_queues[PM_TYPE_search][port_group_search].index; i++)
            {
                    uint32_t j = 0;
                    PMQ *tmp_resps = &(rxp_response_queues[PM_TYPE_search][port_group_search]);
                    for (j = 0; j < t2s_psb_id_map[tmp_resps->id[i]-1].tics_fp_elem->snort_add_seqs_cnt; j++)
                    {
                            /*call hyperscan_match*/
                            match(t2s_psb_id_map[tmp_resps->id[i]-1].tics_fp_elem->snort_add_seqs[j],
                                    tmp_resps->to[i]);
                    }
            }
        }
    }
    return 0;
}
#else /* TICS_USE_RXP_MATCH */
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
#endif /* TICS_USE_RXP_MATCH */

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

static void hs_init()
{
    HyperscanMpse::instances = 0;
    HyperscanMpse::patterns = 0;
}

static void hs_print()
{
    LogCount("instances", HyperscanMpse::instances);
    LogCount("patterns", HyperscanMpse::patterns);
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
    nullptr,  // activate
    nullptr,  // setup
    nullptr,  // start
    nullptr,  // stop
    hs_ctor,
    hs_dtor,
    hs_init,
    hs_print,
};

//#ifdef BUILDING_SO
//SO_PUBLIC const BaseApi* snort_plugins[] =
//{
//    &hs_api.base,
//    nullptr
//};
//#else
const BaseApi* se_hyperscan = &hs_api.base;
//#endif

