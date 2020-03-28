//--------------------------------------------------------------------------
// Copyright (C) 2016-2020 Cisco and/or its affiliates. All rights reserved.
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

#include "fp_utils.h"

#include <cassert>
#include <cstring>
#include <list>
#include <mutex>
#include <thread>

#include "ips_options/ips_flow.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "pattern_match_data.h"
#include "ports/port_group.h"
#include "target_based/snort_protocols.h"
#include "treenodes.h"
#include "utils/util.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

//--------------------------------------------------------------------------
// private utilities
//--------------------------------------------------------------------------

static void finalize_content(OptFpList* ofl)
{
    PatternMatchData* pmd = get_pmd(ofl, UNKNOWN_PROTOCOL_ID, RULE_WO_DIR);

    if ( !pmd )
        return;

    if ( pmd->is_negated() )
        pmd->last_check = (PmdLastCheck*)snort_calloc(
            ThreadConfig::get_instance_max(), sizeof(*pmd->last_check));
}

static void clear_fast_pattern_only(OptFpList* ofl)
{
    PatternMatchData* pmd = get_pmd(ofl, UNKNOWN_PROTOCOL_ID, RULE_WO_DIR);

    if ( pmd && pmd->fp_only > 0 )
        pmd->fp_only = 0;
}

static bool pmd_can_be_fp(
    PatternMatchData* pmd, CursorActionType cat, bool only_literals)
{
    if ( cat <= CAT_SET_OTHER )
        return false;

    if ( only_literals and !pmd->is_literal() )
        return false;

    return pmd->can_be_fp();
}

static PmType get_pm_type(CursorActionType cat)
{
    switch ( cat )
    {
    case CAT_SET_RAW:
    case CAT_SET_OTHER:
        return PM_TYPE_PKT;

    case CAT_SET_BODY:
        return PM_TYPE_BODY;

    case CAT_SET_HEADER:
        return PM_TYPE_HEADER;

    case CAT_SET_KEY:
        return PM_TYPE_KEY;

    case CAT_SET_FILE:
        return PM_TYPE_FILE;

    default:
        break;
    }
    assert(false);
    return PM_TYPE_MAX;
}

static RuleDirection get_dir(OptTreeNode* otn)
{
    if ( OtnFlowFromServer(otn) )
        return RULE_FROM_SERVER;

    if ( OtnFlowFromClient(otn) )
        return RULE_FROM_CLIENT;

    return RULE_WO_DIR;
}

//--------------------------------------------------------------------------
// public utilities
//--------------------------------------------------------------------------

PatternMatchData* get_pmd(OptFpList* ofl, SnortProtocolId snort_protocol_id, RuleDirection direction)
{
    if ( !ofl->ips_opt )
        return nullptr;

    return ofl->ips_opt->get_pattern(snort_protocol_id, direction);
}

bool is_fast_pattern_only(OptFpList* ofl, Mpse::MpseType mpse_type)
{
    PatternMatchData* pmd = get_pmd(ofl, UNKNOWN_PROTOCOL_ID, RULE_WO_DIR);

    if ( !pmd )
        return false;

    assert((mpse_type == Mpse::MPSE_TYPE_NORMAL) or (mpse_type == Mpse::MPSE_TYPE_OFFLOAD));

    return (pmd->fp_only & (1 << mpse_type));
}

bool is_fast_pattern_only(OptFpList* ofl)
{
    PatternMatchData* pmd = get_pmd(ofl, UNKNOWN_PROTOCOL_ID, RULE_WO_DIR);

    if ( !pmd )
        return false;

    return pmd->fp_only > 0;
}

/*
  * Trim zero byte prefixes, this increases uniqueness
  * will not alter regex since they can't contain bald \0
  *
  * returns
  *   length - of trimmed pattern
  *   buff - ptr to new beginning of trimmed buffer
  */
unsigned flp_trim(const char* p, unsigned plen, const char** buff)
{
    unsigned i;
    unsigned size = 0;

    if ( !p )
        return 0;

    for (i=0; i<plen; i++)
    {
        if ( p[i] != 0 )
            break;
    }

    if ( i < plen )
        size = plen - i;
    else
        size = 0;

    if ( buff && (size==0) )
    {
        *buff = nullptr;
    }
    else if ( buff )
    {
        *buff = &p[i];
    }
    return size;
}

void validate_fast_pattern(OptTreeNode* otn)
{
    OptFpList* fp = nullptr;
    bool relative_is_bad_mkay = false;

    for (OptFpList* fpl = otn->opt_func; fpl; fpl = fpl->next)
    {
        // a relative option is following a fast_pattern/only and
        if ( relative_is_bad_mkay )
        {
            if (fpl->isRelative)
            {
                assert(fp);
                clear_fast_pattern_only(fp);
            }
        }

        // reset the check if one of these are present.
        if ( fpl->ips_opt and !fpl->ips_opt->get_pattern(0))
        {
            if ( fpl->ips_opt->get_cursor_type() > CAT_NONE )
                relative_is_bad_mkay = false;
        }
        // set/unset the check on content options.
        else
        {
            if ( is_fast_pattern_only(fpl) )
            {
                fp = fpl;
                relative_is_bad_mkay = true;
            }
            else
                relative_is_bad_mkay = false;
        }
        finalize_content(fpl);
    }
}

//--------------------------------------------------------------------------
// class to help determine which of two candidate patterns is better for
// a rule that does not have a valid fast_pattern flag.
//--------------------------------------------------------------------------

struct FpSelector
{
    CursorActionType cat;
    PatternMatchData* pmd;
    unsigned size;

    FpSelector(CursorActionType, PatternMatchData*);

    FpSelector()
    { cat = CAT_NONE; pmd = nullptr; size = 0; }

    bool is_better_than(FpSelector&, bool srvc, RuleDirection, bool only_literals = false);
};

FpSelector::FpSelector(CursorActionType c, PatternMatchData* p)
{
    cat = c;
    pmd = p;

    // FIXIT-M unconditional trim is bad mkay? see fpGetFinalPattern
    size = flp_trim(pmd->pattern_buf, pmd->pattern_size, nullptr);
}

bool FpSelector::is_better_than(
    FpSelector& rhs, bool /*srvc*/, RuleDirection /*dir*/, bool only_literals)
{
    if ( !pmd_can_be_fp(pmd, cat, only_literals) )
    {
        if ( pmd->is_fast_pattern() )
        {
            ParseWarning(WARN_RULES, "content ineligible for fast_pattern matcher - ignored");
            // When we have a normal search engine we do not wish to invalidate the user
            // indicated fast pattern as this may be a valid fast pattern for use in the offload
            // search engine
            // pmd->flags &= ~PatternMatchData::FAST_PAT;
        }
        return false;
    }

    if ( !rhs.pmd )
        return true;

    if ( pmd->is_fast_pattern() )
    {
        if ( rhs.pmd->is_fast_pattern() )
        {
            ParseWarning(WARN_RULES,
                "only one fast_pattern content per rule allowed - using first");
            pmd->flags &= ~PatternMatchData::FAST_PAT;
            return false;
        }
        return true;
    }
    if ( rhs.pmd->is_fast_pattern() )
        return false;

    if ( !pmd->is_negated() && rhs.pmd->is_negated() )
        return true;

    if ( pmd->is_negated() && !rhs.pmd->is_negated() )
        return false;

    if ( size > rhs.size )
        return true;

    return false;
}

//--------------------------------------------------------------------------
// public methods
//--------------------------------------------------------------------------

PatternMatchVector get_fp_content(
    OptTreeNode* otn, OptFpList*& next, bool srvc, bool only_literals, bool& exclude)
{
    CursorActionType curr_cat = CAT_SET_RAW;
    FpSelector best;
    bool content = false;
    bool fp_only = true;
    PatternMatchVector pmds;

    for (OptFpList* ofl = otn->opt_func; ofl; ofl = ofl->next)
    {
        if ( !ofl->ips_opt )
            continue;

        CursorActionType cat = ofl->ips_opt->get_cursor_type();

        if ( cat > CAT_ADJUST )
        {
            curr_cat = cat;
            fp_only = !ofl->ips_opt->fp_research();
        }

        RuleDirection dir = get_dir(otn);
        PatternMatchData* tmp = get_pmd(ofl, otn->snort_protocol_id, dir);

        if ( !tmp )
            continue;

        content = true;

        if ( !fp_only )
            tmp->fp_only = -1;

        tmp->pm_type = get_pm_type(curr_cat);

        FpSelector curr(curr_cat, tmp);

        if ( curr.is_better_than(best, srvc, dir, only_literals) )
        {
            best = curr;
            next = ofl->next;
            pmds.clear();
            // Add alternate pattern
            PatternMatchData* alt_pmd = ofl->ips_opt->get_alternate_pattern();
            if (alt_pmd)
                pmds.emplace_back(alt_pmd);
            // Add main pattern last
            pmds.emplace_back(best.pmd);
        }
    }

    if ( best.pmd and best.cat != CAT_SET_RAW and !srvc and !otn->sigInfo.services.empty() )
    {
        pmds.clear();  // just include in service group
        exclude = true;
    }
    else
        exclude = false;

    if ( content && !best.pmd)
        ParseWarning(WARN_RULES, "content based rule %u:%u has no eligible fast pattern",
            otn->sigInfo.gid, otn->sigInfo.sid);

    return pmds;
}

//--------------------------------------------------------------------------
// mpse compile threads
//--------------------------------------------------------------------------

static std::list<Mpse*> s_tbd;
static std::mutex s_mutex;

static Mpse* get_mpse()
{
    std::lock_guard<std::mutex> lock(s_mutex);

    if ( s_tbd.empty() )
        return nullptr;

    Mpse* m = s_tbd.front();
    s_tbd.pop_front();

    return m;
}

static void compile_mpse(SnortConfig* sc, unsigned id, unsigned* count)
{
    set_instance_id(id);
    unsigned c = 0;

    while ( Mpse* m = get_mpse() )
    {
        if ( !m->prep_patterns(sc) )
            c++;
    }
    std::lock_guard<std::mutex> lock(s_mutex);
    *count += c;
}

void queue_mpse(Mpse* m)
{
    s_tbd.push_back(m);
}

unsigned compile_mpses(struct SnortConfig* sc, bool parallel)
{
    std::list<std::thread*> workers;
    unsigned max = parallel ? sc->num_slots : 1;
    unsigned count = 0;

    if ( max == 1 )
    {
        compile_mpse(sc, get_instance_id(), &count);
        return count;
    }

    for ( unsigned i = 0; i < max; ++i )
        workers.push_back(new std::thread(compile_mpse, sc, i, &count));

    for ( auto* w : workers )
    {
        w->join();
        delete w;
    }
    return count;
}

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
static void set_pmd(PatternMatchData& pmd, unsigned flags, const char* s)
{
    memset(&pmd, 0, sizeof(pmd));

    if ( flags & 0x01 )
        pmd.set_negated();
    if ( flags & 0x02 )
        pmd.set_no_case();
    if ( flags & 0x04 )
        pmd.set_relative();
    if ( flags & 0x08 )
        pmd.set_literal();
    if ( flags & 0x10 )
        pmd.set_fast_pattern();

    pmd.pattern_buf = s;
    pmd.pattern_size = strlen(s);
}

TEST_CASE("pmd_no_options", "[PatternMatchData]")
{
    PatternMatchData pmd;
    set_pmd(pmd, 0x0, "foo");
    CHECK(pmd.can_be_fp());
}

TEST_CASE("pmd_negated", "[PatternMatchData]")
{
    PatternMatchData pmd;
    set_pmd(pmd, 0x1, "foo");
    CHECK(!pmd.can_be_fp());
}

TEST_CASE("pmd_no_case", "[PatternMatchData]")
{
    PatternMatchData pmd;
    set_pmd(pmd, 0x2, "foo");
    CHECK(pmd.can_be_fp());
}

TEST_CASE("pmd_relative", "[PatternMatchData]")
{
    PatternMatchData pmd;
    set_pmd(pmd, 0x4, "foo");
    CHECK(pmd.can_be_fp());
}

TEST_CASE("pmd_negated_no_case", "[PatternMatchData]")
{
    PatternMatchData pmd;
    set_pmd(pmd, 0x3, "foo");
    CHECK(pmd.can_be_fp());
}

TEST_CASE("pmd_negated_relative", "[PatternMatchData]")
{
    PatternMatchData pmd;
    set_pmd(pmd, 0x5, "foo");
    CHECK(!pmd.can_be_fp());
}

TEST_CASE("pmd_negated_no_case_offset", "[PatternMatchData]")
{
    PatternMatchData pmd;
    set_pmd(pmd, 0x1, "foo");
    pmd.offset = 3;
    CHECK(!pmd.can_be_fp());
}

TEST_CASE("pmd_negated_no_case_depth", "[PatternMatchData]")
{
    PatternMatchData pmd;
    set_pmd(pmd, 0x3, "foo");
    pmd.depth = 1;
    CHECK(!pmd.can_be_fp());
}

TEST_CASE("fp_simple", "[FastPatternSelect]")
{
    FpSelector test;
    PatternMatchData pmd;
    set_pmd(pmd, 0x0, "foo");
    FpSelector left(CAT_SET_RAW, &pmd);
    CHECK(left.is_better_than(test, false, RULE_WO_DIR));

    test.size = 1;
    CHECK(left.is_better_than(test, false, RULE_WO_DIR));
}

TEST_CASE("fp_negated", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "foo");
    FpSelector s0(CAT_SET_RAW, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x1, "foo");
    FpSelector s1(CAT_SET_RAW, &p1);

    CHECK(s0.is_better_than(s1, false, RULE_WO_DIR));
    CHECK(!s1.is_better_than(s0, false, RULE_WO_DIR));
}

TEST_CASE("fp_cat1", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_FILE, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "short");
    FpSelector s1(CAT_SET_BODY, &p1);

    CHECK(s0.is_better_than(s1, true, RULE_WO_DIR));
}

TEST_CASE("fp_cat2", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "foo");
    FpSelector s0(CAT_SET_RAW, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "foo");
    FpSelector s1(CAT_SET_FILE, &p1);

    CHECK(!s0.is_better_than(s1, false, RULE_WO_DIR));
    CHECK(!s1.is_better_than(s0, false, RULE_WO_DIR));
}

TEST_CASE("fp_cat3", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "foo");
    FpSelector s0(CAT_SET_RAW, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "foo");
    FpSelector s1(CAT_SET_FILE, &p1);

    CHECK(!s0.is_better_than(s1, true, RULE_WO_DIR));
}

TEST_CASE("fp_size", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_HEADER, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "short");
    FpSelector s1(CAT_SET_HEADER, &p1);

    CHECK(s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "short");
    FpSelector s0(CAT_SET_RAW, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_KEY, &p1);

    CHECK(!s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port_user", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x10, "short");
    FpSelector s0(CAT_SET_KEY, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_KEY, &p1);

    CHECK(s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port_user_user", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x10, "longer");
    FpSelector s0(CAT_SET_KEY, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x10, "short");
    FpSelector s1(CAT_SET_KEY, &p1);

    CHECK(!s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port_user_user2", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_KEY, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x10, "short");
    FpSelector s1(CAT_SET_KEY, &p1);

    CHECK(!s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_srvc_1", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "short");
    FpSelector s0(CAT_SET_RAW, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_KEY, &p1);

    CHECK(s1.is_better_than(s0, true, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_srvc_2", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_RAW, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "short");
    FpSelector s1(CAT_SET_KEY, &p1);

    CHECK(s0.is_better_than(s1, true, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_srvc_rsp", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "short");
    FpSelector s0(CAT_SET_RAW, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_KEY, &p1);

    CHECK(!s0.is_better_than(s1, true, RULE_FROM_SERVER));
    CHECK(s1.is_better_than(s0, true, RULE_FROM_SERVER));
}
#endif

