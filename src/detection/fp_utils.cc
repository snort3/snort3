//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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
#include <fstream>
#include <iomanip>
#include <list>
#include <mutex>
#include <sstream>
#include <thread>

#include "framework/mpse.h"
#include "framework/mpse_batch.h"
#include "hash/ghash.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "parser/parse_conf.h"
#include "pattern_match_data.h"
#include "ports/port_group.h"
#include "ports/port_table.h"
#include "ports/rule_port_tables.h"
#include "target_based/snort_protocols.h"
#include "treenodes.h"
#include "utils/util.h"

#include "service_map.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

//--------------------------------------------------------------------------
// private utilities
//--------------------------------------------------------------------------

static bool pmd_can_be_fp(
    PatternMatchData* pmd, CursorActionType cat, bool only_literals)
{
    switch ( cat )
    {
    case CAT_NONE:
    case CAT_ADJUST:
    case CAT_SET_OTHER:
        return false;
    default:
        break;
    }

    if ( only_literals and !pmd->is_literal() )
        return false;

    return pmd->can_be_fp();
}

PmType get_pm_type(CursorActionType cat)
{
    switch ( cat )
    {
    case CAT_SET_RAW:
    case CAT_SET_OTHER:
        return PM_TYPE_PKT;

    case CAT_SET_COOKIE:
        return PM_TYPE_COOKIE;

    case CAT_SET_JS_DATA:
        return PM_TYPE_JS_DATA;

    case CAT_SET_STAT_MSG:
        return PM_TYPE_STAT_MSG;

    case CAT_SET_STAT_CODE:
        return PM_TYPE_STAT_CODE;

    case CAT_SET_METHOD:
        return PM_TYPE_METHOD;

    case CAT_SET_RAW_HEADER:
        return PM_TYPE_RAW_HEADER;

    case CAT_SET_RAW_KEY:
        return PM_TYPE_RAW_KEY;

    case CAT_SET_FILE:
        return PM_TYPE_FILE;

    case CAT_SET_BODY:
        return PM_TYPE_BODY;

    case CAT_SET_HEADER:
        return PM_TYPE_HEADER;

    case CAT_SET_KEY:
        return PM_TYPE_KEY;

    case CAT_SET_VBA:
        return PM_TYPE_VBA;

    default:
        break;
    }
    assert(false);
    return PM_TYPE_MAX;
}

static RuleDirection get_dir(OptTreeNode* otn)
{
    if ( otn->to_client() )
        return RULE_FROM_SERVER;

    if ( otn->to_server() )
        return RULE_FROM_CLIENT;

    return RULE_WO_DIR;
}

// this will be made extensible when fast patterns are extensible
static const char* get_service(const char* opt)
{
    if ( !strncmp(opt, "http_", 5) )
        return "http";
    
    if ( !strncmp(opt, "js_data", 7) )
        return "http";

    if ( !strncmp(opt, "cip_", 4) )  // NO FP BUF
        return "cip";

    if ( !strncmp(opt, "dce_", 4) )
        return "netbios-ssn";

    if ( !strncmp(opt, "dnp3_", 5) )
        return "dnp3";

    if ( !strncmp(opt, "gtp_", 4) )  // NO FP BUF
        return "gtp";

    if ( !strncmp(opt, "modbus_", 7) )
        return "modbus";

    if ( !strncmp(opt, "s7commplus_", 11) )
        return "s7commplus";

    if ( !strncmp(opt, "sip_", 4) )
        return "sip";

    if ( !strncmp(opt, "vba_data", 8) )
        return "file";

    return nullptr;
}

//--------------------------------------------------------------------------
// class to help determine which of two candidate patterns is better for
// a rule that does not have a valid fast_pattern flag.
//--------------------------------------------------------------------------

struct FpSelector
{
    CursorActionType cat = CAT_NONE;
    IpsOption* opt = nullptr;
    PatternMatchData* pmd = nullptr;
    unsigned size = 0;

    FpSelector() = default;
    FpSelector(CursorActionType, IpsOption*, PatternMatchData*);

    bool is_better_than(FpSelector&, bool srvc, RuleDirection, bool only_literals = false);
};

FpSelector::FpSelector(CursorActionType c, IpsOption* o, PatternMatchData* p)
{
    cat = c;
    opt = o;
    pmd = p;
    size = p->pattern_size;
}

bool FpSelector::is_better_than(
    FpSelector& rhs, bool /*srvc*/, RuleDirection /*dir*/, bool only_literals)
{
    if ( !pmd_can_be_fp(pmd, cat, only_literals) )
    {
        if ( pmd->is_fast_pattern() )
            ParseWarning(WARN_RULES, "content ineligible for fast_pattern matcher - ignored");

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
// mpse database serialization
//--------------------------------------------------------------------------

static unsigned mpse_loaded, mpse_dumped;

static bool store(const std::string& s, const uint8_t* data, size_t len)
{
    std::ofstream out(s.c_str(), std::ofstream::binary);
    out.write((const char*)data, len);
    return true;
}

static bool fetch(const std::string& s, uint8_t*& data, size_t& len)
{
    std::ifstream in(s.c_str(), std::ifstream::binary);

    if ( !in.is_open() )
        return false;

    in.seekg (0, in.end);
    len = in.tellg();
    in.seekg (0);

    data = new uint8_t[len];
    in.read((char*)data, len);

    return true;
}

static std::string make_db_name(
    const std::string& path, const char* proto, const char* dir, const char* buf, const std::string& id)
{
    std::stringstream ss;

    ss << path << "/";
    ss << proto << "_";
    ss << dir << "_";
    ss << buf << "_";

    ss << std::hex << std::setfill('0') << std::setw(2);

    for ( auto c : id )
        ss << (unsigned)(uint8_t)c;

    ss << ".hsdb";

    return ss.str();
}

static bool db_dump(const std::string& path, const char* proto, const char* dir, RuleGroup* g)
{
    for ( auto i = 0; i < PM_TYPE_MAX; ++i )
    {
        if ( !g->mpsegrp[i] )
            continue;

        std::string id;
        g->mpsegrp[i]->normal_mpse->get_hash(id);

        std::string file = make_db_name(path, proto, dir, pm_type_strings[i], id);

        uint8_t* db = nullptr;
        size_t len = 0;

        if ( g->mpsegrp[i]->normal_mpse->serialize(db, len) and db and len > 0 )
        {
            store(file, db, len);
            free(db);
            ++mpse_dumped;
        }
        else
        {
            ParseWarning(WARN_RULES, "Failed to serialize %s", file.c_str());
            return false;
        }
    }
    return true;
}

static bool db_load(const std::string& path, const char* proto, const char* dir, RuleGroup* g)
{
    for ( auto i = 0; i < PM_TYPE_MAX; ++i )
    {
        if ( !g->mpsegrp[i] )
            continue;

        std::string id;
        g->mpsegrp[i]->normal_mpse->get_hash(id);

        std::string file = make_db_name(path, proto, dir, pm_type_strings[i], id);

        uint8_t* db = nullptr;
        size_t len = 0;

        if ( !fetch(file, db, len) )
        {
            ParseWarning(WARN_RULES, "Failed to read %s", file.c_str());
            return false;
        }
        else if ( !g->mpsegrp[i]->normal_mpse->deserialize(db, len) )
        {
            ParseWarning(WARN_RULES, "Failed to deserialize %s", file.c_str());
            return false;
        }
        delete[] db;
        ++mpse_loaded;
    }
    return true;
}

typedef bool (*db_io)(const std::string&, const char*, const char*, RuleGroup*);

static void port_io(
    const std::string& path, const char* proto, const char* end, PortTable* pt, db_io func)
{
    for (GHashNode* node = pt->pt_mpo_hash->find_first();
         node;
         node = pt->pt_mpo_hash->find_next())
    {
        PortObject2* po = (PortObject2*)node->data;

        if ( !po or !po->group )
            continue;

        func(path, proto, end, po->group);
    }
}

static void port_io(
    const std::string& path, const char* proto, const char* end, PortObject* po, db_io func)
{
    if ( po->group )
        func(path, proto, end, po->group);
}

static void svc_io(const std::string& path, const char* dir, GHash* h, db_io func)
{
    for ( GHashNode* n = h->find_first(); n; n = h->find_next())
    {
        func(path, (const char*)n->key, dir, (RuleGroup*)n->data);
    }
}

static void fp_io(const SnortConfig* sc, const std::string& path, db_io func)
{
    auto* pt = sc->port_tables;

    port_io(path, "ip", "src", pt->ip.src, func);
    port_io(path, "ip", "dst", pt->ip.dst, func);
    port_io(path, "ip", "any", pt->ip.any, func);

    port_io(path, "icmp", "src", pt->icmp.src, func);
    port_io(path, "icmp", "dst", pt->icmp.dst, func);
    port_io(path, "icmp", "any", pt->icmp.any, func);

    port_io(path, "tcp", "src", pt->tcp.src, func);
    port_io(path, "tcp", "dst", pt->tcp.dst, func);
    port_io(path, "tcp", "any", pt->tcp.any, func);

    port_io(path, "udp", "src", pt->udp.src, func);
    port_io(path, "udp", "dst", pt->udp.dst, func);
    port_io(path, "udp", "any", pt->udp.any, func);

    auto* sp = sc->spgmmTable;

    svc_io(path, "s2c", sp->to_cli, func);
    svc_io(path, "c2s", sp->to_srv, func);
}

//--------------------------------------------------------------------------
// public methods
//--------------------------------------------------------------------------

unsigned fp_serialize(const SnortConfig* sc, const std::string& dir)
{
    mpse_dumped = 0;
    fp_io(sc, dir, db_dump);
    return mpse_dumped;
}

unsigned fp_deserialize(const SnortConfig* sc, const std::string& dir)
{
    mpse_loaded = 0;
    fp_io(sc, dir, db_load);
    return mpse_loaded;
}

void validate_services(SnortConfig* sc, OptTreeNode* otn)
{
    std::string svc;
    bool file = false;

    for (OptFpList* ofl = otn->opt_func; ofl; ofl = ofl->next)
    {
        if ( !ofl->ips_opt )
            continue;

        CursorActionType cat = ofl->ips_opt->get_cursor_type();

        if ( cat <= CAT_ADJUST )
            continue;

        const char* s = ofl->ips_opt->get_name();

        // special case file_data because it could be any subset of file carving services
        if ( !strcmp(s, "file_data") )
        {
            file = true;
            continue;
        }

        s = get_service(s);

        if ( !s )
            continue;

        if ( !svc.empty() and svc != s )
        {
            ParseWarning(WARN_RULES, "%u:%u:%u has mixed service buffers (%s and %s)",
                otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev, svc.c_str(), s);
        }
        svc = s;
    }
    if ( otn->sigInfo.services.size() == 1 and !svc.empty() and otn->sigInfo.services[0].service != svc )
    {
        ParseWarning(WARN_RULES, "%u:%u:%u has service:%s with %s buffer",
            otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev,
            otn->sigInfo.services[0].service.c_str(), svc.c_str());
    }
    if ( otn->sigInfo.services.empty() and !svc.empty() )
    {
        ParseWarning(WARN_RULES, "%u:%u:%u has no service with %s buffer",
            otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev, svc.c_str());

        add_service_to_otn(sc, otn, svc.c_str());
    }
    if ( otn->sigInfo.services.empty() and file )
    {
        ParseWarning(WARN_RULES, "%u:%u:%u has no service with file_data",
            otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev);
        add_service_to_otn(sc, otn, "file");
    }
}

PatternMatchVector get_fp_content(
    OptTreeNode* otn, OptFpList*& node, bool srvc, bool only_literals, bool& exclude)
{
    CursorActionType curr_cat = CAT_SET_RAW;
    FpSelector best;
    bool content = false;
    PatternMatchVector pmds;

    for (OptFpList* ofl = otn->opt_func; ofl; ofl = ofl->next)
    {
        if ( !ofl->ips_opt )
            continue;

        CursorActionType cat = ofl->ips_opt->get_cursor_type();

        if ( cat > CAT_ADJUST )
            curr_cat = cat;

        RuleDirection dir = get_dir(otn);
        PatternMatchData* tmp = ofl->ips_opt->get_pattern(otn->snort_protocol_id, dir);

        if ( !tmp )
            continue;

        content = true;

        FpSelector curr(curr_cat, ofl->ips_opt, tmp);

        if ( curr.is_better_than(best, srvc, dir, only_literals) )
        {
            best = curr;
            node = ofl;
        }
    }

    exclude = best.pmd and (best.cat != CAT_SET_RAW) and !srvc and !otn->sigInfo.services.empty();

    if ( content && !best.pmd)
        ParseWarning(WARN_RULES, "content based rule %u:%u has no eligible fast pattern",
            otn->sigInfo.gid, otn->sigInfo.sid);

    if ( !exclude and best.pmd )
    {
        PatternMatchData* alt_pmd = best.opt->get_alternate_pattern();
        if (alt_pmd)
            pmds.emplace_back(alt_pmd);
        pmds.emplace_back(best.pmd); // add primary pattern last
    }
    return pmds;
}

bool make_fast_pattern_only(const OptFpList* ofp, const PatternMatchData* pmd)
{
    // FIXIT-L no_case consideration is mpse specific, delegate
    if ( !pmd->is_relative() and !pmd->is_negated() and
         !pmd->offset and !pmd->depth and pmd->is_no_case() )
    {
        ofp = ofp->next;
        if ( !ofp || !ofp->ips_opt || !ofp->ips_opt->is_relative() )
            return true;
    }
    return false;
}

bool is_fast_pattern_only(const OptTreeNode* otn, const OptFpList* ofp, Mpse::MpseType mpse_type)
{
    if ( mpse_type == Mpse::MPSE_TYPE_NORMAL and otn->normal_fp_only == ofp )
        return true;

    if ( mpse_type == Mpse::MPSE_TYPE_OFFLOAD and otn->offload_fp_only == ofp )
        return true;

    return false;
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
    FpSelector left(CAT_SET_RAW, nullptr, &pmd);
    CHECK(left.is_better_than(test, false, RULE_WO_DIR));

    test.size = 1;
    CHECK(left.is_better_than(test, false, RULE_WO_DIR));
}

TEST_CASE("fp_negated", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "foo");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x1, "foo");
    FpSelector s1(CAT_SET_RAW, nullptr, &p1);

    CHECK(s0.is_better_than(s1, false, RULE_WO_DIR));
    CHECK(!s1.is_better_than(s0, false, RULE_WO_DIR));
}

TEST_CASE("fp_cat1", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_FILE, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "short");
    FpSelector s1(CAT_SET_BODY, nullptr, &p1);

    CHECK(s0.is_better_than(s1, true, RULE_WO_DIR));
}

TEST_CASE("fp_cat2", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "foo");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "foo");
    FpSelector s1(CAT_SET_FILE, nullptr, &p1);

    CHECK(!s0.is_better_than(s1, false, RULE_WO_DIR));
    CHECK(!s1.is_better_than(s0, false, RULE_WO_DIR));
}

TEST_CASE("fp_cat3", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "foo");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "foo");
    FpSelector s1(CAT_SET_FILE, nullptr, &p1);

    CHECK(!s0.is_better_than(s1, true, RULE_WO_DIR));
}

TEST_CASE("fp_size", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_HEADER, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "short");
    FpSelector s1(CAT_SET_HEADER, nullptr, &p1);

    CHECK(s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "short");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_KEY, nullptr, &p1);

    CHECK(!s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port_user", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x10, "short");
    FpSelector s0(CAT_SET_KEY, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_KEY, nullptr, &p1);

    CHECK(s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port_user_user", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x10, "longer");
    FpSelector s0(CAT_SET_KEY, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x10, "short");
    FpSelector s1(CAT_SET_KEY, nullptr, &p1);

    CHECK(!s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port_user_user2", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_KEY, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x10, "short");
    FpSelector s1(CAT_SET_KEY, nullptr, &p1);

    CHECK(!s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_srvc_1", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "short");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_KEY, nullptr, &p1);

    CHECK(s1.is_better_than(s0, true, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_srvc_2", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "short");
    FpSelector s1(CAT_SET_KEY, nullptr, &p1);

    CHECK(s0.is_better_than(s1, true, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_srvc_rsp", "[FastPatternSelect]")
{
    PatternMatchData p0;
    set_pmd(p0, 0x0, "short");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1;
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_KEY, nullptr, &p1);

    CHECK(!s0.is_better_than(s1, true, RULE_FROM_SERVER));
    CHECK(s1.is_better_than(s0, true, RULE_FROM_SERVER));
}
#endif

