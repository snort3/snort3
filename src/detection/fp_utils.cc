//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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
#include <unordered_map>

#include "framework/inspector.h"
#include "framework/mpse.h"
#include "framework/mpse_batch.h"
#include "hash/ghash.h"
#include "ips_options/ips_flowbits.h"
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

#include "fp_config.h"
#include "service_map.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

// PduSection to string, used by debug traces
const char* section_to_str[] = {"NONE", "HEADER", "HEADER_BODY", "BODY", "TRAILER"};

//--------------------------------------------------------------------------
// private utilities
//--------------------------------------------------------------------------

static bool pmd_can_be_fp(
    PatternMatchData* pmd, CursorActionType cat, bool only_literals)
{
    switch ( cat )
    {
    case CAT_NONE:
    case CAT_READ:
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

PatternMatcher::Type get_pm_type(const std::string& buf)
{
    if ( buf == "pkt_data" or buf == "raw_data" )
        return PatternMatcher::PMT_PKT;

    if ( buf == "file_data" )
        return PatternMatcher::PMT_FILE;

    return PatternMatcher::PMT_PDU;
}

static RuleDirection get_dir(OptTreeNode* otn)
{
    if ( otn->to_client() )
        return RULE_FROM_SERVER;

    if ( otn->to_server() )
        return RULE_FROM_CLIENT;

    return RULE_WO_DIR;
}

using SvcList = std::vector<std::string>;
static std::unordered_map<std::string, SvcList> buffer_map;

static const char* get_service(const char* buf)
{
    auto it = buffer_map.find(buf);

    if ( it == buffer_map.end() )
        return nullptr;

    return it->second[0].c_str();
}

static unsigned get_num_services(const char* buf)
{
    auto it = buffer_map.find(buf);

    if ( it == buffer_map.end() )
        return 0;

    return it->second.size();
}

void update_buffer_map(const char** bufs, const char* svc)
{
    if ( !bufs )
        return;

    if ( !svc )
    {
        assert(svc);
        return;
    }

    for ( int i = 0; bufs[i]; ++i )
        buffer_map[bufs[i]].push_back(svc);

    if ( !strcmp(svc, "http") )
        buffer_map["file_data"].push_back("http");
}

void add_default_services(SnortConfig* sc, const std::string& buf, OptTreeNode* otn)
{
    SvcList& list = buffer_map[buf];

    for ( auto& svc : list )
        add_service_to_otn(sc, otn, svc.c_str());
}

// FIXIT-L this will be removed when ips option api
// is updated to include service
static const char* guess_service(const char* opt)
{
    if ( !strncmp(opt, "http_", 5) )
        return "http";

    if ( !strncmp(opt, "cip_", 4) or !strncmp(opt, "enip_", 5) )
        return "cip";

    if ( !strncmp(opt, "dce_", 4) )
        return "netbios-ssn";

    if ( !strncmp(opt, "dnp3_", 5) )
        return "dnp3";

    if ( !strncmp(opt, "gtp_", 4) )
        return "gtp";

    if ( !strncmp(opt, "mms_", 4) )
        return "mms";

    if ( !strncmp(opt, "modbus_", 7) )
        return "modbus";

    if ( !strncmp(opt, "s7commplus_", 11) )
        return "s7commplus";

    if ( !strncmp(opt, "sip_", 4) )
        return "sip";

    if ( !strncmp(opt, "ssl_", 4) )
        return "ssl";

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
    const std::string& path, const char* proto, const char* dir, const char* buf, const std::string& id, int sect)
{
    std::stringstream ss;

    ss << path << "/";
    ss << proto << "_";
    ss << dir << "_";
    ss << buf << "_";
    ss << std::to_string(sect) << "_";
    ss << std::hex << std::setfill('0') << std::setw(2);

    for ( auto c : id )
        ss << (unsigned)(uint8_t)c;

    ss << ".hsdb";

    return ss.str();
}

static bool db_dump(const std::string& path, const char* proto, const char* dir, RuleGroup* g)
{
    for ( int sect = PS_NONE; sect <= PS_MAX; sect++)
    {
        for ( auto it : g->pm_list[sect] )
        {
            if (it->group.normal_is_dup)
                continue;

            std::string id;
            it->group.normal_mpse->get_hash(id);

            std::string file = make_db_name(path, proto, dir, it->name, id, sect);

            uint8_t* db = nullptr;
            size_t len = 0;

            if ( it->group.normal_mpse->serialize(db, len) and db and len > 0 )
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
    }
    return true;
}

static bool db_load(const std::string& path, const char* proto, const char* dir, RuleGroup* g)
{
    for ( int sect = PS_NONE; sect <= PS_MAX; sect++)
    {
        for ( auto it : g->pm_list[sect] )
        {
            if (it->group.normal_is_dup)
                continue;

            std::string id;
            it->group.normal_mpse->get_hash(id);

            std::string file = make_db_name(path, proto, dir, it->name, id, sect);

            uint8_t* db = nullptr;
            size_t len = 0;

            if ( !fetch(file, db, len) )
            {
                ParseWarning(WARN_RULES, "Failed to read %s", file.c_str());
                delete[] db;
                return false;
            }
            else if ( !it->group.normal_mpse->deserialize(db, len) )
            {
                ParseWarning(WARN_RULES, "Failed to deserialize %s", file.c_str());
                delete[] db;
                return false;
            }
            delete[] db;
            ++mpse_loaded;
        }
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

bool has_service_rule_opt(OptTreeNode* otn)
{
    for (OptFpList* ofl = otn->opt_func; ofl; ofl = ofl->next)
    {
        if ( !ofl->ips_opt )
            continue;

        CursorActionType cat = ofl->ips_opt->get_cursor_type();
        const char* s = ofl->ips_opt->get_name();

        if ( cat <= CAT_ADJUST )
        {
            if (guess_service(s) != nullptr)
                return true;

            continue;
        }

        if (get_num_services(s) != 0)
            return true;
    }
    return false;
}

void validate_services(SnortConfig* sc, OptTreeNode* otn)
{
    std::string svc, multi_svc_buf;
    const char* guess = nullptr;

    for (OptFpList* ofl = otn->opt_func; ofl; ofl = ofl->next)
    {
        if ( !ofl->ips_opt )
            continue;

        CursorActionType cat = ofl->ips_opt->get_cursor_type();
        const char* opt = ofl->ips_opt->get_name();

        if ( cat <= CAT_ADJUST )
        {
            if ( !guess )
                guess = guess_service(opt);

            continue;
        }

        unsigned n = get_num_services(opt);

        if ( !n )
            continue;

        if ( n > 1 )
        {
            multi_svc_buf = opt;
            continue;
        }

        const char* opt_svc = get_service(opt);
        const auto& search = sc->service_extension.find(opt_svc);
        if (search != sc->service_extension.end())
        {
            multi_svc_buf = opt;
            continue;
        }

        if ( !svc.empty() and svc != opt_svc )
        {
            ParseWarning(WARN_RULES, "%u:%u:%u has mixed service buffers (%s and %s)",
                otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev, svc.c_str(), opt_svc);
        }
        svc = opt_svc;
    }

    if ( !svc.empty() or !multi_svc_buf.empty() or guess )
        otn->set_service_only();

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
    if ( otn->sigInfo.services.empty() and !multi_svc_buf.empty() )
    {
        ParseWarning(WARN_RULES, "%u:%u:%u has no service with %s",
            otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev, multi_svc_buf.c_str());

        add_default_services(sc, multi_svc_buf, otn);
    }
    if ( !otn->sigInfo.services.size() and guess )
    {
        ParseWarning(WARN_RULES, "%u:%u:%u has no service with %s option",
            otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev, guess);

        add_service_to_otn(sc, otn, guess);
    }
}

PatternMatchVector get_fp_content(
    OptTreeNode* otn, OptFpList*& node, IpsOption*& fp_opt, bool srvc, bool only_literals, bool& exclude)
{
    CursorActionType curr_cat = CAT_SET_RAW;
    FpSelector best;
    bool content = false;
    PatternMatchVector pmds;
    IpsOption* curr_opt = nullptr, * best_opt = nullptr;

    for (OptFpList* ofl = otn->opt_func; ofl; ofl = ofl->next)
    {
        if ( !ofl->ips_opt )
            continue;

        CursorActionType cat = ofl->ips_opt->get_cursor_type();

        if ( cat > CAT_ADJUST )
        {
            if ( cat == CAT_SET_FAST_PATTERN or cat == CAT_SET_RAW )
                curr_opt = ofl->ips_opt;

            curr_cat = cat;
        }

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
            best_opt = curr_opt;
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
        fp_opt = best_opt;
    }
    return pmds;
}

bool make_fast_pattern_only(const OptFpList* ofp, const PatternMatchData* pmd)
{
    if ( pmd->fp_offset or (pmd->fp_length and pmd->pattern_size != pmd->fp_length) )
        return false;

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

bool is_flowbit_setter(const OptFpList* ofp)
{
    return ofp->type == RULE_OPTION_TYPE_FLOWBIT
        and flowbits_setter(ofp->ips_opt);
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
        {
            if ( sc->fast_pattern_config->get_debug_mode() )
                m->print_info();

            c++;
        }
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
    PatternMatchData pmd = { };
    set_pmd(pmd, 0x0, "foo");
    CHECK(true == pmd.can_be_fp());
}

TEST_CASE("pmd_negated", "[PatternMatchData]")
{
    PatternMatchData pmd = { };
    set_pmd(pmd, 0x1, "foo");
    CHECK(false == pmd.can_be_fp());
}

TEST_CASE("pmd_no_case", "[PatternMatchData]")
{
    PatternMatchData pmd = { };
    set_pmd(pmd, 0x2, "foo");
    CHECK(true == pmd.can_be_fp());
}

TEST_CASE("pmd_relative", "[PatternMatchData]")
{
    PatternMatchData pmd = { };
    set_pmd(pmd, 0x4, "foo");
    CHECK(true == pmd.can_be_fp());
}

TEST_CASE("pmd_negated_no_case", "[PatternMatchData]")
{
    PatternMatchData pmd = { };
    set_pmd(pmd, 0x3, "foo");
    CHECK(true == pmd.can_be_fp());
}

TEST_CASE("pmd_negated_relative", "[PatternMatchData]")
{
    PatternMatchData pmd = { };
    set_pmd(pmd, 0x5, "foo");
    CHECK(false == pmd.can_be_fp());
}

TEST_CASE("pmd_negated_no_case_offset", "[PatternMatchData]")
{
    PatternMatchData pmd = { };
    set_pmd(pmd, 0x1, "foo");
    pmd.offset = 3;
    CHECK(false == pmd.can_be_fp());
}

TEST_CASE("pmd_negated_no_case_depth", "[PatternMatchData]")
{
    PatternMatchData pmd = { };
    set_pmd(pmd, 0x3, "foo");
    pmd.depth = 1;
    CHECK(false == pmd.can_be_fp());
}

TEST_CASE("fp_simple", "[FastPatternSelect]")
{
    FpSelector test;
    PatternMatchData pmd = { };
    set_pmd(pmd, 0x0, "foo");
    FpSelector left(CAT_SET_RAW, nullptr, &pmd);
    CHECK(true == left.is_better_than(test, false, RULE_WO_DIR));

    test.size = 1;
    CHECK(true == left.is_better_than(test, false, RULE_WO_DIR));
}

TEST_CASE("fp_negated", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x0, "foo");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x1, "foo");
    FpSelector s1(CAT_SET_RAW, nullptr, &p1);

    CHECK(true == s0.is_better_than(s1, false, RULE_WO_DIR));
    CHECK(false == s1.is_better_than(s0, false, RULE_WO_DIR));
}

TEST_CASE("fp_cat1", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_FAST_PATTERN, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x0, "short");
    FpSelector s1(CAT_SET_FAST_PATTERN, nullptr, &p1);

    CHECK(true == s0.is_better_than(s1, true, RULE_WO_DIR));
}

TEST_CASE("fp_cat2", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x0, "foo");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x0, "foo");
    FpSelector s1(CAT_SET_FAST_PATTERN, nullptr, &p1);

    CHECK(false == s0.is_better_than(s1, false, RULE_WO_DIR));
    CHECK(false == s1.is_better_than(s0, false, RULE_WO_DIR));
}

TEST_CASE("fp_cat3", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x0, "foo");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x0, "foo");
    FpSelector s1(CAT_SET_FAST_PATTERN, nullptr, &p1);

    CHECK(false == s0.is_better_than(s1, true, RULE_WO_DIR));
}

TEST_CASE("fp_size", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_FAST_PATTERN, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x0, "short");
    FpSelector s1(CAT_SET_FAST_PATTERN, nullptr, &p1);

    CHECK(true == s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x0, "short");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_FAST_PATTERN, nullptr, &p1);

    CHECK(false == s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port_user", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x10, "short");
    FpSelector s0(CAT_SET_FAST_PATTERN, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_FAST_PATTERN, nullptr, &p1);

    CHECK(true == s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port_user_user", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x10, "longer");
    FpSelector s0(CAT_SET_FAST_PATTERN, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x10, "short");
    FpSelector s1(CAT_SET_FAST_PATTERN, nullptr, &p1);

    CHECK(false == s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_port_user_user2", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_FAST_PATTERN, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x10, "short");
    FpSelector s1(CAT_SET_FAST_PATTERN, nullptr, &p1);

    CHECK(false == s0.is_better_than(s1, false, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_srvc_1", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x0, "short");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_FAST_PATTERN, nullptr, &p1);

    CHECK(true == s1.is_better_than(s0, true, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_srvc_2", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x0, "longer");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x0, "short");
    FpSelector s1(CAT_SET_FAST_PATTERN, nullptr, &p1);

    CHECK(true == s0.is_better_than(s1, true, RULE_WO_DIR));
}

TEST_CASE("fp_pkt_key_srvc_rsp", "[FastPatternSelect]")
{
    PatternMatchData p0 = { };
    set_pmd(p0, 0x0, "short");
    FpSelector s0(CAT_SET_RAW, nullptr, &p0);

    PatternMatchData p1 = { };
    set_pmd(p1, 0x0, "longer");
    FpSelector s1(CAT_SET_FAST_PATTERN, nullptr, &p1);

    CHECK(false == s0.is_better_than(s1, true, RULE_FROM_SERVER));
    CHECK(true == s1.is_better_than(s0, true, RULE_FROM_SERVER));
}
#endif

