//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
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
// profiler.cc author Joel Cornett <jocornet@cisco.com>
// based on work by Steven Sturges <ssturges@sourcefire.com>

#include "profiler.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>

#include "detection/fp_detect.h"
#include "detection/treenodes.h"
#include "detection/detection_options.h"
#include "framework/module.h"
#include "hash/sfghash.h"
#include "main/snort_config.h"
#include "parser/parser.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

#define TOTAL "total"

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

class ModStatsFunctor
{
public:
    const ProfileStats* operator()(const std::string&);

    bool is_set() const
    { return type != NONE; }

    void set(Module* m)
    { owner = m; type = MODULE; }

    void set(get_profile_func cb)
    { callback = cb; type = CALLBACK; }

private:
    enum { NONE, MODULE, CALLBACK } type = NONE;
    union
    {
        Module* owner;
        get_profile_func callback;
    };
};

class ModStatsNode
{
public:
    ModStatsNode(const std::string& key) :
        name { key } { }

    template<typename T>
    void set(T v)
    { getter.set(v); }

    bool is_set() const
    { return getter.is_set(); }

    void add_child(ModStatsNode* p)
    { children.insert(p); }

    void reset()
    { stats.reset(); totalled = false; }

    const ProfileStats& get_total()
    { return stats; }

    void accumulate();

    const std::string name;
    std::set<ModStatsNode*> children;

private:
    ProfileStats stats { 0, 0 };
    bool totalled = false;
    ModStatsFunctor getter;
};

struct ModEntry
{
    std::string name;
    ModStatsNode* node;
    ProfileStats stats;

    double ticks_per_check;
    double pct_of_parent;

    std::vector<ModEntry> entries;

    ModEntry(ModStatsNode*, const ProfileStats&);
};

using ModEntrySortFunc = std::function<bool(const ModEntry&, const ModEntry&)>;

// Wraps std::unordered_map with some initialization for operator[]
class ModStatsTree
{
    std::unordered_map<std::string, ModStatsNode> nodes;

public:
    ModStatsNode& operator[](std::string key)
    {
        auto result = nodes.emplace(key, key);
        return result.first->second;
    }

    auto begin() -> decltype(nodes.begin())
    { return nodes.begin(); }

    auto end() -> decltype(nodes.end())
    { return nodes.end(); }
};

struct RuleEntry
{
    SigInfo sig_info;

    OtnState state;

    double ticks_per_check = 0.0;
    double ticks_per_match = 0.0;
    double ticks_per_nomatch = 0.0;

    RuleEntry(const SigInfo&, const OtnState&);
};

using RuleEntrySortFunc = std::function<bool(const RuleEntry&, const RuleEntry&)>;

// -----------------------------------------------------------------------------
// global variables
// -----------------------------------------------------------------------------

THREAD_LOCAL ProfileStats totalPerfStats;
THREAD_LOCAL ProfileStats metaPerfStats;

static ModStatsTree s_module_nodes;

// -----------------------------------------------------------------------------
// static functions
// -----------------------------------------------------------------------------

static inline OtnState& operator+=(OtnState& lhs, const OtnState& rhs)
{
    lhs.ticks += rhs.ticks;
    lhs.ticks_match += rhs.ticks_match;
    lhs.ticks_no_match += rhs.ticks_no_match;
    lhs.checks += rhs.checks;
    lhs.matches += rhs.matches;
    lhs.noalerts += rhs.noalerts;
    lhs.alerts += rhs.alerts;
    return lhs;
}

static double get_ticks_per_us()
{
    static double ticks_per_us = 0.0;
    if ( ticks_per_us == 0.0 )
        ticks_per_us = get_ticks_per_usec();

    return ticks_per_us;
}

template<typename T>
static void add_module(std::string name, const char* pname, T v)
{
    ModStatsNode& node = s_module_nodes[name];

    assert(!node.is_set());
    node.set(v);

    if ( !pname )
        pname = TOTAL;

    // don't allow parent to be child of self
    if ( name == pname )
        return;

    ModStatsNode& parent = s_module_nodes[pname];
    parent.add_child(&node);
}

static void get_mod_entries(ModEntry& parent, ModEntrySortFunc* sort_fn, int count)
{
    std::vector<ModEntry> entries;

    for ( auto child : parent.node->children )
    {
        if ( bool(child->get_total()) )
            entries.emplace_back(child, parent.stats);
    }

    if ( sort_fn )
        std::stable_sort(entries.begin(), entries.end(), *sort_fn);

    size_t n = (count < 0) ? entries.size() : static_cast<size_t>(count);

    for ( size_t i = 0; i < n && i < entries.size(); ++i )
    {
        parent.entries.push_back(entries[i]);
        get_mod_entries(parent.entries.back(), sort_fn, count);
    }
}

static void print_mod_entry(int layer, int num, const ModEntry& root, const ModEntry& cur)
{
    unsigned indent = 6 - (5 - layer) + 2;
    LogMessage("%*d%*s%*d" FMTu64("*") FMTu64("*") "%*.2f%*.2f%*.2f\n",
        indent, num,
        28 - indent, cur.name.c_str(), 6, layer,
        11, cur.stats.checks,
        20, uint64_t((double(cur.stats.ticks) / get_ticks_per_us())),
        11, cur.ticks_per_check / get_ticks_per_us(),
        10, cur.pct_of_parent,
        10, double(cur.stats.ticks) / double(root.stats.ticks) * 100.0);

    int num2 = 0;
    for ( const auto& entry : cur.entries )
        print_mod_entry(layer + 1, ++num2, root, entry);
}

static void print_mod_entries(ModEntry& root, int count)
{
    LogMessage("--------------------------------------------------\n");

    // print table title
    if (count != -1)
        LogMessage("Module Profile Statistics (worst %d)\n", count);
    else
        LogMessage("Module Profile Statistics (all)\n");

    // print headers
    LogMessage("%*s%*s%*s%*s%*s%*s%*s%*s\n",
        4, "Num",
        24, "Module",
        6, "Layer",
        11, "Checks",
        20, "Microsecs",
        11, "Avg/Check",
        10, "%/Caller",
        10, "%/Total");

    LogMessage("%*s%*s%*s%*s%*s%*s%*s%*s\n",
        4, "===",
        24, "======",
        6, "=====",
        11, "======",
        20, "=========",
        11, "=========",
        10, "========",
        10, "========");

    int num = 0;
    for ( const auto& entry : root.entries )
        print_mod_entry(0, ++num, root, entry);

    int indent = root.name.size() + 1;
    LogMessage("%*s%*s%*d" FMTu64("*") FMTu64("*") "%*.2f%*.2f%*.2f\n",
        indent, root.name.c_str(),
        28 - indent, root.name.c_str(), 6, 0,
        11, root.stats.checks,
        20, uint64_t(double(root.stats.ticks) / get_ticks_per_us()),
        11, root.ticks_per_check / get_ticks_per_us(),
        10, root.pct_of_parent,
        10, root.pct_of_parent);
}

bool get_mod_sort_function(ProfileSort sort_mode, ModEntrySortFunc& sort_fn)
{
    switch ( sort_mode )
    {
    case PROFILE_SORT_CHECKS:
        sort_fn = [](const ModEntry& a, const ModEntry& b) -> bool
        { return a.stats.checks > b.stats.checks; };
        break;

    case PROFILE_SORT_TOTAL_TICKS:
        sort_fn = [](const ModEntry& a, const ModEntry& b) -> bool
        { return a.stats.ticks > b.stats.ticks; };
        break;

    case PROFILE_SORT_AVG_TICKS:
        sort_fn = [](const ModEntry& a, const ModEntry& b) -> bool
        { return a.ticks_per_check > b.ticks_per_check; };
        break;

    default:
        return false;
        break;
    }

    return true;
}

static void consolidate_otn_states(OtnState* states)
{
    for ( unsigned i = 1; i < get_instance_max(); ++i )
        states[0] += states[i];
}

static void sort_rule_stats(std::vector<RuleEntry>& entries, ProfileSort sort_mode)
{
    RuleEntrySortFunc sort_fn;
    switch ( sort_mode )
    {
    case PROFILE_SORT_CHECKS:
        sort_fn = [](const RuleEntry& a, const RuleEntry& b)
        { return a.state.checks >= b.state.checks; };
        break;

    case PROFILE_SORT_MATCHES:
        sort_fn = [](const RuleEntry& a, const RuleEntry& b)
        { return a.state.matches >= b.state.matches; };
        break;

    case PROFILE_SORT_NOMATCHES:
        sort_fn = [](const RuleEntry& a, const RuleEntry& b)
        { return (a.state.checks - a.state.matches) > (b.state.checks - b.state.matches); };
        break;

    case PROFILE_SORT_AVG_TICKS_PER_MATCH:
        sort_fn = [](const RuleEntry& a, const RuleEntry& b)
        { return a.ticks_per_match >= b.ticks_per_match; };
        break;

    case PROFILE_SORT_AVG_TICKS_PER_NOMATCH:
        sort_fn = [](const RuleEntry& a, const RuleEntry& b)
        { return a.ticks_per_nomatch >= b.ticks_per_nomatch; };
        break;

    case PROFILE_SORT_TOTAL_TICKS:
        sort_fn = [](const RuleEntry& a, const RuleEntry& b)
        { return a.state.ticks >= b.state.ticks; };
        break;

    case PROFILE_SORT_AVG_TICKS:
        sort_fn = [](const RuleEntry& a, const RuleEntry& b)
        { return a.ticks_per_check >= b.ticks_per_check; };
        break;

    default:
        return;
        break;
    }

    std::sort(entries.begin(), entries.end(), sort_fn);
}

static void get_rule_stats_entries(std::vector<RuleEntry>& entries)
{
    assert(snort_conf);

    detection_option_tree_update_otn_stats(snort_conf->detection_option_tree_hash_table);

    for ( SFGHASH_NODE* h = sfghash_findfirst(snort_conf->otn_map); h; h = sfghash_findnext(snort_conf->otn_map) )
    {
        OptTreeNode* otn = static_cast<OptTreeNode*>(h->data);
        assert(otn);

        OtnState* states = otn->state;
        OtnState& state = states[0];

        consolidate_otn_states(states);

        if ( !state.checks || !state.ticks )
            continue;

        entries.emplace_back(otn->sigInfo, state);
    }
}

static void print_rule_stats(std::vector<RuleEntry>& entries, int num)
{
    // if ( entries.empty ) return;

    LogMessage("--------------------------------------------------\n");

    // print table title
    if ( num != -1 )
        LogMessage("Rule Profile Statistics (worst %d rules)\n", num);

    else
        LogMessage("Rule Profile Statistics (all rules)\n");

    // print headers
    LogMessage(
#ifdef PPM_MGR
        "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
#else
        "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
#endif
        6, "Num",
        9, "SID", 4, "GID", 4, "Rev",
        11, "Checks",
        10, "Matches",
        10, "Alerts",
        20, "Microsecs",
        11, "Avg/Check",
        11, "Avg/Match",
        13, "Avg/Nonmatch"
#ifdef PPM_MGR
        , 11, "Disabled"
#endif
        );

    LogMessage(
#ifdef PPM_MGR
        "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
#else
        "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
#endif
        6, "===",
        9, "===", 4, "===", 4, "===",
        11, "======",
        10, "=======",
        10, "======",
        20, "=========",
        11, "=========",
        11, "=========",
        13, "============"
#ifdef PPM_MGR
        , 11, "========"
#endif
        );

    int i = 0;
    for ( const auto& entry : entries )
    {
        if ( (num != -1) && (i >= num) )
            break;

        LogMessage(
#ifdef PPM_MGR
            "%*d%*d%*d%*d" FMTu64("*") FMTu64("*") FMTu64("*") FMTu64(
            "*") "%*.1f%*.1f%*.1f" FMTu64("*") "\n",
#else
            "%*d%*d%*d%*d" FMTu64("*") FMTu64("*") FMTu64("*") FMTu64("*") "%*.1f%*.1f%*.1f" "\n",
#endif
            6, ++i,
            9, entry.sig_info.id, 4, entry.sig_info.generator, 4, entry.sig_info.rev,
            11, entry.state.checks,
            10, entry.state.matches,
            10, entry.state.alerts,
            20, uint64_t(double(entry.state.ticks) / get_ticks_per_us()),
            11, entry.ticks_per_check / get_ticks_per_us(),
            11, entry.ticks_per_match / get_ticks_per_us(),
            13, entry.ticks_per_nomatch / get_ticks_per_us()
#ifdef PPM_MGR
            , 11, entry.state.ppm_disable_cnt
#endif
            );
    }
}

// -----------------------------------------------------------------------------
// class/struct implementation
// -----------------------------------------------------------------------------

void NodePerfProfiler::update(bool match)
{ stats.update(get_delta(), match); }

const ProfileStats* ModStatsFunctor::operator()(const std::string& key)
{
    assert(is_set());

    if ( type == MODULE )
    {
        const auto *ps = owner->get_profile();
        if ( ps )
            return ps;

        unsigned i = 0;
        const char* name, * pname;
        while ( (ps = owner->get_profile(i++, name, pname)) && key != name );

        return ps;
    }

    else if ( type == CALLBACK )
        return callback(key.c_str());

    return nullptr;
}

void ModStatsNode::accumulate()
{
    assert(!name.empty());

    if ( is_set() )
    {
        const auto* ps = getter(name);
        if ( ps )
            stats += *ps;
    }
}

ModEntry::ModEntry(ModStatsNode* node, const ProfileStats& caller_stats) :
        name(node->name), node(node), stats(node->get_total())
{
    assert(stats.ticks >= stats.checks);
    assert(caller_stats.ticks >= stats.ticks);

    if ( stats.checks == 0.0 )
        ticks_per_check = 0.0;
    else
        ticks_per_check = double(stats.ticks) / double(stats.checks);

    if ( caller_stats.ticks == 0.0 )
        pct_of_parent = 0.0;
    else
        pct_of_parent = double(stats.ticks) / double(caller_stats.ticks) * 100.0;
}

RuleEntry::RuleEntry(const SigInfo& si, const OtnState& os) :
    sig_info(si), state(os)
{
    ticks_per_check = double(state.ticks) / double(state.checks);

    state.checks = std::max(state.checks, state.matches);

    if ( state.matches )
        ticks_per_match = double(state.ticks_match) / double(state.matches);

    // can safely replace != with >
    if ( state.checks != state.matches )
        ticks_per_nomatch = double(state.ticks_no_match) / double(state.checks - state.matches);
}

// -----------------------------------------------------------------------------
// public API
// -----------------------------------------------------------------------------

void PerfProfilerManager::register_module(Module* m)
{
    if ( m->get_profile() )
        register_module(m->get_name(), nullptr, m);

    else
    {
        const char* name, * pname;
        const ProfileStats* ps;
        unsigned i = 0;

        while ( (ps = m->get_profile(i++, name, pname)) )
            register_module(name, pname, m);
    }
}

void PerfProfilerManager::register_module(const char* name, const char* pname, Module* m)
{ add_module(name, pname, m); }

void PerfProfilerManager::register_module(const char* name, const char* pname,
    get_profile_func getter)
{ add_module(name, pname, getter); }

// thread local
void PerfProfilerManager::consolidate_stats()
{
    static std::mutex stats_mutex;
    std::lock_guard<std::mutex> lock(stats_mutex);

    for ( auto it = s_module_nodes.begin(); it != s_module_nodes.end(); ++it )
        it->second.accumulate();
}

void PerfProfilerManager::show_module_stats()
{
    const auto& config = *snort_conf->profile_modules;

    if ( !config.count )
        return;

    ModStatsNode& root_node = s_module_nodes[TOTAL];
    ModEntry root(&root_node, root_node.get_total());

    ModEntrySortFunc sort_fn;
    if ( get_mod_sort_function(config.sort, sort_fn) )
        get_mod_entries(root, &sort_fn, config.count);

    else
        get_mod_entries(root, nullptr, config.count);

    print_mod_entries(root, config.count);
}

void PerfProfilerManager::reset_module_stats()
{
    for ( auto it = s_module_nodes.begin(); it != s_module_nodes.end(); ++it )
        it->second.reset();
}

void PerfProfilerManager::show_rule_stats()
{
    const auto& config = *snort_conf->profile_rules;

    if ( !config.count )
        return;

    std::vector<RuleEntry> entries;
    get_rule_stats_entries(entries);

    if ( entries.empty() )
        return;

    sort_rule_stats(entries, config.sort);
    print_rule_stats(entries, config.count);
}

void PerfProfilerManager::reset_rule_stats()
{
    auto* otn_map = snort_conf->otn_map;

    for ( SFGHASH_NODE* h = sfghash_findfirst(otn_map); h; h = sfghash_findnext(otn_map) )
    {
        auto* otn = static_cast<OptTreeNode*>(h->data);
        assert(otn);

        auto* rtn = getRtnFromOtn(otn);

        if ( !rtn || !is_network_protocol(rtn->proto) )
            continue;

        for ( unsigned i = 0; i < get_instance_max(); ++i )
        {
            auto& state = otn->state[i];
            memset(&state, 0, sizeof(state));
        }
    }
}

void PerfProfilerManager::show_all_stats()
{
    if ( SnortConfig::get_profile_modules() )
        show_module_stats();

    if ( SnortConfig::get_profile_rules() )
        show_rule_stats();
}

void PerfProfilerManager::reset_all_stats()
{
    if ( SnortConfig::get_profile_modules() )
        reset_module_stats();

    if ( SnortConfig::get_profile_rules() )
        reset_rule_stats();
}

// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------

#ifdef UNIT_TEST

struct ProfilePauseObserver
{
    void start()
    {
        start_called = true;
        if ( pause_called )
            pause_called_before_start = true;
    }

    void pause()
    { pause_called = true; }

    bool pause_called = false;
    bool start_called = false;
    bool pause_called_before_start = false;
};

TEST_CASE( "profile stats", "[profiler]" )
{
    ProfileStats stats = { 1, 2 };

    SECTION( "operator bool()" )
    {
        CHECK( stats );
        stats = { 0, 0 };
        CHECK_FALSE( stats );
    }

    SECTION( "operator==" )
    {
        ProfileStats compare = { 0, 0 };
        CHECK_FALSE( stats == compare );
        compare = stats;
        CHECK( stats == compare );
    }

    SECTION( "reset" )
    {
        stats.reset();
        CHECK_FALSE( stats );
    }

    SECTION( "operator+=" )
    {
        ProfileStats inc = { 3, 4 };
        ProfileStats expected = { stats.ticks + inc.ticks, stats.checks + inc.checks };
        stats += inc;

        CHECK( stats == expected );
    }
}

TEST_CASE( "stopwatch", "[profiler]" )
{
    Stopwatch sw;

    REQUIRE_FALSE( sw.alive() );
    REQUIRE( sw.get() == 0 );

    SECTION( "start" )
    {
        sw.start();

        SECTION( "sets clock to alive" )
        {
            CHECK( sw.alive() );
        }

        SECTION( "running elapsed time should be non-zero" )
        {
            CHECK( sw.get() > 0 );
        }

        SECTION( "start on running clock has no effect" )
        {
            auto val = sw.get();
            sw.start();
            CHECK( sw.alive() );
            CHECK( sw.get() > val );
        }
    }

    SECTION( "stop" )
    {
        sw.start();
        sw.stop();

        SECTION( "sets clock to be dead" )
        {
            CHECK_FALSE( sw.alive() );
        }

        SECTION( "ticks should not increase after death" )
        {
            auto val = sw.get();
            CHECK( val == sw.get() );
        }

        SECTION( "stop on stopped clock has no effect" )
        {
            auto val = sw.get();
            sw.stop();
            CHECK_FALSE( sw.alive() );
            CHECK( val == sw.get() );
        }
    }

    SECTION( "reset" )
    {
        sw.start();

        SECTION( "reset on running clock" )
        {
            sw.reset();
            CHECK_FALSE( sw.alive() );
            CHECK( sw.get() == 0 );
        }

        SECTION( "reset on stopped clock" )
        {
            sw.stop();
            sw.reset();
            CHECK_FALSE( sw.alive() );
            CHECK( sw.get() == 0 );
        }
    }

    SECTION( "cancel" )
    {
        sw.start();
        SECTION( "cancel on running clock that has no lap time" )
        {
            sw.cancel();
            CHECK_FALSE( sw.alive() );
            CHECK( sw.get() == 0 );
        }

        SECTION( "cancel on stopped clock that has lap time" )
        {
            sw.stop();
            auto val = sw.get();
            sw.cancel();

            CHECK_FALSE( sw.alive() );
            CHECK( val == sw.get() );
        }
    }
}

TEST_CASE( "perf profiler base", "[profiler]" )
{
    SECTION( "profiler is started on instantiation" )
    {
        PerfProfilerBase prof;
        CHECK( prof.get_delta() > 0 );
    }

    SECTION( "profiler evaluates to true" )
    {
        PerfProfilerBase prof;
        CHECK( prof );
    }
}

TEST_CASE( "perf profiler", "[profiler]" )
{
    ProfileStats stats = { 0, 0 };

    REQUIRE( stats.ticks == 0 );
    REQUIRE( stats.checks == 0 );

    SECTION( "going out of scope causes profiler to update stats" )
    {
        {
            PerfProfiler prof(stats);
        }

        CHECK( stats.ticks > 0 );
        CHECK( stats.checks == 1 );
    }

    SECTION( "stopping profiler is only done once" )
    {
        PerfProfiler prof(stats);
        prof.stop();
        ProfileStats saved = stats;
        prof.stop();

        CHECK( saved.ticks == stats.ticks );
        CHECK( saved.checks == stats.checks );
    }

    SECTION( "profiler can be stopped while paused" )
    {
        PerfProfiler prof(stats);
        prof.pause();
        prof.stop();

        CHECK( stats.ticks > 0 );
        CHECK( stats.checks == 1 );
    }

    SECTION( "profiler can be pause and restarted" )
    {
        PerfProfiler prof(stats);
        prof.pause();
        prof.start();

        CHECK( stats.ticks == 0 );
        CHECK( stats.checks == 0 );

        prof.stop();

        CHECK( stats.ticks > 0 );
        CHECK( stats.checks == 1 );
    }

    SECTION( "profiler correctly handles exceptions" )
    {
        try
        {
            PerfProfiler prof(stats);
            throw int(1);
        }

        catch( int& )
        { }

        CHECK( stats.ticks > 0 );
        CHECK( stats.checks == 1 );
    }
}

TEST_CASE( "node perf profiler", "[profiler]" )
{
    dot_node_state_t stats;
    memset(&stats, 0, sizeof(stats));

    SECTION( "going out of scope causes profiler to update stats" )
    {
        {
            NodePerfProfiler prof(stats);
        }

        CHECK( stats.ticks > 0 );
        CHECK( stats.checks == 1 );

        SECTION( "evaluates to NO MATCH by default" )
        {
            CHECK( stats.ticks_no_match > 0 );
        }
    }

    SECTION( "stopping profiler is only done once" )
    {
        NodePerfProfiler prof(stats);
        prof.stop(false);
        dot_node_state_t saved = stats;
        prof.stop(true);

        CHECK( saved.ticks == stats.ticks );
        CHECK( saved.checks == stats.checks );

        SECTION( "only one of match or no match is updated" )
        {
            CHECK( stats.ticks_no_match > 0 );
            CHECK( stats.ticks_match == 0 );
        }
    }

    SECTION( "profiler can be stopped while paused" )
    {
        NodePerfProfiler prof(stats);
        prof.pause();
        prof.stop(false);

        CHECK( stats.ticks > 0 );
        CHECK( stats.checks == 1 );
    }

    SECTION( "profiler can be pause and restarted" )
    {
        NodePerfProfiler prof(stats);
        prof.pause();
        prof.start();

        CHECK( stats.ticks == 0 );
        CHECK( stats.checks == 0 );

        prof.stop(false);

        CHECK( stats.ticks > 0 );
        CHECK( stats.checks == 1 );
    }

    SECTION( "profiler uses MATCH when stop(true) is called" )
    {
        NodePerfProfiler prof(stats);
        prof.stop(true);

        CHECK( stats.ticks_match > 0 );

        SECTION( "and doesn't update NO MATCH" )
        {
            CHECK( stats.ticks_no_match == 0 );
        }
    }

    SECTION( "profiler correctly handles exceptions" )
    {
        try
        {
            NodePerfProfiler prof(stats);
            throw int(1);
        }

        catch( int& )
        { }

        CHECK( stats.ticks > 0 );
        CHECK( stats.checks == 1 );
    }
}

TEST_CASE( "perf profiler pause", "[profiler]" )
{
    ProfilePauseObserver observer;

    {
        ProfilerPause<decltype(observer)> pause(observer);
    }

    CHECK( observer.pause_called );
    CHECK( observer.start_called );
    CHECK( observer.pause_called_before_start );
}

// FIXIT-M Add unit tests for internally used types

class MockProfilerModule : public Module
{
public:
    MockProfilerModule(ProfileStats* ps = nullptr) :
        Module(nullptr, nullptr), stats(ps) { }

    ProfileStats* get_profile() const override
    {
        get_profile_called = true;
        return stats;
    }

    ProfileStats* stats;
    mutable bool get_profile_called = false;
};

static ProfileStats mod_stats_test_stats;

static ProfileStats* mock_get_profile_func(const char*)
{ return &mod_stats_test_stats; }

TEST_CASE( "mod stats functor", "[profiler]" )
{
    static_assert(std::is_default_constructible<ModStatsFunctor>::value, "");
    static_assert(std::is_copy_constructible<ModStatsFunctor>::value, "");

    ModStatsFunctor functor;

    SECTION( "is not set by default" )
    {
        CHECK_FALSE( functor.is_set() );
    }

    SECTION( "calls Module::get_profile() if module is set" )
    {
        MockProfilerModule m;
        REQUIRE_FALSE( m.get_profile_called );
        functor.set(&m);

        REQUIRE( functor.is_set() );
        functor("");

        CHECK( m.get_profile_called );
    }

    SECTION( "calls get_profile_func if callback is set" )
    {
        functor.set(mock_get_profile_func);
        REQUIRE( functor.is_set() );
        auto ps = functor("");
        REQUIRE( ps );
        CHECK( ps == &mod_stats_test_stats );
    }

    SECTION( "last set() overrides any previous set()" )
    {
        MockProfilerModule m;
        functor.set(&m);
        functor.set(mock_get_profile_func);

        REQUIRE( functor.is_set() );

        auto ps = functor("");
        CHECK( ps == &mod_stats_test_stats );
        CHECK_FALSE( m.get_profile_called );

        functor.set(&m);
        ps = functor("");
        CHECK_FALSE( ps );
        CHECK( m.get_profile_called );
    }

    SECTION( "copy-constructed functor retains information" )
    {
        SECTION( "unset" )
        {
            ModStatsFunctor copied(functor);
            CHECK_FALSE( copied.is_set() );
        }

        SECTION( "set(Module*)" )
        {
            MockProfilerModule m;
            functor.set(&m);

            ModStatsFunctor copied(functor);
            REQUIRE( functor.is_set() );

            copied("");
            CHECK( m.get_profile_called );
        }

        SECTION( "set(get_profile_func)" )
        {
            functor.set(mock_get_profile_func);

            ModStatsFunctor copied(functor);
            REQUIRE( functor.is_set() );

            auto ps = copied("");
            CHECK( ps == &mod_stats_test_stats );
        }
    }
}

TEST_CASE( "mod stats node", "[profiler]" )
{
    ModStatsNode node("a");

    SECTION( "copy-constructed node retains children and name" )
    {
        ModStatsNode child_1("1");
        ModStatsNode child_2("2");

        node.add_child(&child_1);
        node.add_child(&child_2);

        ModStatsNode copied(node);

        CHECK( copied.name == node.name );
        CHECK( copied.children == node.children );
    }

    SECTION( "copy-constructed node retains stats" )
    {
        mod_stats_test_stats = { 1, 2 };
        node.set(mock_get_profile_func);
        node.accumulate();
        auto orig_stats = node.get_total();

        ModStatsNode copied(node);
        auto copied_stats = copied.get_total();

        CHECK( copied_stats == orig_stats );
    }

    SECTION( "accumulate() and get_total() correctly adds stats" )
    {
        mod_stats_test_stats = { 1, 2 };
        ProfileStats expected = mod_stats_test_stats;
        expected += mod_stats_test_stats;

        node.set(mock_get_profile_func);

        node.accumulate();
        node.accumulate();

        auto ps = node.get_total();
        CHECK( ps == expected );
    }

    SECTION( "stats are zero initially" )
    {
        auto ps = node.get_total();
        CHECK_FALSE( ps );
    }
}

TEST_CASE( "mod stats tree", "[profiler]" )
{
    ModStatsTree tree;
    SECTION( "correctly sets the name of a node when accessed" )
    {
        auto& foo = tree["foo"];
        CHECK( foo.name == "foo" );
    }
}

TEST_CASE( "mod entry", "[profiler]" )
{
    ProfileStats stats = { 2, 1 };
    ProfileStats caller_stats = { 20, 10 };
    MockProfilerModule m(&stats);
    ModStatsNode node("a");

    node.set(&m);
    node.accumulate();

    ModEntry entry(&node, caller_stats);

    REQUIRE( entry.stats == stats );

    SECTION( "ctor calculates percentages" )
    {
        CHECK( entry.ticks_per_check == 2.0 );
        CHECK( entry.pct_of_parent == 2.0 / 20.0 * 100.0 );
    }

    SECTION( "zeros" )
    {
        stats = { 0, 0 };
        caller_stats = { 0, 0 };
        node.reset();
        node.accumulate();

        ModEntry entry(&node, caller_stats);

        CHECK( entry.ticks_per_check == 0.0 );
        CHECK( entry.pct_of_parent == 0.0 );
    }
}

TEST_CASE( "rule entry", "[profiler]" )
{
}

TEST_CASE( "module stats algorithms", "[profiler]" )
{
}

TEST_CASE( "rule stats algorithms", "[profiler]" )
{
}

#endif
