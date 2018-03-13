//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// profiler_nodes.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "profiler_nodes.h"

#include <cassert>
#include <mutex>

#include "framework/module.h"

#include "profiler_defs.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

struct GetProfileFunctor
{
    GetProfileFunctor(const std::string& name) : name(name) { }

    virtual ~GetProfileFunctor() = default;
    virtual const ProfileStats* operator()() = 0;

    const std::string name;
};

struct GetProfileFromModule : public GetProfileFunctor
{
    GetProfileFromModule(const std::string& name, Module* m) :
        GetProfileFunctor(name), m(m) { }

    const ProfileStats* operator()() override
    {
        // const auto *ps = m->get_profiler_stats();
        const auto *ps = m->get_profile();
        if ( ps )
            return ps;

        unsigned i = 0;
        const char* n, * pn;
        // while ( (ps = m->get_profiler_stats(i++, n, pn)) && name != n );
        while ( (ps = m->get_profile(i++, n, pn)) && name != n );

        return ps;
    }

    Module* m;
};

struct GetProfileFromFunction : public GetProfileFunctor
{
    GetProfileFromFunction(const std::string& name, get_profile_stats_fn fn) :
        GetProfileFunctor(name), fn(fn) { }

    const ProfileStats* operator()() override
    { return fn(name.c_str()); }

    get_profile_stats_fn fn;
};

// -----------------------------------------------------------------------------
// implementation
// -----------------------------------------------------------------------------

template<typename Getter>
static void setup_node(ProfilerNode& child, ProfilerNode& parent, Getter g)
{
    assert(!child.is_set());
    child.set(g);

    // don't link parent->parent
    if ( child == parent )
        return;

    parent.add_child(&child);
}

void ProfilerNode::set(Module* m)
{ getter = std::make_shared<GetProfileFromModule>(name, m); }

void ProfilerNode::set(get_profile_stats_fn fn)
{ getter = std::make_shared<GetProfileFromFunction>(name, fn); }

void ProfilerNode::accumulate()
{
    if ( is_set() )
    {
        const auto* local_stats = (*getter)();

        if ( !local_stats )
            return;

        get_stats();
        stats += *local_stats;
    }
}

void ProfilerNodeMap::register_node(const std::string &n, const char* pn, Module* m)
{ setup_node(get_node(n), get_node(pn ? pn : ROOT_NODE), m); }

void ProfilerNodeMap::register_node(const std::string& n, const char* pn, get_profile_stats_fn fn)
{ setup_node(get_node(n), get_node(pn ? pn : ROOT_NODE), fn); }

void ProfilerNodeMap::accumulate_nodes()
{
    static std::mutex stats_mutex;
    std::lock_guard<std::mutex> lock(stats_mutex);

    for ( auto it = nodes.begin(); it != nodes.end(); ++it )
        it->second.accumulate();
}

void ProfilerNodeMap::reset_nodes()
{
    for ( auto it = nodes.begin(); it != nodes.end(); ++it )
        it->second.reset();
}

const ProfilerNode& ProfilerNodeMap::get_root()
{ return get_node(ROOT_NODE); }

ProfilerNode& ProfilerNodeMap::get_node(const std::string& key)
{
    auto node = nodes.emplace(key, key);
    return node.first->second;
}

#ifdef UNIT_TEST

static ProfileStats* s_profiler_stats = nullptr;
static const char* s_profiler_name = nullptr;

static ProfileStats* s_profiler_stats_getter(const char* name)
{
    if ( s_profiler_name && std::string(name) == s_profiler_name )
        return s_profiler_stats;

    return nullptr;
}

static ProfilerNode find_node(const ProfilerNodeMap& tree, const std::string& name)
{
    for ( const auto& it : tree )
        if ( it.first == name )
            return it.second;

    return ProfilerNode("");
}

namespace
{

class SpyModule : public Module
{
public:
    SpyModule(const char* name, ProfileStats* stats, bool multi) :
        Module(name, nullptr), stats(stats), multi(multi) { }

    ProfileStats* get_stats() { return stats; }
    void set_stats(ProfileStats* ps) { stats = ps; }
    bool get_multi() { return multi; }
    void set_multi(bool b) { multi = b; }

    ProfileStats* get_profile() const override
    { return multi ? nullptr : stats; }

    ProfileStats* get_profile(
        unsigned i, const char*& name, const char*&) const override
    {
        if ( !multi )
            return nullptr;

        if ( i == 0 )
        {
            name = "dummy";
            return &dummy_stats;
        }

        else if ( i == 1 )
        {
            name = get_name();
            return stats;
        }

        return nullptr;
    }

private:
    ProfileStats* stats;
    bool multi;

    mutable ProfileStats dummy_stats;
};

} // anonymous namespace

TEST_CASE( "get profile functor for module", "[profiler]" )
{
    ProfileStats the_stats;
    SpyModule m("foo", &the_stats, false);
    GetProfileFromModule functor("foo", &m);

    SECTION( "one" )
    {
        CHECK( functor() == &the_stats );
    }

    SECTION( "many" )
    {
        m.set_multi(true);
        CHECK( functor() == &the_stats );
    }
}

TEST_CASE( "get profile functor for function", "[profiler]" )
{
    ProfileStats the_stats;
    s_profiler_stats = &the_stats;
    s_profiler_name = "foo";

    GetProfileFromFunction functor("foo", s_profiler_stats_getter);
    CHECK( functor() == &the_stats );

    s_profiler_stats = nullptr;
}

TEST_CASE( "profiler node", "[profiler]" )
{
    ProfileStats the_stats;
    SpyModule m("foo", &the_stats, false);

    ProfilerNode node("foo");
    node.set(&m);

    SECTION( "get_stats" )
    {
        auto& result = node.get_stats();
        CHECK( result == ProfileStats() );
    }

    SECTION( "set" )
    {
        the_stats.time = { 5_ticks, 7 };

        SECTION( "module" )
        {
            node.accumulate();
            CHECK( node.get_stats() == the_stats );
        }

        SECTION( "function" )
        {
            ProfilerNode f_node("foo");
            s_profiler_stats = &the_stats;
            s_profiler_name = "foo";
            f_node.set(s_profiler_stats_getter);
            f_node.accumulate();
            CHECK( f_node.get_stats() == the_stats );
            s_profiler_stats = nullptr;
        }
    }

    SECTION( "accumulate" )
    {
        the_stats.time = { 1_ticks, 1 };

        node.accumulate();
        node.accumulate();

        auto& result = node.get_stats();

        CHECK( (result.time.elapsed == 2_ticks) );
        CHECK( (result.time.checks == 2) );
    }

    SECTION( "reset" )
    {
        the_stats.time = { 1_ticks, 1 };

        node.accumulate();

        auto& r1 = node.get_stats();
        CHECK( r1 != ProfileStats() );

        node.reset();
        auto& r2 = node.get_stats();
        CHECK( r2 == ProfileStats() );
    }
}

TEST_CASE( "profiler node map", "[profiler]" )
{
    ProfilerNodeMap tree;

    SECTION( "register" )
    {
        ProfileStats stats;
        SpyModule m("foo", &stats, false);

        SECTION( "register module" )
        {
            tree.register_node("foo", nullptr, &m);
            CHECK( !find_node(tree, "foo").name.empty() );
        }

        SECTION( "register function")
        {
            tree.register_node("foo", nullptr, s_profiler_stats_getter);
            CHECK( !find_node(tree, "foo").name.empty() );
        }

        SECTION( "register child -> parent" )
        {
            tree.register_node("foo", "bar", &m);
            auto node = find_node(tree, "bar");
            CHECK( !node.get_children().empty() );
            CHECK( node.get_children().front()->name == "foo" );
        }

        SECTION( "register child -> null" )
        {
            tree.register_node("foo", nullptr, &m);
            auto root = tree.get_root();
            CHECK( !root.get_children().empty() );
            CHECK( root.get_children().front()->name == "foo" );
        }

        SECTION( "register parent -> parent" )
        {
            tree.register_node("foo", "foo", &m);
            auto node = find_node(tree, "foo");
            CHECK( node.get_children().empty() );
        }
    }

    SECTION( "get root" )
    {
        CHECK( tree.get_root().name == ROOT_NODE );
    }
}

#endif
