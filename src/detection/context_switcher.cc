//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// context_switcher.cc author Russ Combs <rucombs@cisco.com>

#include "context_switcher.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "ips_context.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

//--------------------------------------------------------------------------
// context switcher methods
//--------------------------------------------------------------------------

ContextSwitcher::ContextSwitcher(unsigned max) :
    hold(max+1, nullptr)  // use 1-based index / skip hold[0]
{
}

ContextSwitcher::~ContextSwitcher()
{
    abort();

    for ( auto* p : idle )
        delete p;
}

void ContextSwitcher::push(IpsContext* c)
{
    c->set_slot(idle.size() + 1);
    idle.push_back(c);
}

IpsContext* ContextSwitcher::pop()
{
    if ( idle.empty() )
        return nullptr;

    IpsContext* c = idle.back();
    idle.pop_back();
    return c;
}

void ContextSwitcher::start()
{
    assert(busy.empty());
    assert(idle.size() > 0);
    busy.push_back(idle.back());
    idle.pop_back();
}

void ContextSwitcher::stop()
{
    assert(busy.size() == 1);
    idle.push_back(busy.back());
    busy.pop_back();
}

void ContextSwitcher::abort()
{
    for ( unsigned i = 0; i < hold.capacity(); ++i )
    {
        if ( hold[i] )
        {
            idle.push_back(hold[i]);
            hold[i] = nullptr;
        }
    }
    while ( !busy.empty() )
    {
        idle.push_back(busy.back());
        busy.pop_back();
    }
}

IpsContext* ContextSwitcher::interrupt()
{
    assert(!idle.empty());
    busy.push_back(idle.back());
    idle.pop_back();
    return busy.back();
}

IpsContext* ContextSwitcher::complete()
{
    assert(!busy.empty());
    idle.push_back(busy.back());
    busy.pop_back();
    return busy.empty() ? nullptr : busy.back();
}

unsigned ContextSwitcher::suspend()
{
    assert(!busy.empty());
    IpsContext* c = busy.back();
    busy.pop_back();
    unsigned slot = c->get_slot();
    assert(!hold[slot]);
    hold[slot] = c;
    return slot;
}

void ContextSwitcher::resume(unsigned slot)
{
    assert(slot <= hold.capacity());
    busy.push_back(hold[slot]);
    hold[slot] = nullptr;
}

void ContextSwitcher::set_context_data(unsigned id, IpsContextData* cd) const
{
    assert(!busy.empty());
    busy.back()->set_context_data(id, cd);
}

IpsContextData* ContextSwitcher::get_context_data(unsigned id) const
{
    assert(!busy.empty());
    return busy.back()->get_context_data(id);
}

unsigned ContextSwitcher::idle_count() const
{ return idle.size(); }

unsigned ContextSwitcher::busy_count() const
{ return busy.size(); }

unsigned ContextSwitcher::hold_count() const
{
    unsigned c = 0;

    for ( auto* p : hold )
        if ( p ) c++;

    return c;
}

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
class ContextData : public IpsContextData
{
public:
    ContextData(int) { }
};

TEST_CASE("ContextSwitcher normal", "[ContextSwitcher]")
{
    const unsigned max = 3;
    auto mgr = ContextSwitcher(max);
    auto id = IpsContextData::get_ips_id();
    CHECK(!mgr.pop());

    for ( unsigned i = 0; i < max; ++i )
        mgr.push(new IpsContext(id+1));

    SECTION("workflow")
    {
        CHECK(mgr.idle_count() == max);

        mgr.start();
        CHECK(mgr.idle_count() == max-1);
        CHECK(mgr.busy_count() == 1);

        IpsContextData* a = new ContextData(id);
        mgr.set_context_data(1, a);
        IpsContext* p = mgr.interrupt();
        CHECK(mgr.idle_count() == max-2);
        CHECK(mgr.busy_count() == 2);

        unsigned u = mgr.suspend();
        CHECK(mgr.idle_count() == max-2);
        CHECK(mgr.busy_count() == 1);
        CHECK(mgr.hold_count() == 1);

        mgr.resume(u);
        CHECK(mgr.idle_count() == max-2);
        CHECK(mgr.busy_count() == 2);
        CHECK(mgr.hold_count() == 0);

        mgr.complete();
        CHECK(mgr.idle_count() == max-1);
        CHECK(mgr.busy_count() == 1);

        IpsContextData* b = mgr.get_context_data(1);
        CHECK(a == b);

        mgr.stop();
        CHECK(mgr.idle_count() == max);
    }
    for ( unsigned i = 0; i < max; ++i )
    {
        IpsContext* p = mgr.pop();
        CHECK(p);
        delete p;
    }
    CHECK(!mgr.pop());
}

TEST_CASE("ContextSwitcher abort", "[ContextSwitcher]")
{
    const unsigned max = 3;
    auto mgr = ContextSwitcher(max);
    auto id = IpsContextData::get_ips_id();
    CHECK(!mgr.pop());

    for ( unsigned i = 0; i < max; ++i )
        mgr.push(new IpsContext(id+1));

    SECTION("cleanup")
    {
        mgr.start();
        IpsContextData* a = new ContextData(id);
        mgr.set_context_data(1, a);
        mgr.interrupt();
        mgr.interrupt();
        CHECK(mgr.idle_count() == max-3);

        unsigned u = mgr.suspend();
        CHECK(mgr.busy_count() == 2);
        CHECK(mgr.hold_count() == 1);

        mgr.abort();
        CHECK(mgr.idle_count() == max);
    }
}
#endif

