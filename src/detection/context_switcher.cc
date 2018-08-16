//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "context_switcher.h"

#include <cassert>

#include "main/modules.h"
#include "main/snort_debug.h"
#include "utils/stats.h"

#include "detect_trace.h"
#include "ips_context.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

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
    assert(!idle.empty());
    trace_logf(detection, TRACE_DETECTION_ENGINE, "(wire) %" PRIu64 " cs::start %u (i=%zu, b=%zu)\n",
        get_packet_number(), idle.back()->get_slot(), idle.size(), busy.size());
    busy.push_back(idle.back());
    idle.pop_back();
}

void ContextSwitcher::stop()
{
    assert(busy.size() == 1);
    trace_logf(detection, TRACE_DETECTION_ENGINE, "(wire) %" PRIu64 " cs::stop %u (i=%zu, b=%zu)\n",
        get_packet_number(), busy.back()->get_slot(), idle.size(), busy.size());
    idle.push_back(busy.back());
    busy.pop_back();
}

void ContextSwitcher::abort()
{
    trace_logf(detection, TRACE_DETECTION_ENGINE, "(wire) %" PRIu64 " cs::abort (i=%zu, b=%zu)\n",
        get_packet_number(), idle.size(), busy.size());
    for ( unsigned i = 0; i < hold.capacity(); ++i )
    {
        if ( hold[i] )
        {
            trace_logf(detection, TRACE_DETECTION_ENGINE, "%" PRIu64 " cs::abort hold",
                hold[i]->packet_number);

            idle.push_back(hold[i]);
            hold[i] = nullptr;
        }
    }
    while ( !busy.empty() )
    {
        trace_logf(detection, TRACE_DETECTION_ENGINE, "%" PRIu64 " cs::abort busy",
            busy[0]->packet_number);

        idle.push_back(busy.back());
        busy.pop_back();
    }
}

IpsContext* ContextSwitcher::interrupt()
{
    assert(!idle.empty());
    trace_logf(detection, TRACE_DETECTION_ENGINE, "%" PRIu64 " cs::interrupt %u (i=%zu, b=%zu)\n",
        idle.back()->packet_number, idle.back()->get_slot(), idle.size(), busy.size());
    busy.push_back(idle.back());
    idle.pop_back();
    return busy.back();
}

IpsContext* ContextSwitcher::complete()
{
    assert(!busy.empty());
    IpsContext* c = busy.back();

    trace_logf(detection, TRACE_DETECTION_ENGINE, "%" PRIu64 " cs::complete %u (i=%zu, b=%zu)\n",
        c->packet_number, busy.back()->get_slot(), idle.size(), busy.size());

    c->clear_context_data();
    idle.push_back(c);
    busy.pop_back();
    return busy.empty() ? nullptr : busy.back();
}

unsigned ContextSwitcher::suspend()
{
    assert(!busy.empty());
    IpsContext* c = busy.back();

    trace_logf(detection, TRACE_DETECTION_ENGINE, "%" PRIu64 " cs::suspend %u (i=%zu, b=%zu)\n",
        c->packet_number, busy.back()->get_slot(), idle.size(), busy.size());

    busy.pop_back();
    unsigned slot = c->get_slot();
    assert(!hold[slot]);
    hold[slot] = c;
    return slot;
}

void ContextSwitcher::resume(unsigned slot)
{
    assert(slot <= hold.capacity());
    trace_logf(detection, TRACE_DETECTION_ENGINE, "%" PRIu64 " cs::resume %u (i=%zu, b=%zu)\n",
        hold[slot]->packet_number, slot, idle.size(), busy.size());
    busy.push_back(hold[slot]);
    hold[slot] = nullptr;
}

IpsContext* ContextSwitcher::get_context() const
{
    assert(!busy.empty());
    return busy.back();
}

IpsContext* ContextSwitcher::get_context(unsigned slot) const
{
    assert(slot <= hold.capacity());
    IpsContext* c = hold[slot];
    assert(c);
    return c;
}

IpsContext* ContextSwitcher::get_next() const
{
    assert(!idle.empty());
    return idle.back();
}

IpsContextData* ContextSwitcher::get_context_data(unsigned id) const
{
    return get_context()->get_context_data(id);
}

void ContextSwitcher::set_context_data(unsigned id, IpsContextData* cd) const
{
    get_context()->set_context_data(id, cd);
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

bool ContextSwitcher::on_hold(Flow* f)
{
    for ( unsigned i = 0; i < hold.capacity(); ++i )
    {
        IpsContext* c = hold[i];
        if ( c and c->packet and c->packet->flow == f )
            return true;
    }
    return false;
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
        mgr.interrupt();
        CHECK(mgr.idle_count() == max-2);
        CHECK((mgr.busy_count() == 2));

        unsigned u = mgr.suspend();
        CHECK(mgr.idle_count() == max-2);
        CHECK(mgr.busy_count() == 1);
        CHECK(mgr.hold_count() == 1);

        mgr.resume(u);
        CHECK(mgr.idle_count() == max-2);
        CHECK((mgr.busy_count() == 2));
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

        mgr.suspend();
        CHECK((mgr.busy_count() == 2));
        CHECK(mgr.hold_count() == 1);

        mgr.abort();
        CHECK(mgr.idle_count() == max);
    }
}
#endif

