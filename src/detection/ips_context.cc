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

// ips_context.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_context.h"

#include <cassert>
#include "events/event_queue.h"
#include "events/sfeventq.h"
#include "main/snort_config.h"

#include "fp_detect.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

//--------------------------------------------------------------------------
// context data
//--------------------------------------------------------------------------

// ips_id is not a member of context data so that
// tests (and only tests) can reset the id
static unsigned ips_id = 0;

unsigned IpsContextData::get_ips_id()
{ return ++ips_id; }

unsigned IpsContextData::get_max_id()
{ return ips_id; }

//--------------------------------------------------------------------------
// context methods
//--------------------------------------------------------------------------

IpsContext::IpsContext(unsigned size) :
    data(size ? size : IpsContextData::get_max_id() + 1, nullptr)
{
    packet = new Packet(false);
    encode_packet = nullptr;

    pkth = new DAQ_PktHdr_t;
    buf = new uint8_t[buf_size];

    const EventQueueConfig* qc = SnortConfig::get_conf()->event_queue_config;
    equeue = sfeventq_new(qc->max_events, qc->log_events, sizeof(EventNode));

    packet->context = this;
    fp_set_context(*this);

    active_rules = CONTENT;
    check_tags = false;
}

IpsContext::~IpsContext()
{
    for ( auto* p : data )
    {
        if ( p )
        {
            p->clear();
            delete p;
        }
    }

    sfeventq_free(equeue);
    fp_clear_context(*this);

    delete[] buf;
    delete pkth;
    delete packet;
}

void IpsContext::set_context_data(unsigned id, IpsContextData* cd)
{
    assert(id < data.size());
    data[id] = cd;
}

IpsContextData* IpsContext::get_context_data(unsigned id) const
{
    assert(id < data.size());
    return data[id];
}

void IpsContext::clear_context_data()
{
    for ( auto* p : data )
    {
        if ( p )
            p->clear();
    }
}

void IpsContext::snapshot_flow(Flow* f)
{
    flow.session_flags = f->ssn_state.session_flags;
    flow.proto_id = f->ssn_state.snort_protocol_id;
}

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
class TestData : public IpsContextData
{
public:
    TestData()
    { ++count; }

    ~TestData() override
    { --count; }

    static int count;
};

int TestData::count = 0;

TEST_CASE("IpsContextData id", "[IpsContextData]")
{
    ips_id = 0;
    CHECK(IpsContextData::get_max_id() == 0);

    auto id1 = IpsContextData::get_ips_id();
    auto id2 = IpsContextData::get_ips_id();
    CHECK(id1 != id2);

    CHECK(IpsContextData::get_max_id() == id2);
}

TEST_CASE("IpsContext basic", "[IpsContext]")
{
    ips_id = 0;
    IpsContext ctx(4);
    int num_data = 0;

    CHECK(ctx.packet != nullptr);
    CHECK(ctx.pkth != nullptr);
    CHECK(ctx.buf != nullptr);
    CHECK(ctx.equeue != nullptr);

    SECTION("one data")
    {
        auto id1 = IpsContextData::get_ips_id();
        auto* d1 = new TestData;
        ctx.set_context_data(id1, d1);

        CHECK(d1 == ctx.get_context_data(id1));
        num_data = 1;
    }
    SECTION("two data")
    {
        auto id1 = IpsContextData::get_ips_id();
        auto* d1 = new TestData;
        ctx.set_context_data(id1, d1);

        auto id2 = IpsContextData::get_ips_id();
        auto* d2 = new TestData;
        ctx.set_context_data(id2, d2);

        CHECK(d1 == ctx.get_context_data(id1));
        CHECK(d2 == ctx.get_context_data(id2));
        num_data = 2;
    }
    CHECK(TestData::count == num_data);
}
#endif

