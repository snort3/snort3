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

// ips_context.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_context.h"

#include <cassert>

#include "detection/detection_engine.h"
#include "detection/fp_detect.h"
#include "detection/ips_context_data.h"
#include "events/event_queue.h"
#include "events/sfeventq.h"
#include "main/snort_config.h"
#include "stream/stream.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

//--------------------------------------------------------------------------
// context methods
//--------------------------------------------------------------------------

IpsContext::IpsContext(unsigned size) :
    data(size ? size : max_ips_id, nullptr)
{
    depends_on = nullptr;
    next_to_process = nullptr;

    state = IDLE;

    packet = new Packet(false);
    encode_packet = nullptr;

    pkth = new DAQ_PktHdr_t;
    buf = new uint8_t[buf_size];

    conf = SnortConfig::get_conf();
    const EventQueueConfig* qc = conf->event_queue_config;
    equeue = sfeventq_new(qc->max_events, qc->log_events, sizeof(EventNode));

    packet->context = this;
    fp_set_context(*this);

    active_rules = CONTENT;
    check_tags = false;
    clear_inspectors = false;
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
    ids_in_use.clear();

    sfeventq_free(equeue);
    fp_clear_context(*this);

    delete[] buf;
    delete pkth;
    delete packet;
}

void IpsContext::setup()
{
    conf = SnortConfig::get_conf();
    remove_gadget = false;
}

void IpsContext::clear()
{
    for ( auto id : ids_in_use )
    {
        auto* p = data[id];
        if ( p )
            p->clear();
    }
    if ( remove_gadget and packet->flow and !packet->is_rebuilt() )
    {
       Stream::disable_reassembly(packet->flow);

       if ( packet->flow->gadget )
           packet->flow->clear_gadget();
    }
    remove_gadget = false;
    assert(post_callbacks.empty());
}

void IpsContext::set_context_data(unsigned id, IpsContextData* cd)
{
    assert(id < data.size());
    data[id] = cd;
    ids_in_use.push_back(id);
}

IpsContextData* IpsContext::get_context_data(unsigned id) const
{
    assert(id < data.size());
    return data[id];
}

void IpsContext::snapshot_flow(Flow* f)
{
    flow.session_flags = f->ssn_state.session_flags;
    flow.proto_id = f->ssn_state.snort_protocol_id;
}

void IpsContext::post_detection()
{
    for ( auto callback : post_callbacks )
        callback(this);

    post_callbacks.clear();
    alt_data.len = 0;
}

void IpsContext::disable_detection()
{
    if ( active_rules == IpsContext::NONE )
        return;

    IpsPolicy* empty_policy = get_empty_ips_policy(conf);
    set_ips_policy(empty_policy);

    if ( Flow* f = packet->flow )
    {
        f->ips_policy_id = empty_policy->policy_id;
        f->set_to_client_detection(false);
        f->set_to_server_detection(false);
    }
    active_rules = IpsContext::NONE;
}

void IpsContext::disable_inspection()
{ remove_gadget = true; }

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

TEST_CASE("IpsContext basic", "[IpsContext]")
{
    IpsContextData::clear_ips_id();
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

static IpsContext* post_val;
static void test_post(IpsContext* c)
{ post_val = c; }

TEST_CASE("IpsContext post detection", "[IpsContext]")
{
    post_val = nullptr;
    IpsContext c;
    c.register_post_callback(test_post);

    CHECK( post_val == nullptr);
    c.post_detection();
    CHECK( post_val == &c);

    // callbacks should be cleared
    post_val = nullptr;
    c.post_detection();
    CHECK( post_val == nullptr );
}

TEST_CASE("IpsContext Link", "[IpsContext]")
{
    IpsContext c0, c1, c2;

    CHECK(c0.dependencies() == nullptr);
    CHECK(c0.next() == nullptr);

    c0.link(&c1);
    CHECK(c0.dependencies() == nullptr);
    CHECK(c0.next() == &c1);
    CHECK(c1.dependencies() == &c0);
    CHECK(c1.next() == nullptr);

    c1.link(&c2);
    CHECK(c0.dependencies() == nullptr);
    CHECK(c0.next() == &c1);
    CHECK(c1.dependencies() == &c0);
    CHECK(c1.next() == &c2);
    CHECK(c2.dependencies() == &c1);
    CHECK(c2.next() == nullptr);
}

TEST_CASE("IpsContext Unlink", "[IpsContext]")
{
    IpsContext c0, c1, c2;
    c0.link(&c1);
    c1.link(&c2);

    c0.unlink();
    CHECK(c0.dependencies() == nullptr);
    CHECK(c0.next() == nullptr);
    CHECK(c1.dependencies() == nullptr);
    CHECK(c1.next() == &c2);
    CHECK(c2.dependencies() == &c1);
    CHECK(c2.next() == nullptr);

    c1.unlink();
    CHECK(c1.dependencies() == nullptr);
    CHECK(c1.next() == nullptr);
    CHECK(c2.dependencies() == nullptr);
    CHECK(c2.next() == nullptr);

    c2.unlink();
    CHECK(c2.dependencies() == nullptr);
    CHECK(c2.next() == nullptr);
}

TEST_CASE("IpsContext Abort, [IpsContext]")
{
    IpsContext c0, c1, c2, c3;
    Flow flow;

    c0.link(&c1);
    c1.link(&c2);
    c2.link(&c3);

    // mid list
    // c0 <- c1 <- c2 <- c3
    // c0 <- c2 <- c3
    c1.abort();
    CHECK(c0.dependencies() == nullptr);
    CHECK(c0.next() == &c2);
    CHECK(c1.dependencies() == nullptr);
    CHECK(c1.next() == nullptr);
    CHECK(c2.dependencies() == &c0);
    CHECK(c2.next() == &c3);
    CHECK(c3.dependencies() == &c2);
    CHECK(c3.next() == nullptr);

    // front of list
    // c0 <- c2 <- c3
    // c2 <- c3
    c0.abort();
    CHECK(c0.dependencies() == nullptr);
    CHECK(c0.next() == nullptr);
    CHECK(c2.dependencies() == nullptr);
    CHECK(c2.next() == &c3);
    CHECK(c3.dependencies() == &c2);
    CHECK(c3.next() == nullptr);

    // back of list
    // c2 <- c3
    // c2
    c3.abort();
    CHECK(c2.dependencies() == nullptr);
    CHECK(c2.next() == nullptr);
    CHECK(c3.dependencies() == nullptr);
    CHECK(c3.next() == nullptr);

    // only
    c2.abort();
    CHECK(c2.dependencies() == nullptr);
    CHECK(c2.next() == nullptr);
}
#endif

