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

// ips_context.cc author Russ Combs <rucombs@cisco.com>

#include "ips_context.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include "events/event_queue.h"
#include "events/sfeventq.h"
#include "main/snort_config.h"

#include "fp_detect.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

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

    const EventQueueConfig* qc = snort_conf->event_queue_config;
    equeue = sfeventq_new(qc->max_events, qc->log_events, sizeof(EventNode));

    packet->context = this;
    fp_set_context(*this);

    offload = nullptr;
    onload = false;
    active_rules = CONTENT;
}

IpsContext::~IpsContext()
{
    for ( auto* p : data )
        if ( p )
            delete p;

    assert(!offload);

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

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
class ContextData : public IpsContextData
{
public:
    ContextData(int)
    { ++count; }

    ~ContextData()
    { --count; }

    static int count;
};

int ContextData::count = 0;

TEST_CASE("IpsContextData id", "[IpsContextData]")
{
    ips_id = 0;
    CHECK(IpsContextData::get_max_id() == 0);

    unsigned id1 = IpsContextData::get_ips_id();
    unsigned id2 = IpsContextData::get_ips_id();
    CHECK(id1 != id2);
    
    CHECK(IpsContextData::get_max_id() == id2);
}

TEST_CASE("IpsContext basic", "[IpsContext]")
{
    ips_id = 0;

    SECTION("one context")
    {
        auto id = IpsContextData::get_ips_id();
        auto* d1 = new ContextData(10);
        auto ctxt = IpsContext(id+1);
        ctxt.set_context_data(id, d1);
        CHECK(ctxt.get_context_data(id) == d1);
    }
    CHECK(ContextData::count == 0);
}

#endif

