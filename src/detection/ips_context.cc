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

#include <assert.h>

#define UNIT_TEST

#ifdef UNIT_TEST
#include "catch.hpp"
#endif

unsigned IpsContextData::ips_id = 0;

//--------------------------------------------------------------------------
// context methods
//--------------------------------------------------------------------------

IpsContext::IpsContext(unsigned size) : data(size, nullptr)
{ }

IpsContext::~IpsContext()
{
    for ( auto* p : data )
        if ( p )
            delete p;
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
    ContextData(int i)
    { ++count; }

    ~ContextData()
    { --count; }

    static int count;
};

int ContextData::count = 0;

TEST_CASE("ips_ids", "[IpsContextData]")
{
    CHECK(IpsContextData::get_max_id() == 0);

    unsigned id1 = IpsContextData::get_ips_id();
    unsigned id2 = IpsContextData::get_ips_id();
    CHECK(id1 != id2);
    
    CHECK(IpsContextData::get_max_id() == id2);
}

TEST_CASE("basic", "[IpsContext]")
{
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

