//--------------------------------------------------------------------------
// Copyright (C) 2018-2022 Cisco and/or its affiliates. All rights reserved.
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

// ips_context_chain.cc author Carter Waxman <cwamxan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/ips_context_chain.h"

#include "detection/ips_context.h"

using namespace snort;

void IpsContextChain::pop()
{
    assert(_front);

    IpsContext* new_front = _front->next();
    _front->unlink();
    _front = new_front;
    if ( !_front )
        _back = nullptr;
}

void IpsContextChain::push_back(IpsContext* new_back)
{
    if ( _back )
    {
        _back->link(new_back);
        _back = new_back;
    }
    else
    {
        assert(!_front);
        _front = _back = new_back;
    }
}

#ifdef UNIT_TEST
#include "catch/snort_catch.h"

TEST_CASE("IpsContextChain push_back", "[IpsContextChain]")
{
    IpsContextChain chain;
    IpsContext a, b, c;

    CHECK(chain.front() == nullptr);
    CHECK(chain.back() == nullptr);

    chain.push_back(&a);
    CHECK(chain.front() == &a);
    CHECK(chain.back() == &a);

    chain.push_back(&b);
    CHECK(chain.front() == &a);
    CHECK(chain.back() == &b);

    chain.push_back(&c);
    CHECK(chain.front() == &a);
    CHECK(chain.back() == &c);

    CHECK(a.next() == &b);
    CHECK(b.next() == &c);
    CHECK(c.next() == nullptr);
}

TEST_CASE("IpsContextChain pop", "[IpsContextChain]")
{
    IpsContextChain chain;
    IpsContext a, b, c;

    chain.push_back(&a);
    chain.push_back(&b);
    chain.push_back(&c);

    chain.pop();
    CHECK(chain.front() == &b);
    CHECK(chain.back() == &c);

    chain.pop();
    CHECK(chain.front() == &c);
    CHECK(chain.back() == &c);

    chain.pop();
    CHECK(chain.front() == nullptr);
    CHECK(chain.back() == nullptr);
}

TEST_CASE("IpsContextChain abort", "[IpsContextChain]")
{
    IpsContextChain chain;
    IpsContext a, b;

    chain.push_back(&a);
    chain.push_back(&b);
    chain.abort();

    CHECK(!chain.front());
    CHECK(!chain.back());
}

#endif

