//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// cursor.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "cursor.h"

#include "detection/detection_buf.h"
#include "detection/detection_engine.h"
#include "protocols/packet.h"
#include "detection/ips_context.h"

using namespace snort;

unsigned CursorData::cursor_data_id = 0;

Cursor::Cursor(Packet* p)
{
    reset(p);
}

Cursor::Cursor(const Cursor& rhs)
{
    name = rhs.name;
    buf = rhs.buf;
    file_pos = rhs.file_pos;
    buf_size = rhs.buf_size;
    current_pos = rhs.current_pos;
    extensible = rhs.extensible;
    buf_id = rhs.buf_id;
    is_accumulated = rhs.is_accumulated;
    re_eval = rhs.re_eval;

    if (re_eval)
        delta = rhs.delta;

    if (rhs.data)
    {
        data = new CursorDataVec;
        data->reserve(rhs.data->size());

        for (CursorData*& cd : *rhs.data)
            data->push_back(cd->clone());
    }
}

CursorData* Cursor::get_data(unsigned id) const
{
    if (data)
    {
        for (CursorData*& cd : *data)
        {
            if (cd->get_id() == id)
                return cd;
        }
    }

    return nullptr;
}

void Cursor::set_data(CursorData* cd)
{
    assert(cd);

    if (data)
    {
        unsigned i = cd->get_id();
        for (CursorData*& old : *data)
        {
            if (old->get_id() == i)
            {
                delete old;
                old = cd;
                return;
            }
        }
    }
    else
    {
        data = new CursorDataVec;
    }

    data->push_back(cd);
}

void Cursor::reset(Packet* p)
{
    if (p->flow and p->flow->gadget)
    {
        const DataPointer& alt_buf = DetectionEngine::get_alt_buffer(p);
        if (alt_buf.len)
        {
            set("alt_data", alt_buf.data, alt_buf.len);
            return;
        }
    }

    set("pkt_data", p->packet_flags & (PKT_FROM_SERVER | PKT_FROM_CLIENT),
        p->data, p->get_detect_limit(), true);
}

//-------------------------------------------------------------------------
// UNIT TESTS
//-------------------------------------------------------------------------
#ifdef UNIT_TEST

#include "catch/snort_catch.h"

TEST_CASE("Boundaries", "[cursor]")
{
    const uint8_t buf_1[] = "the first";
    const uint8_t buf_2[] = "the second";
    const uint8_t buf_3[] = "the third";

    Cursor cursor;

    SECTION("Stateless buffer")
    {
        const int offset = 11;
        bool r1, r2;

        cursor.set("1", buf_1, sizeof(buf_1), false);
        r1 = cursor.set_pos(offset);
        r2 = cursor.awaiting_data();

        CHECK(!r1);
        CHECK(!r2);
    }

    SECTION("Ends within 1st PDU")
    {
        const int offset = 8;
        bool r1, r2;

        cursor.set("1", buf_1, sizeof(buf_1), true);
        r1 = cursor.set_pos(offset);
        r2 = cursor.awaiting_data();

        CHECK(r1);
        CHECK(!r2);
    }

    SECTION("At the very end of 1st PDU")
    {
        const int offset = sizeof(buf_1);
        bool r1, r2;

        cursor.set("1", buf_1, sizeof(buf_1), true);
        r1 = cursor.set_pos(offset);
        r2 = cursor.awaiting_data();

        CHECK(r1);
        CHECK(r2);

        auto rem = cursor.get_next_pos();
        CHECK(rem == 0);

        cursor.set("2", buf_2, sizeof(buf_2), true);
        r1 = cursor.set_pos(rem);
        r2 = cursor.awaiting_data();

        CHECK(r1);
        CHECK(!r2);
    }

    SECTION("Ends after 1st PDU")
    {
        const int offset = 11;
        bool r1, r2;

        cursor.set("1", buf_1, sizeof(buf_1), true);
        r1 = cursor.set_pos(offset);
        r2 = cursor.awaiting_data();

        CHECK(!r1);
        CHECK(r2);

        auto rem = cursor.get_next_pos();
        CHECK(rem == offset - sizeof(buf_1));

        cursor.set("2", buf_2, sizeof(buf_2), true);
        r1 = cursor.set_pos(rem);
        r2 = cursor.awaiting_data();

        CHECK(r1);
        CHECK(!r2);
    }

    SECTION("Ends after 2nd PDU")
    {
        const int offset = 25;
        bool r1, r2;

        cursor.set("1", buf_1, sizeof(buf_1), true);
        r1 = cursor.set_pos(offset);
        r2 = cursor.awaiting_data();

        CHECK(!r1);
        CHECK(r2);

        auto rem1 = cursor.get_next_pos();
        CHECK(rem1 == offset - sizeof(buf_1));

        cursor.set("2", buf_2, sizeof(buf_2), true);
        r1 = cursor.set_pos(rem1);
        r2 = cursor.awaiting_data();

        CHECK(!r1);
        CHECK(r2);

        auto rem2 = cursor.get_next_pos();
        CHECK(rem2 == rem1 - sizeof(buf_2));

        cursor.set("3", buf_3, sizeof(buf_3), true);
        r1 = cursor.set_pos(rem2);
        r2 = cursor.awaiting_data();

        CHECK(r1);
        CHECK(!r2);
    }

    SECTION("Delta")
    {
        SECTION("Set delta in bounds")
        {
            bool r1 = false;
            unsigned d1 = sizeof(buf_1) - 1;

            cursor.set("1", buf_1, sizeof(buf_1), true);
            r1 = cursor.set_delta(d1);

            CHECK(r1);
            CHECK(cursor.get_delta() == d1);
        }
        SECTION("Set delta as buffer size")
        {
            bool r1 = false;
            unsigned d1 = sizeof(buf_1);

            cursor.set("1", buf_1, sizeof(buf_1), true);
            r1 = cursor.set_delta(d1);

            CHECK(r1);
            CHECK(cursor.get_delta() == d1);
        }
        SECTION("Set delta bigger than buffer size")
        {
            bool r1 = false;
            unsigned d1 = sizeof(buf_1) + 1;

            cursor.set("1", buf_1, sizeof(buf_1), true);
            r1 = cursor.set_delta(d1);

            CHECK(!r1);
            CHECK(cursor.get_delta() == d1);
        }
        SECTION("Set delta as negative")
        {
            bool r1 = false;
            unsigned d1 = -1;

            cursor.set("1", buf_1, sizeof(buf_1), true);
            r1 = cursor.set_delta(d1);

            CHECK(!r1);
            CHECK(cursor.get_delta() == d1);
        }
        SECTION("Copy constructor")
        {
            SECTION("re_eval false")
            {
                cursor.set("1", buf_1, sizeof(buf_1), true);
                cursor.set_delta(sizeof(buf_1) - 1);
                cursor.set_re_eval(false);
                unsigned r = Cursor(cursor).get_delta();
                CHECK(r != cursor.get_delta());
                CHECK(r == 0);
            }
            SECTION("re_eval true")
            {
                cursor.set("1", buf_1, sizeof(buf_1), true);
                unsigned d1 = sizeof(buf_1) - 1;
                cursor.set_delta(d1);
                cursor.set_re_eval(true);

                Cursor c = Cursor(cursor);
                CHECK(c.get_delta() == cursor.get_delta());
                CHECK(c.get_delta() == d1);
                bool r1 = c.is_re_eval();
                CHECK(r1);
            }
        }
    }
}

#endif
