//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// ring2_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/catch.hpp"

#include <vector>

#include "helpers/ring2.h"

using namespace std;

using Data = string;

template <class T, class... Args>
static void write(T& writer, Args&& ... records)
{
    const vector<Data> items{std::forward<Args>(records)...};

    for (const auto& item : items)
    {
        bool res = writer.write(item.data(), item.size());
        CHECK(true == res);
    }
}

template <class T, class... Args>
static void read(T& reader, Args&& ... args)
{
    const vector<Data> expected_items{std::forward<Args>(args)...};

    for (const auto& expected : expected_items)
    {
        size_t data_len = 0;
        const char* data = (const char*)reader.read(data_len);
        Data actual(data, data_len);
        CHECK(expected == actual);
    }
}

TEST_CASE("Basic", "[Ring2]")
{
    Ring2 buffer(1024);

    SECTION("no data")
    {
        REQUIRE(1024 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        auto reader = buffer.reader();

        write(writer);
        read(reader);
        read(reader, "");
        read(reader, "", "", "");

        CHECK(1024 == buffer.capacity());
        CHECK(true == buffer.empty());

        writer.push();
        reader.pop();

        CHECK(1024 == buffer.capacity());
        CHECK(true == buffer.empty());
    }

    SECTION("1 element")
    {
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();

        write(writer, "hello");
        CHECK(true == buffer.empty());

        writer.push();
        CHECK(false == buffer.empty());

        auto reader = buffer.reader();

        read(reader, "hello");
        CHECK(false == buffer.empty());

        reader.pop();
        CHECK(true == buffer.empty());
    }
}

TEST_CASE("Visibility", "[Ring2]")
{
    Ring2 buffer(1024);

    SECTION("caching")
    {
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        auto reader = buffer.reader();

        write(writer, "0", "1", "2", "3", "4");
        reader.retry();
        read(reader, "");

        write(writer, "5", "6", "7", "8", "9");
        reader.retry();
        read(reader, "");

        write(writer, "a", "b", "c", "d", "e");
        reader.retry();
        read(reader, "");

        write(writer, "f");
        reader.retry();
        read(reader, "");

        writer.push();
        reader.retry();
        read(reader, "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f");
    }

    SECTION("reader")
    {
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        auto reader = buffer.reader();

        write(writer, "hello", " ", "world", "!");
        writer.push();

        read(reader, "");
        CHECK(false == buffer.empty());

        reader.retry();
        read(reader, "hello", " ", "world", "!");

        CHECK(false == buffer.empty());
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("reader incremental")
    {
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        auto reader = buffer.reader();

        read(reader, "");
        reader.retry();
        read(reader, "");

        write(writer, "foo");
        writer.push();

        read(reader, "");
        reader.retry();
        read(reader, "foo", "");

        write(writer, "bar");
        writer.push();

        read(reader, "");
        reader.retry();
        read(reader, "foo", "bar", "");

        write(writer, "baz");
        writer.push();

        read(reader, "");
        reader.retry();
        read(reader, "foo", "bar", "baz", "");
        reader.pop();

        CHECK(true == buffer.empty());
    }

    SECTION("reader incremental with pop")
    {
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        auto reader = buffer.reader();

        read(reader, "");
        reader.retry();
        read(reader, "");

        write(writer, "foo");
        writer.push();

        read(reader, "");
        reader.retry();
        read(reader, "foo", "");
        reader.pop();

        write(writer, "bar");
        writer.push();

        read(reader, "");
        reader.retry();
        read(reader, "bar", "");
        reader.pop();

        write(writer, "baz");
        writer.push();

        read(reader, "");
        reader.retry();
        read(reader, "baz", "");
        reader.pop();

        CHECK(true == buffer.empty());
    }

    SECTION("writer incremental")
    {
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "foo");
        writer.push();

        auto r1 = buffer.reader();
        read(r1, "foo", "");

        writer.retry();
        write(writer, "bar");

        auto r2 = buffer.reader();
        read(r2, "foo", "");

        writer.retry();
        write(writer, "baz");

        auto r3 = buffer.reader();
        read(r3, "foo", "");

        writer.retry();
        write(writer, "foo");
        writer.push();

        auto r4 = buffer.reader();
        read(r4, "foo", "foo", "");
        r4.pop();

        CHECK(true == buffer.empty());
    }

    SECTION("writer incremental with push")
    {
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();

        writer.retry();
        write(writer, "foo");
        writer.push();

        auto r1 = buffer.reader();
        read(r1, "foo", "");

        writer.retry();
        write(writer, "bar");
        writer.push();

        auto r2 = buffer.reader();
        read(r2, "foo", "bar", "");

        writer.retry();
        write(writer, "baz");
        writer.push();

        auto r3 = buffer.reader();
        read(r3, "foo", "bar", "baz", "");
        r3.pop();

        CHECK(true == buffer.empty());
    }

    SECTION("clear")
    {
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        auto reader = buffer.reader();

        write(writer, "Alpha", "Bravo", "Charlie", "Delta", "Echo");
        writer.push();

        reader.retry();
        read(reader, "Alpha", "Bravo", "Charlie", "Delta", "Echo");
        CHECK(false == buffer.empty());

        reader.retry();
        read(reader, "Alpha", "Bravo", "Charlie", "Delta", "Echo");
        CHECK(false == buffer.empty());

        reader.retry();
        read(reader, "Alpha", "Bravo", "Charlie", "Delta", "Echo");
        CHECK(false == buffer.empty());

        reader.pop();
        CHECK(true == buffer.empty());

        writer.retry();
        write(writer, "Foxtrot", "Golf", "Hotel", "India", "Juliette");
        writer.push();

        CHECK(false == buffer.empty());
        buffer.clear();
        CHECK(true == buffer.empty());

        reader.retry();
        read(reader, "");
    }
}

TEST_CASE("Wrapping", "[Ring2]")
{
    Ring2 buffer(21);

    SECTION("[LEN][DATA]#(no room)")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding");

        CHECK(true == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "padding", "12345");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("[LEN][DATA#](no room)")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding");

        CHECK(false == writer.write("123456", 6));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "padding");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("[LEN][DATA#](no room)")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding ");

        CHECK(false == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "padding ");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("[LEN][DA#TA](no room)")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding   ");

        CHECK(false == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "padding   ");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("[LEN]#[DATA](no room)")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding 2345");

        CHECK(false == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "padding 2345");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("[LE#N][DATA](no room)")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding 123456");

        CHECK(false == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "padding 123456");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("#[LEN][DATA](no room)")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "01234567890abcde");

        CHECK(false == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "01234567890abcde");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("[LEN][DATA]#")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding");
        writer.push();
        auto eraser = buffer.reader();
        read(eraser, "padding");
        eraser.pop();

        CHECK(true == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "12345");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("[LEN][DATA#]")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding");
        writer.push();
        auto eraser = buffer.reader();
        read(eraser, "padding");
        eraser.pop();

        CHECK(true == writer.write("123456", 6));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "123456");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("[LEN][DATA#]")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding ");
        writer.push();
        auto eraser = buffer.reader();
        read(eraser, "padding ");
        eraser.pop();

        CHECK(true == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "12345");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("[LEN][DA#TA]")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding   ");
        writer.push();
        auto eraser = buffer.reader();
        read(eraser, "padding   ");
        eraser.pop();

        CHECK(true == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "12345");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("[LEN]#[DATA]")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding 2345");
        writer.push();
        auto eraser = buffer.reader();
        read(eraser, "padding 2345");
        eraser.pop();

        CHECK(true == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "12345");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("[LE#N][DATA]")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "padding 123456");
        writer.push();
        auto eraser = buffer.reader();
        read(eraser, "padding 123456");
        eraser.pop();

        CHECK(true == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "12345");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("#[LEN][DATA]")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "01234567890abcde");
        writer.push();
        auto eraser = buffer.reader();
        read(eraser, "01234567890abcde");
        eraser.pop();

        CHECK(true == writer.write("12345", 5));
        writer.push();

        auto reader = buffer.reader();
        read(reader, "12345");
        reader.pop();
        CHECK(true == buffer.empty());
    }

    SECTION("extended")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto w1 = buffer.writer();
        auto r1 = buffer.reader();

        write(w1, "0", "1");                // 10 bytes
        w1.push();

        r1.retry();
        read(r1, "0", "1", "");

        write(w1, "2", "3");                // 20 bytes
        w1.push();

        r1.retry();
        read(r1, "0", "1", "2", "3");
        r1.pop();

        // wrapping 1
        auto w2 = buffer.writer();
        auto r2 = buffer.reader();

        write(w2, "4", "5");                // +10 bytes
        w2.push();

        r2.retry();
        read(r2, "4", "5", "");

        // cannot write two records now, as w2 thinks r2 still stays near the end
        write(w2, "6");                     // +15 bytes
        CHECK(false == w2.write("7", 1));
        w2.push();

        // The next two lines:
        //     - make it visible the reader passed the end
        //     - writer gets updated that the reader moved away from the end
        //     - this sequence unblocks the case when reader and writer find their pointers close to the end
        r2.pop();
        w2.retry();

        write(w2, "7");                     // +20 bytes
        w2.push();

        r2.retry();
        read(r2, "6", "7");
        r2.pop();

        // wrapping 2
        auto w3 = buffer.writer();
        auto r3 = buffer.reader();

        write(w3, "a", "b");                // ++10 bytes
        w3.push();

        r3.retry();
        read(r3, "a", "b", "");

        // cannot write two records now, as w3 thinks r3 still stays near the end
        write(w3, "c");                     // ++15 bytes
        CHECK(false == w3.write("d", 1));
        w3.push();

        // unblock
        r3.pop();
        w3.retry();

        write(w3, "d");                     // ++20 bytes
        w3.push();

        r3.retry();
        read(r3, "c", "d");
        r3.pop();
    }

    SECTION("data fits")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "0123456789", "ab");  // 14 bytes + 6 bytes more
        writer.push();

        auto reader = buffer.reader();
        read(reader, "0123456789", "ab");
        reader.pop();

        writer.retry(); // as the read pointer is on 21 byte, effective capacity is decreased by 1 byte
        CHECK(false == writer.write("0123456789abcdef", 16));
        CHECK(true == writer.write("0123456789abcde", 15));
        writer.push();

        reader.retry();
        read(reader, "0123456789abcde");
        reader.pop();
    }

    SECTION("data doesn't fit: 1st half, 2nd half")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "0123456789");            // 14 bytes
        CHECK(false == writer.write("abc", 3)); // no place for 7 bytes, otherwise it'd fill entire storage
        writer.push();

        auto reader = buffer.reader();
        read(reader, "0123456789");
        reader.pop();

        CHECK(true == buffer.empty());                 // now as the storage is empty
        writer.retry();                                // but split into two parts of 14 + 7 bytes
        CHECK(false == writer.write("0123456789a", 11)); // there is not room for records bigger than that
        CHECK(false == writer.write("0123456789", 10));  // moreover, a guarding byte won't let the same record to go in

        CHECK(true == writer.write("012345678", 9));   // writer is forced to a smaller record by reader position
        writer.push();                                 // consuming 13 bytes this time
        reader.retry();
        read(reader, "012345678");
        reader.pop();

        writer.retry();
        CHECK(true == writer.write("abc", 3));         // no, we have more place for the same record of 7 bytes
        writer.push();

        reader.retry();
        read(reader, "abc");
        reader.pop();
    }

    SECTION("Getting writer while it's behind reader")
    {
        REQUIRE(21 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();
        write(writer, "0123456789", "ab");  // 14 bytes + 6 bytes more
        writer.push();

        auto reader = buffer.reader();
        read(reader, "0123456789", "ab");
        reader.pop();

        write(writer, "1", "2");  // start from beginning
        writer.push();

        {
            auto co_writer = buffer.writer();
            write(co_writer, "3");
            co_writer.push();
        }

        reader.retry();
        read(reader, "1", "2", "3");
        reader.pop();
    }
}

TEST_CASE("Empty buffer", "[Ring2]")
{
    Ring2 buffer(0);

    SECTION("writing")
    {
        REQUIRE(0 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto writer = buffer.writer();

        CHECK(false == writer.write("", 0));
        CHECK(false == writer.write("a", 1));
        CHECK(false == writer.write("foo", 3));
        writer.push();

        CHECK(false == writer.write("", 0));
        CHECK(false == writer.write("a", 1));
        CHECK(false == writer.write("foo", 3));
        writer.push();

        writer.retry();

        CHECK(false == writer.write("", 0));
        CHECK(false == writer.write("a", 1));
        CHECK(false == writer.write("foo", 3));
        writer.push();

        CHECK(0 == buffer.capacity());
        CHECK(true == buffer.empty());
    }

    SECTION("reading")
    {
        REQUIRE(0 == buffer.capacity());
        REQUIRE(true == buffer.empty());

        auto reader = buffer.reader();

        read(reader, "");
        read(reader, "");
        read(reader, "");
        reader.pop();

        read(reader, "");
        read(reader, "");
        read(reader, "");
        reader.pop();

        reader.retry();

        read(reader, "");
        read(reader, "");
        read(reader, "");
        reader.pop();

        CHECK(0 == buffer.capacity());
        CHECK(true == buffer.empty());
    }
}
