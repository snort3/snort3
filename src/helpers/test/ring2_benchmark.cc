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
// ring2_benchmark.cc author Cisco

#ifdef BENCHMARK_TEST

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/catch.hpp"

#include <vector>

#include "helpers/ring2.h"

#define WRITE_FULL                                      \
    do {                                                \
        buffer.clear();                                 \
        auto writer = buffer.writer();                  \
                                                        \
        BENCHMARK("full write")                         \
        {                                               \
            while(writer.write(data, sizeof(data)));    \
            writer.retry();                             \
                                                        \
            return true;                                \
        };                                              \
    } while (0)

#define READ_FULL                                   \
    do {                                            \
        buffer.clear();                             \
        auto writer = buffer.writer();              \
        auto reader = buffer.reader();              \
        size_t len = 0;                             \
                                                    \
        while (writer.write(data, sizeof(data)));   \
        writer.push();                              \
                                                    \
        BENCHMARK("full read")                      \
        {                                           \
            while(reader.read(len));                \
            reader.retry();                         \
                                                    \
            return true;                            \
        };                                          \
    } while (0)

#define WRITE_1                                                 \
    do {                                                        \
        buffer.clear();                                         \
        auto writer = buffer.writer();                          \
                                                                \
        BENCHMARK("1 write")                                    \
        {                                                       \
            auto accepted = writer.write(data, sizeof(data));   \
                                                                \
            if (!accepted)                                      \
                writer.retry();                                 \
                                                                \
            return true;                                        \
        };                                                      \
    } while (0)

#define READ_1                                      \
    do {                                            \
        buffer.clear();                             \
        auto writer = buffer.writer();              \
        auto reader = buffer.reader();              \
        size_t len = 0;                             \
                                                    \
        while (writer.write(data, sizeof(data)));   \
        writer.push();                              \
                                                    \
        BENCHMARK("1 read")                         \
        {                                           \
            auto read = reader.read(len);           \
                                                    \
            if (!read)                              \
                reader.retry();                     \
                                                    \
            return true;                            \
        };                                          \
    } while (0)

#define WRITE_1_READ_1                                  \
    do {                                                \
        buffer.clear();                                 \
        auto writer = buffer.writer();                  \
        auto reader = buffer.reader();                  \
        size_t len = 0;                                 \
                                                        \
        BENCHMARK("1 write 1 read")                     \
        {                                               \
            auto r1 = writer.write(data, sizeof(data)); \
            writer.push();                              \
                                                        \
            auto r2 = reader.read(len);                 \
            reader.pop();                               \
                                                        \
            return r1 and r2 and len;                   \
        };                                              \
    } while (0)


#define WRITE_4_READ_4x                         \
    do {                                        \
        buffer.clear();                         \
        auto writer = buffer.writer();          \
        auto reader = buffer.reader();          \
        size_t len = 0;                         \
                                                \
        BENCHMARK("4 writes 4x reads")          \
        {                                       \
            writer.write(data, sizeof(data));   \
            writer.push();                      \
            writer.write(data, sizeof(data));   \
            writer.push();                      \
            writer.write(data, sizeof(data));   \
            writer.push();                      \
            writer.write(data, sizeof(data));   \
            writer.push();                      \
                                                \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.pop();                       \
                                                \
            return true;                        \
        };                                      \
    } while (0)

#define WRITE_4x_READ_4x                        \
    do {                                        \
        buffer.clear();                         \
        auto writer = buffer.writer();          \
        auto reader = buffer.reader();          \
        size_t len = 0;                         \
                                                \
        BENCHMARK("4x writes 4x reads")         \
        {                                       \
            writer.write(data, sizeof(data));   \
            writer.write(data, sizeof(data));   \
            writer.write(data, sizeof(data));   \
            writer.write(data, sizeof(data));   \
            writer.push();                      \
                                                \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.pop();                       \
                                                \
            return true;                        \
        };                                      \
    } while (0)

#define WRITE_8x_READ_8x                        \
    {                                           \
        buffer.clear();                         \
        auto writer = buffer.writer();          \
        auto reader = buffer.reader();          \
        size_t len = 0;                         \
                                                \
        BENCHMARK("8x writes 8x reads")         \
        {                                       \
            writer.write(data, sizeof(data));   \
            writer.write(data, sizeof(data));   \
            writer.write(data, sizeof(data));   \
            writer.write(data, sizeof(data));   \
            writer.write(data, sizeof(data));   \
            writer.write(data, sizeof(data));   \
            writer.write(data, sizeof(data));   \
            writer.write(data, sizeof(data));   \
            writer.push();                      \
                                                \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.read(len);                   \
            reader.pop();                       \
                                                \
            return true;                        \
        };                                      \
    } while (0)

#define SEQUENCE                                \
    do {                                        \
        WRITE_FULL;                             \
        READ_FULL;                              \
        WRITE_1;                                \
        READ_1;                                 \
        WRITE_1_READ_1;                         \
        WRITE_4_READ_4x;                        \
        WRITE_4x_READ_4x;                       \
        WRITE_8x_READ_8x;                       \
    } while (0)

TEST_CASE("Linear: buffer 8K, record size 32", "[Ring2]")
{
    Ring2 buffer(8192);
    char data[28] = {};

    SEQUENCE;
}

TEST_CASE("Linear: buffer 16K, record size 32", "[Ring2]")
{
    Ring2 buffer(16384);
    char data[28] = {};

    SEQUENCE;
}

TEST_CASE("Linear: buffer 64K, record size 32", "[Ring2]")
{
    Ring2 buffer(65536);
    char data[28] = {};

    SEQUENCE;
}

TEST_CASE("Linear: buffer 8K, record size 256", "[Ring2]")
{
    Ring2 buffer(8192);
    char data[252] = {0};

    SEQUENCE;
}

TEST_CASE("Linear: buffer 16K, record size 256", "[Ring2]")
{
    Ring2 buffer(16384);
    char data[252] = {0};

    SEQUENCE;
}

TEST_CASE("Linear: buffer 64K, record size 256", "[Ring2]")
{
    Ring2 buffer(65536);
    char data[252] = {0};

    SEQUENCE;
}

TEST_CASE("Linear: buffer 64K, odd record size 239", "[Ring2]")
{
    Ring2 buffer(65536);
    char data[239 - 4] = {0};

    SEQUENCE;
}

TEST_CASE("Linear: buffer 64K, odd record size 479", "[Ring2]")
{
    Ring2 buffer(65536);
    char data[479 - 4] = {0};

    SEQUENCE;
}

#endif
