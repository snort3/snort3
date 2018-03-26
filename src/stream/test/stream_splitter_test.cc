//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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
// stream_splitter.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream/stream_splitter.h"

#include "detection/detection_engine.h"
#include "stream/flush_bucket.h"
#include "stream/stream.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//--------------------------------------------------------------------------
// mocks
//--------------------------------------------------------------------------
namespace snort
{
THREAD_LOCAL SnortConfig* snort_conf = nullptr;
SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

static StreamSplitter* next_splitter = nullptr;

Flow::Flow() = default;

struct Packet* DetectionEngine::get_current_packet()
{ return nullptr; }

uint8_t* DetectionEngine::get_next_buffer(unsigned int&)
{ return nullptr; }

StreamSplitter* Stream::get_splitter(Flow*, bool)
{ return next_splitter; }

static int flushed = 0;

void Stream::flush_client(Packet*)
{ flushed = 1; }

void Stream::flush_server(Packet*)
{ flushed = 2; }
}


uint16_t FlushBucket::get_size()
{ return 1; }


//--------------------------------------------------------------------------
// atom splitter tests
//--------------------------------------------------------------------------

TEST_GROUP(atom_splitter) { };

TEST(atom_splitter, t2x256)
{
    AtomSplitter s(true, 128);
    uint32_t fp = 0;

    CHECK(s.scan(nullptr, nullptr, 256, 0, &fp) == StreamSplitter::SEARCH);
    CHECK(fp == 0);

    CHECK(s.scan(nullptr, nullptr, 256, 0, &fp) == StreamSplitter::FLUSH);
    CHECK(fp == 256);
}

TEST(atom_splitter, t3x64)
{
    AtomSplitter s(true, 128);
    uint32_t fp = 0;

    CHECK(s.scan(nullptr, nullptr, 64, 0, &fp) == StreamSplitter::SEARCH);
    CHECK(fp == 0);

    CHECK(s.scan(nullptr, nullptr, 64, 0, &fp) == StreamSplitter::SEARCH);
    CHECK(fp == 0);

    CHECK(s.scan(nullptr, nullptr, 64, 0, &fp) == StreamSplitter::FLUSH);
    CHECK(fp == 64);
}

TEST(atom_splitter, t3x256_with_update)
{
    AtomSplitter s(true, 128);
    uint32_t fp = 0;

    CHECK(s.scan(nullptr, nullptr, 256, 0, &fp) == StreamSplitter::SEARCH);
    CHECK(fp == 0);

    s.update();

    CHECK(s.scan(nullptr, nullptr, 256, 0, &fp) == StreamSplitter::SEARCH);
    CHECK(fp == 0);

    CHECK(s.scan(nullptr, nullptr, 256, 0, &fp) == StreamSplitter::FLUSH);
    CHECK(fp == 256);
}

//--------------------------------------------------------------------------
// other splitter tests
//--------------------------------------------------------------------------

TEST_GROUP(other_splitter) { };

TEST(other_splitter, log)
{
    LogSplitter s(true);
    uint32_t fp = 0;

    CHECK(s.scan(nullptr, nullptr, 0, 0, &fp) == StreamSplitter::FLUSH);
    CHECK(fp == 0);

    fp = 0;
    CHECK(s.scan(nullptr, nullptr, 123, 0, &fp) == StreamSplitter::FLUSH);
    CHECK(fp == 123);
}

TEST(other_splitter, stop_and_wait)
{
    Flow flow;

    StopAndWaitSplitter cs(false);
    StopAndWaitSplitter ss(true);

    uint32_t fp = 0;
    next_splitter = &ss;

    CHECK(cs.scan(nullptr, nullptr, 123, 0, &fp) == StreamSplitter::SEARCH);
    CHECK(fp == 0);
    CHECK(flushed == 0);

    next_splitter = &cs;

    CHECK(ss.scan(nullptr, nullptr, 456, 0, &fp) == StreamSplitter::SEARCH);
    CHECK(fp == 0);
    CHECK(flushed == 1);

    next_splitter = &ss;

    CHECK(cs.scan(nullptr, nullptr, 123, 0, &fp) == StreamSplitter::SEARCH);
    CHECK(fp == 0);
    CHECK(flushed == 2);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

