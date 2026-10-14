//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// ip_frag_tracker_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream/ip/ip_session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

// GOT_FIRST and GOT_LAST must not survive a purge; LATCH is a bit the caller keeps
#define TEST_FRAG_GOT_FIRST 0x00000001
#define TEST_FRAG_GOT_LAST  0x00000002
#define TEST_FRAG_LATCH     0x00000020

// non-null stand-ins that clear_fragments() never dereferences
static Fragment* const stale_node = reinterpret_cast<Fragment*>(static_cast<uintptr_t>(0x10));
static FragEngine* const live_engine = reinterpret_cast<FragEngine*>(static_cast<uintptr_t>(0x20));

// a timed-out train: first and last seen, 64 of 96 bytes stored, one alert raised
static void set_stale_state(FragTracker& ft)
{
    ft.frag_flags = TEST_FRAG_GOT_FIRST | TEST_FRAG_GOT_LAST | TEST_FRAG_LATCH;
    ft.frag_bytes = 64;
    ft.calculated_size = 96;
    ft.frag_pkts = 2;
    ft.overlap_count = 3;
    ft.fraglist = stale_node;
    ft.fraglist_tail = stale_node;
    ft.fraglist_count = 2;
    ft.alert_count = 1;
}

TEST_GROUP(ip_frag_tracker) { };

// Regression for a rebuild sized from an abandoned fragment train
TEST(ip_frag_tracker, clear_fragments_resets_completion_state)
{
    FragTracker ft = {};
    set_stale_state(ft);

    ft.clear_fragments(TEST_FRAG_LATCH);

    POINTERS_EQUAL(nullptr, ft.fraglist);
    POINTERS_EQUAL(nullptr, ft.fraglist_tail);
    CHECK_EQUAL(0, ft.fraglist_count);
    CHECK_EQUAL(0, ft.frag_bytes);
    CHECK_EQUAL(0, ft.calculated_size);
    CHECK_EQUAL(0, ft.frag_pkts);
    CHECK_EQUAL(0, ft.overlap_count);
    CHECK_EQUAL(TEST_FRAG_LATCH, ft.frag_flags);
}

// a kept bit survives only if it was already set
TEST(ip_frag_tracker, clear_fragments_does_not_set_kept_bits)
{
    FragTracker ft = {};
    ft.frag_flags = TEST_FRAG_GOT_FIRST;

    ft.clear_fragments(TEST_FRAG_LATCH);

    CHECK_EQUAL(0, ft.frag_flags);
}

// Regression for an abandoned train's alert suppressing a later datagram's event
TEST(ip_frag_tracker, clear_fragments_resets_alert_record)
{
    FragTracker ft = {};
    set_stale_state(ft);

    ft.clear_fragments(0);

    CHECK_EQUAL(0, ft.alert_count);
}

// Defrag::expired() reuses the tracker in place, so identity must survive
TEST(ip_frag_tracker, clear_fragments_keeps_tracker_identity)
{
    FragTracker ft = {};
    set_stale_state(ft);
    ft.engine = live_engine;
    ft.ip_proto = IpProtocol::UDP;
    ft.ttl = 64;
    ft.frag_policy = 2;

    ft.clear_fragments(0);

    POINTERS_EQUAL(live_engine, ft.engine);
    CHECK_EQUAL(static_cast<int>(IpProtocol::UDP), static_cast<int>(ft.ip_proto));
    CHECK_EQUAL(64, ft.ttl);
    CHECK_EQUAL(2, ft.frag_policy);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
