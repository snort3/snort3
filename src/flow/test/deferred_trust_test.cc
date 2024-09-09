//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// deferred_trust_test.cc author Ron Dempster <rdempste@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/deferred_trust.h"
#include "packet_io/active.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//-------------------------------------------------------------------------
// tests
//-------------------------------------------------------------------------

TEST_GROUP(deferred_trust_test)
{
};

TEST(deferred_trust_test, set_deferred_trust)
{
    DeferredTrust deferred_trust;
    // Disable non-existent module_id
    deferred_trust.set_deferred_trust(1, false);
    CHECK_TEXT(!deferred_trust.is_active(), "Deferred trust should not be active");

    // Enable
    deferred_trust.set_deferred_trust(1, true);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(!deferred_trust.is_deferred(), "Deferred trust should not be deferring");
    // Disable non-existent module_id, no state change
    deferred_trust.set_deferred_trust(2, false);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(!deferred_trust.is_deferred(), "Deferred trust should not be deferring");
    // Disable the only module_id disables deferring
    deferred_trust.set_deferred_trust(1, false);
    CHECK_TEXT(!deferred_trust.is_active(), "Deferred trust should not be active");

    // Enable
    deferred_trust.set_deferred_trust(1, true);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(!deferred_trust.is_deferred(), "Deferred trust should not be deferring");
    // Enable second module_id
    deferred_trust.set_deferred_trust(2, true);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(!deferred_trust.is_deferred(), "Deferred trust should not be deferring");
    // Disable the first module_id, no state change
    deferred_trust.set_deferred_trust(1, false);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(!deferred_trust.is_deferred(), "Deferred trust should not be deferring");
    // Disable the second module_id disables deferring
    deferred_trust.set_deferred_trust(2, false);
    CHECK_TEXT(!deferred_trust.is_active(), "Deferred trust should not be active");

    // Enable
    deferred_trust.set_deferred_trust(1, true);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(!deferred_trust.is_deferred(), "Deferred trust should not be deferring");
    // Try to trust, change state to deferring
    deferred_trust.try_trust();
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(deferred_trust.is_deferred(), "Deferred trust should be deferring");
    // Disable the only module_id disables deferring
    deferred_trust.set_deferred_trust(1, false);
    CHECK_TEXT(!deferred_trust.is_active(), "Deferred trust should not be active");
}

TEST(deferred_trust_test, finalize)
{
    DeferredTrust deferred_trust;
    Active active{};
    active.block_again();

    // Enable
    deferred_trust.set_deferred_trust(1, true);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(!deferred_trust.is_deferred(), "Deferred trust should not be deferring");
    // finalize with blocked packet disables deferring
    deferred_trust.finalize(active);
    CHECK_TEXT(!deferred_trust.is_active(), "Deferred trust should not be active");

    active.set_allow();
    // Enable
    deferred_trust.set_deferred_trust(1, true);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(!deferred_trust.is_deferred(), "Deferred trust should not be deferring");
    // Try to trust, change state to deferring
    deferred_trust.try_trust();
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(deferred_trust.is_deferred(), "Deferred trust should be deferring");
    // Disable the only module_id disables deferring
    deferred_trust.set_deferred_trust(1, false);
    CHECK_TEXT(!deferred_trust.is_active(), "Deferred trust should not be active");
    // State should be do trust
    // Enable with state do trust goes to deferring
    deferred_trust.set_deferred_trust(2, true);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(deferred_trust.is_deferred(), "Deferred trust should be deferring");
    deferred_trust.set_deferred_trust(2, false);
    CHECK_TEXT(!deferred_trust.is_active(), "Deferred trust should not be active");
    // State should be do trust
    deferred_trust.finalize(active);
    CHECK_TEXT(active.session_was_trusted(), "Session was not trusted from do trust");

    // Enable
    deferred_trust.set_deferred_trust(1, true);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(!deferred_trust.is_deferred(), "Deferred trust should not be deferring");
    // Session is trusted, defer should move to deferring and session should not be trusted
    deferred_trust.finalize(active);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(deferred_trust.is_deferred(), "Deferred trust should be deferring");
    CHECK_TEXT(!active.session_was_trusted(), "Session was trusted while deferring trust");
    CHECK_TEXT(active.session_was_allowed(), "Session was not allowed while deferring trust");

    deferred_trust.clear();
    // Trust flow
    active.set_trust();
    deferred_trust.try_trust();
    // Enable
    deferred_trust.set_deferred_trust(1, true);
    deferred_trust.try_trust();
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(deferred_trust.is_deferred(), "Deferred trust should be deferring");
    // Session is trusted, defer should change action to allow and session should not be trusted
    deferred_trust.finalize(active);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    CHECK_TEXT(deferred_trust.is_deferred(), "Deferred trust should be deferring");
    CHECK_TEXT(!active.session_was_trusted(), "Session was trusted while deferring trust");
    CHECK_TEXT(active.session_was_allowed(), "Session was not allowed while deferring trust");
}

/* Stub implementation for the test below to avoid linking */
void Active::drop_packet(const Packet*, bool)
{
    active_action = ACT_DROP;
}

TEST(deferred_trust_test, finalize_clear)
{
    DeferredTrust deferred_trust;
    Active active{};

    deferred_trust.clear();
    // Enable
    deferred_trust.set_deferred_trust(1, true);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    active.block_again();
    // finalize should clear deferred_trust
    deferred_trust.finalize(active);
    CHECK_TEXT(!deferred_trust.is_active(), "Deferred trust should not be active");

    deferred_trust.clear();
    // Enable
    deferred_trust.set_deferred_trust(1, true);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should be active");
    active.drop_packet(nullptr, true);
    // finalize should NOT clear deferred_trust
    deferred_trust.finalize(active);
    CHECK_TEXT(deferred_trust.is_active(), "Deferred trust should still be active");
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
