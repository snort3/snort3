//--------------------------------------------------------------------------
// Copyright (C) 2019-2021 Cisco and/or its affiliates. All rights reserved.
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

// session_test.cc authors Devendra Dahiphale <ddahipha@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

class DummySession : public Session
{
    public:
        DummySession(Flow* f) : Session(f) { }
        void clear() override { }
        ~DummySession() override = default;
};

//-------------------------------------------------------------------------
// tests
//-------------------------------------------------------------------------

TEST_GROUP(session_test)
{
};

TEST(session_test, seesion_class_test)
{
    Session *ssn = new DummySession(nullptr);
    CHECK(true == ssn->setup(nullptr));

    CHECK(0 == ssn->process(nullptr));
    ssn->restart(nullptr);
    ssn->flush_client(nullptr);
    ssn->flush_server(nullptr);
    ssn->flush_talker(nullptr, false);
    ssn->flush_listener(nullptr, false);
    CHECK(nullptr == ssn->get_splitter(true));

    ssn->set_extra_data(nullptr, 1);

    CHECK(true == ssn->is_sequenced(1));
    CHECK(false == ssn->are_packets_missing(1));

    CHECK(SSN_DIR_NONE == ssn->get_reassembly_direction());
    CHECK(SSN_MISSING_NONE == ssn->missing_in_reassembled(1));

    CHECK(false == ssn->set_packet_action_to_hold(nullptr));

    delete ssn;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

