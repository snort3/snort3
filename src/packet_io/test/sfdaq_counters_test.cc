//--------------------------------------------------------------------------
// Copyright (C) 2024 Cisco and/or its affiliates. All rights reserved.
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
// sfdaq_counters_test.cc author Arunkumar Kayambu <akayambu@cisco.com>

// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------

#include "packet_io/sfdaq.h"
#include "packet_io/sfdaq_module.h"
#include "sfdaq_module_stubs.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

static DAQ_Stats_t* mock_stats_ptr = nullptr;
SFDAQInstance *local_instance = nullptr;

const DAQ_Stats_t* SFDAQ::get_stats() {
    mock().actualCall("get_stats");
    mock_stats_ptr->packets_outstanding = 20;
    return mock_stats_ptr;
}

SFDAQInstance* SFDAQ::get_local_instance() {
    mock().actualCall("get_local_instance");
    return local_instance;
}

TEST_GROUP(sfdaq_module_counters)
{
    void setup() {
        mock_stats_ptr = new DAQ_Stats_t();
        local_instance = new SFDAQInstance(nullptr, 0, nullptr);
    }

    void teardown() {
        mock().clear();
        delete mock_stats_ptr;
        delete local_instance;
    }
};

TEST(sfdaq_module_counters, check_outstanding_counter)
{
    SFDAQModule sfdm;
    const PegInfo* infos = sfdm.get_pegs();

    // Set up the expectation
    mock().expectOneCall("get_stats");
    mock().expectOneCall("get_local_instance");

    sfdm.prep_counts(false);
    PegCount* p = sfdm.get_counts();
    mock().checkExpectations();
    for ( unsigned i = 0; infos[i].name; i++ )
    {
        if ( strcmp(infos[i].name, "packets_outstanding") == 0 )
            CHECK(20 == p[i]);
    }
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
