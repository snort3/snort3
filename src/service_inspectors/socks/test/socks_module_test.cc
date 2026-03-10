//--------------------------------------------------------------------------
// Copyright (C) 2024-2026 Cisco and/or its affiliates. All rights reserved.
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

// socks_module_test.cc author Raza Shafiq <rshafiq@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "log/messages.h"
#include "main/thread_config.h"
#include "service_inspectors/socks/socks_module.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

namespace snort
{
// Stubs whose sole purpose is to make the test code link
void ParseWarning(WarningGroup, const char*, ...) {}
void ParseError(const char*, ...) {}

unsigned get_instance_id()
{ return 0; }
unsigned ThreadConfig::get_instance_max() { return 1; }
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }

// THREAD_LOCAL variables that socks_module.cc references
THREAD_LOCAL ProfileStats socksPerfStats;
THREAD_LOCAL SocksStats socks_stats;

// Stub class and constructor for Socks5Inspector to resolve linking
class SocksInspector
{
public:
    SocksInspector(const SocksModule*);
    ~SocksInspector();
};

// Provide explicit constructor and destructor definitions
SocksInspector::SocksInspector(const SocksModule*) {}
SocksInspector::~SocksInspector() {}

TEST_GROUP(socks5_module_test)
{
    SocksModule* mod = nullptr;

    void setup() override
    {
        mod = new SocksModule();
        (void)mod;
    }

    void teardown() override
    {
        // Reset stats to zero
        PegCount* counts = mod->get_counts();
        for (unsigned k = 0; k < SOCKS_PEG_MAX; k++)
        {
            counts[k] = 0;
        }
        delete mod;
    }
};

TEST(socks5_module_test, constructor_defaults)
{
    CHECK_EQUAL(Module::INSPECT, mod->get_usage());
    CHECK_TRUE(mod->is_bindable());
    CHECK(mod->get_pegs() == socks_pegs);
    CHECK(mod->get_counts() != nullptr);
    CHECK(mod->get_profile() == &socksPerfStats);
}

TEST(socks5_module_test, peg_count_initialization)
{
    // Test that all peg counts are initialized to zero
    for (unsigned k = 0; k < SOCKS_PEG_MAX; k++)
    {
        CHECK_EQUAL(0, socks_stats.sessions);
        CHECK_EQUAL(0, socks_stats.concurrent_sessions);
        CHECK_EQUAL(0, socks_stats.auth_requests);
        break; // Just test a few key ones
    }
}

TEST(socks5_module_test, module_interface)
{
    // Test basic module interface
    CHECK(mod != nullptr);
    CHECK_TRUE(mod->is_bindable());
    CHECK_EQUAL(Module::INSPECT, mod->get_usage());
}

TEST(socks5_module_test, lifecycle_methods)
{
    // Test module lifecycle methods
    CHECK_TRUE(mod->begin("", 0, nullptr));
    CHECK_TRUE(mod->end("", 0, nullptr));
}

TEST(socks5_module_test, peg_counters_available)
{
    const PegInfo* pegs = mod->get_pegs();
    CHECK(pegs != nullptr);
    CHECK(pegs == socks_pegs);
    
    // Verify all expected pegs are present
    int count = 0;
    while (pegs[count].type != CountType::END)
    {
        count++;
    }
    CHECK_EQUAL(SOCKS_PEG_MAX, count);
}

TEST(socks5_module_test, all_stats_peg_mapping)
{
    PegCount* counts = mod->get_counts();
    CHECK(counts != nullptr);
    
    // Set all stats to unique values and verify peg index mapping
    socks_stats.sessions = 1;
    socks_stats.concurrent_sessions = 2;
    socks_stats.max_concurrent_sessions = 3;
    socks_stats.auth_requests = 4;
    socks_stats.auth_successes = 5;
    socks_stats.auth_failures = 6;
    socks_stats.connect_requests = 7;
    socks_stats.bind_requests = 8;
    socks_stats.udp_associate_requests = 9;
    socks_stats.successful_connections = 10;
    socks_stats.failed_connections = 11;
    socks_stats.udp_associations_created = 12;
    socks_stats.udp_expectations_created = 13;
    socks_stats.udp_packets = 14;
    socks_stats.udp_frags = 15;
    
    // Verify all peg indices map correctly
    CHECK_EQUAL(1, counts[SOCKS_PEG_SESSIONS]);
    CHECK_EQUAL(2, counts[SOCKS_PEG_CONCURRENT_SESSIONS]);
    CHECK_EQUAL(3, counts[SOCKS_PEG_MAX_CONCURRENT_SESSIONS]);
    CHECK_EQUAL(4, counts[SOCKS_PEG_AUTH_REQUESTS]);
    CHECK_EQUAL(5, counts[SOCKS_PEG_AUTH_SUCCESSES]);
    CHECK_EQUAL(6, counts[SOCKS_PEG_AUTH_FAILURES]);
    CHECK_EQUAL(7, counts[SOCKS_PEG_CONNECT_REQUESTS]);
    CHECK_EQUAL(8, counts[SOCKS_PEG_BIND_REQUESTS]);
    CHECK_EQUAL(9, counts[SOCKS_PEG_UDP_ASSOCIATE_REQUESTS]);
    CHECK_EQUAL(10, counts[SOCKS_PEG_SUCCESSFUL_CONNECTIONS]);
    CHECK_EQUAL(11, counts[SOCKS_PEG_FAILED_CONNECTIONS]);
    CHECK_EQUAL(12, counts[SOCKS_PEG_UDP_ASSOCIATIONS_CREATED]);
    CHECK_EQUAL(13, counts[SOCKS_PEG_UDP_EXPECTATIONS_CREATED]);
    CHECK_EQUAL(14, counts[SOCKS_PEG_UDP_PACKETS]);
    CHECK_EQUAL(15, counts[SOCKS_PEG_UDP_FRAGS]);
}

TEST(socks5_module_test, basic_functionality)
{
    // Test basic module functionality without external dependencies
    CHECK(mod != nullptr);
    CHECK_TRUE(mod->is_bindable());
}

TEST(socks5_module_test, module_constants)
{
    // Test module constants are properly defined
    CHECK(strcmp(SOCKS_NAME, "socks") == 0);
    CHECK(strcmp(SOCKS_HELP, "SOCKS protocol inspector") == 0);
}

TEST(socks5_module_test, all_pegs_defined)
{
    // Ensure all peg info entries are properly defined
    const PegInfo* pegs = socks_pegs;
    
    // Check first few entries
    CHECK(pegs[SOCKS_PEG_SESSIONS].type == CountType::SUM);
    CHECK(strcmp(pegs[SOCKS_PEG_SESSIONS].name, "sessions") == 0);
    
    CHECK(pegs[SOCKS_PEG_CONCURRENT_SESSIONS].type == CountType::NOW);
    CHECK(strcmp(pegs[SOCKS_PEG_CONCURRENT_SESSIONS].name, "concurrent_sessions") == 0);
    
    CHECK(pegs[SOCKS_PEG_MAX_CONCURRENT_SESSIONS].type == CountType::MAX);
    CHECK(strcmp(pegs[SOCKS_PEG_MAX_CONCURRENT_SESSIONS].name, "max_concurrent_sessions") == 0);
    
    // Check last entry is properly terminated
    CHECK(pegs[SOCKS_PEG_MAX].type == CountType::END);
    CHECK(pegs[SOCKS_PEG_MAX].name == nullptr);
    CHECK(pegs[SOCKS_PEG_MAX].help == nullptr);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
