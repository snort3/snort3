//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// ha_module_test.cc author Ed Borgoyn <eborgoyn@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/ha.h"
#include "flow/ha_module.h"

#include "log/messages.h"
#include "main/snort_debug.h"
#include "profiler/profiler.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

THREAD_LOCAL SimpleStats ha_stats;
THREAD_LOCAL ProfileStats ha_perf_stats;

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }

namespace snort
{
void LogMessage(const char*,...) { }
void ParseWarning(WarningGroup, const char*, ...) { }
char* snort_strdup(const char* str) { return strdup(str); }
}

static bool s_port_1_set = false;
static bool s_use_daq = false;
static bool s_instantiate_called = false;

static char* make_bit_string(int bit)
{
    static char bit_string[65537];
    for ( int i=0; i<65536; i++)
        bit_string[i] = (bit == i) ? '1' : '0';

    bit_string[65536] = '\0';

    return bit_string;
}

bool HighAvailabilityManager::instantiate(PortBitSet* mod_ports, bool mod_use_daq_channel, struct timeval*, struct timeval*)
{
    s_instantiate_called = true;
    s_port_1_set = mod_ports->test(1);
    s_use_daq = mod_use_daq_channel;

    return true;
}

TEST_GROUP(high_availability_module_test)
{
    void setup() override
    {
    }

    void teardown() override
    {
    }
};

TEST(high_availability_module_test, test_ha_valid)
{
    Value ports_val(make_bit_string(1));
    Value enable_val(true);
    Value min_age_val(1.0);
    Value min_sync_val(0.1);
    Parameter ports_param = {"ports", Parameter::PT_BIT_LIST, "65535", nullptr, "ports"};
    Parameter enable_param = {"enable", Parameter::PT_BOOL, nullptr, "false", nullptr };
    Parameter min_age_param = {"min_age", Parameter::PT_REAL, nullptr, "1.0", nullptr };
    Parameter min_sync_param = {"min_sync", Parameter::PT_REAL, nullptr, "0.1", nullptr };

    HighAvailabilityModule module;

    ports_val.set(&ports_param);
    enable_val.set(&enable_param);
    min_age_val.set(&min_age_param);
    min_sync_val.set(&min_sync_param);

    s_instantiate_called = false;
    s_port_1_set = false;
    s_use_daq = false;

    module.begin("high_availability", 0, nullptr);
    module.set("high_availability.ports", ports_val, nullptr);
    module.set("high_availability.enable", enable_val, nullptr);
    module.set("high_availability.min_age", min_age_val, nullptr);
    module.set("high_availability.min_sync", min_sync_val, nullptr);
    module.end("high_availability", 0, nullptr);

    CHECK(s_instantiate_called == true);
    CHECK(s_port_1_set == true);
    CHECK(s_use_daq == false);
}

TEST(high_availability_module_test, test_ha_disabled)
{
    Value enable_val(false);
    Parameter enable_param = {"enable", Parameter::PT_BOOL, nullptr, "false", nullptr };

    HighAvailabilityModule module;

    enable_val.set(&enable_param);

    s_instantiate_called = false;
    s_port_1_set = false;
    s_use_daq = false;

    module.begin("high_availability", 0, nullptr);
    module.set("high_availability.enable", enable_val, nullptr);
    module.end("high_availability", 0, nullptr);

    CHECK(s_instantiate_called == false);
    CHECK(s_port_1_set == false);
    CHECK(s_use_daq == false);
}

TEST(high_availability_module_test, test_ha_valid_daq)
{
    Value ports_val(make_bit_string(1));
    Value enable_val(true);
    Value daq_val(true);
    Parameter ports_param = {"ports", Parameter::PT_BIT_LIST, "65535", nullptr, "ports"};
    Parameter enable_param = {"enable", Parameter::PT_BOOL, nullptr, "false", nullptr };
    Parameter daq_param = {"daq_channel", Parameter::PT_BOOL, nullptr, "false", nullptr };

    HighAvailabilityModule module;

    ports_val.set(&ports_param);
    enable_val.set(&enable_param);
    daq_val.set(&daq_param);

    s_instantiate_called = false;
    s_port_1_set = false;
    s_use_daq = false;

    module.begin("high_availability", 0, nullptr);
    module.set("high_availability.ports", ports_val, nullptr);
    module.set("high_availability.enable", enable_val, nullptr);
    module.set("high_availability.daq_channel", daq_val, nullptr);
    module.end("high_availability", 0, nullptr);

    CHECK(s_instantiate_called == true);
    CHECK(s_port_1_set == true);
    CHECK(s_use_daq == true);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

