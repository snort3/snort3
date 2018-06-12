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

// side_channel_module_test.cc author Ed Borgoyn <eborgoyn@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "side_channel/side_channel.h"
#include "side_channel/side_channel_module.h"

#include "log/messages.h"
#include "main/snort_debug.h"
#include "profiler/profiler.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

THREAD_LOCAL SimpleStats sc_stats;
THREAD_LOCAL ProfileStats sc_perf_stats;

static bool port_1_set = false;

static char* make_bit_string(int bit)
{
    static char bit_string[65537];
    for ( int i=0; i<65536; i++)
        bit_string[i] = (bit == i) ? '1' : '0';

    bit_string[65536] = '\0';

    return bit_string;
}

void SideChannelManager::instantiate(const SCConnectors*, const PortBitSet* ports)
{
    port_1_set = ports->test(1);
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }

namespace snort
{
void ParseWarning(WarningGroup, const char*, ...) { }

char* snort_strdup(const char* s)
{ return strdup(s); }
}

TEST_GROUP(side_channel_module)
{ };

TEST(side_channel_module, test_connector_module_valid)
{
    Value ports_val(make_bit_string(1));
    Value connector_t_val("transmit");
    Value connector_r_val("receive");
    Parameter ports_param = {"ports", Parameter::PT_BIT_LIST, "65535", nullptr, "ports"};
    Parameter connector_param = {"connector", Parameter::PT_STRING, nullptr, nullptr, "connector"};

    SideChannelModule module;

    ports_val.set(&ports_param);
    connector_t_val.set(&connector_param);
    connector_r_val.set(&connector_param);

    module.begin("side_channel", 0, nullptr);
    module.begin("side_channel", 1, nullptr);
    module.begin("side_channel.connectors", 0, nullptr);
    module.begin("side_channel.connectors", 1, nullptr);
    module.set("side_channel.connectors.connector", connector_t_val, nullptr);
    module.end("side_channel.connectors", 1, nullptr);
    module.begin("side_channel.connectors", 2, nullptr);
    module.set("side_channel.connectors.connector", connector_r_val, nullptr);
    module.end("side_channel.connectors", 2, nullptr);
    module.end("side_channel.connectors", 0, nullptr);
    module.set("side_channel.ports", ports_val, nullptr);
    module.end("side_channel", 1, nullptr);
    module.end("side_channel", 0, nullptr);

    CHECK(port_1_set == true);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

