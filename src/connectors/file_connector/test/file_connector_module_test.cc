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

// file_connector_module_test.cc author Ed Borgoyn <eborgoyn@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "connectors/file_connector/file_connector_module.h"
#include "profiler/profiler.h"

#include "main/snort_debug.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

THREAD_LOCAL SimpleStats file_connector_stats;
THREAD_LOCAL ProfileStats file_connector_perfstats;

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }

namespace snort
{
char* snort_strdup(const char* s)
{ return strdup(s); }
}

TEST_GROUP(file_connector_module)
{
    void setup() override
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    }

    void teardown() override
    {
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(file_connector_module, test)
{
    Value connector_val("rx");
    Value name_val("rx");
    Value format_val("binary");
    Value direction_val("receive");
    Parameter direction_param =
        {"direction", Parameter::PT_ENUM, "receive | transmit | duplex", nullptr, "direction"};
    Parameter format_param =
        {"format", Parameter::PT_ENUM, "binary | text", nullptr, "format"};
    Parameter connector_param =
        {"connector", Parameter::PT_STRING, nullptr, nullptr, "connector"};
    Parameter name_param =
        {"name", Parameter::PT_STRING, nullptr, nullptr, "name"};

    FileConnectorModule module;

    name_val.set(&name_param);
    direction_val.set(&direction_param);
    format_val.set(&format_param);
    connector_val.set(&connector_param);

    module.begin("file_connector", 0, nullptr);
    module.begin("file_connector", 1, nullptr);
    module.set("file_connector.name", name_val, nullptr);
    module.set("file_connector.direction", direction_val, nullptr);
    module.set("file_connector.connector", connector_val, nullptr);
    module.set("file_connector.format", format_val, nullptr);
    module.end("file_connector", 1, nullptr);
    module.end("file_connector", 0, nullptr);

    FileConnectorConfig::FileConnectorConfigSet* config_set = module.get_and_clear_config();

    CHECK(config_set != nullptr);

    CHECK(config_set->size() == 1);

    FileConnectorConfig config = *(config_set->front());
    CHECK(config.name == "rx");
    CHECK(config.connector_name == "rx");
    CHECK(config.direction == Connector::CONN_RECEIVE);
    CHECK(config.text_format == false);

    for ( auto conf : *config_set )
        delete conf;

    config_set->clear();
    delete config_set;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

