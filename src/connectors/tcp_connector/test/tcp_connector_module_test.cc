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

// tcp_connector_module_test.cc author Ed Borgoyn <eborgoyn@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "connectors/tcp_connector/tcp_connector_module.h"
#include "profiler/profiler.h"

#include "main/snort_debug.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

THREAD_LOCAL SimpleStats tcp_connector_stats;
THREAD_LOCAL ProfileStats tcp_connector_perfstats;

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }

namespace snort
{
char* snort_strdup(const char* s)
{ return strdup(s); }
}

TEST_GROUP(tcp_connector_module)
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

TEST(tcp_connector_module, test_call)
{
    Value connector_val("tcp-c");
    Value address_val("127.0.0.1");
    Value base_port_val((double)10000);
    Value setup_val("call");
    Parameter address_param =
        {"address", Parameter::PT_STRING, nullptr, nullptr, "address"};
    Parameter connector_param =
        {"connector", Parameter::PT_STRING, nullptr, nullptr, "connector"};
    Parameter base_port_param =
        {"base_port", Parameter::PT_PORT, nullptr, nullptr, "base_port"};
    Parameter setup_param =
        {"setup", Parameter::PT_ENUM, "call | answer", nullptr, "establishment"};

    TcpConnectorModule module;

    address_val.set(&address_param);
    base_port_val.set(&base_port_param);
    setup_val.set(&setup_param);
    connector_val.set(&connector_param);

    module.begin("tcp_connector", 0, nullptr);
    module.begin("tcp_connector", 1, nullptr);
    module.set("tcp_connector.base_port", base_port_val, nullptr);
    module.set("tcp_connector.address", address_val, nullptr);
    module.set("tcp_connector.connector", connector_val, nullptr);
    module.set("tcp_connector.setup", setup_val, nullptr);
    module.end("tcp_connector", 1, nullptr);
    module.end("tcp_connector", 0, nullptr);

    TcpConnectorConfig::TcpConnectorConfigSet* config_set = module.get_and_clear_config();

    CHECK(config_set != nullptr);

    CHECK(config_set->size() == 1);

    TcpConnectorConfig config = *(config_set->front());
    CHECK(config.base_port == 10000);
    CHECK(config.address == "127.0.0.1");
    CHECK(config.setup == TcpConnectorConfig::Setup::CALL);
    CHECK(config.connector_name == "tcp-c");
    CHECK(config.direction == Connector::CONN_DUPLEX);

    CHECK(module.get_pegs() != nullptr );
    CHECK(module.get_counts() != nullptr );
    CHECK(module.get_profile() != nullptr );

    for ( auto conf : *config_set )
        delete conf;

    config_set->clear();
    delete config_set;
}

TEST(tcp_connector_module, test_answer)
{
    Value connector_val("tcp-a");
    Value base_port_val((double)20000);
    Value setup_val("answer");
    Parameter connector_param =
        {"connector", Parameter::PT_STRING, nullptr, nullptr, "connector"};
    Parameter base_port_param =
        {"base_port", Parameter::PT_PORT, nullptr, nullptr, "base_port"};
    Parameter setup_param =
        {"setup", Parameter::PT_ENUM, "call | answer", nullptr, "establishment"};

    TcpConnectorModule module;

    base_port_val.set(&base_port_param);
    CHECK( base_port_param.validate(base_port_val) == true );
    setup_val.set(&setup_param);
    CHECK( setup_param.validate(setup_val) == true );
    connector_val.set(&connector_param);
    CHECK( connector_param.validate(connector_val) == true );

    module.begin("tcp_connector", 0, nullptr);
    module.begin("tcp_connector", 1, nullptr);
    module.set("tcp_connector.base_port", base_port_val, nullptr);
    module.set("tcp_connector.connector", connector_val, nullptr);
    module.set("tcp_connector.setup", setup_val, nullptr);
    module.end("tcp_connector", 1, nullptr);
    module.end("tcp_connector", 0, nullptr);

    TcpConnectorConfig::TcpConnectorConfigSet* config_set = module.get_and_clear_config();

    CHECK(config_set != nullptr);

    CHECK(config_set->size() == 1);

    TcpConnectorConfig config = *(config_set->front());
    CHECK(config.base_port == 20000);
//    CHECK(config.setup == TcpConnectorConfig::Setup::ANSWER);
    CHECK(config.connector_name == "tcp-a");
    CHECK(config.direction == Connector::CONN_DUPLEX);

    for ( auto conf : *config_set )
        delete conf;

    config_set->clear();
    delete config_set;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

