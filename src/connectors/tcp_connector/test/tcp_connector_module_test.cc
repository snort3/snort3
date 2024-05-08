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

// tcp_connector_module_test.cc author Ed Borgoyn <eborgoyn@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "connectors/tcp_connector/tcp_connector_module.h"
#include "main/thread_config.h"
#include "profiler/profiler.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;


THREAD_LOCAL SimpleStats tcp_connector_stats;
THREAD_LOCAL ProfileStats tcp_connector_perfstats;

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }

namespace snort
{
char* snort_strdup(const char* s)
{ return strdup(s); }

unsigned get_instance_id()
{ return 0; }
unsigned ThreadConfig::get_instance_max() { return 1; }
}

TEST_GROUP(tcp_connector_module)
{
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

    CHECK(nullptr != config_set);

    CHECK(1 == config_set->size());

    TcpConnectorConfig config = *(config_set->front());
    CHECK(10000 == config.base_port);
    CHECK("127.0.0.1" == config.address);
    CHECK(TcpConnectorConfig::Setup::CALL == config.setup);
    CHECK("tcp-c" == config.connector_name);
    CHECK(Connector::CONN_DUPLEX == config.direction);

    CHECK(nullptr != module.get_pegs());
    CHECK(nullptr != module.get_counts());
    CHECK(nullptr != module.get_profile());

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
    CHECK( true == base_port_param.validate(base_port_val) );
    setup_val.set(&setup_param);
    CHECK( true == setup_param.validate(setup_val) );
    connector_val.set(&connector_param);
    CHECK( true == connector_param.validate(connector_val) );

    module.begin("tcp_connector", 0, nullptr);
    module.begin("tcp_connector", 1, nullptr);
    module.set("tcp_connector.base_port", base_port_val, nullptr);
    module.set("tcp_connector.connector", connector_val, nullptr);
    module.set("tcp_connector.setup", setup_val, nullptr);
    module.end("tcp_connector", 1, nullptr);
    module.end("tcp_connector", 0, nullptr);

    TcpConnectorConfig::TcpConnectorConfigSet* config_set = module.get_and_clear_config();

    CHECK(nullptr != config_set);

    CHECK(1 == config_set->size());

    TcpConnectorConfig config = *(config_set->front());
    CHECK(20000 == config.base_port);
//    CHECK(config.setup == TcpConnectorConfig::Setup::ANSWER);
    CHECK("tcp-a" == config.connector_name);
    CHECK(Connector::CONN_DUPLEX == config.direction);

    for ( auto conf : *config_set )
        delete conf;

    config_set->clear();
    delete config_set;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

