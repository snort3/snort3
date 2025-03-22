//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// unixdomain_connector_module_test.cc author Umang Sharma <umasharm@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "connectors/unixdomain_connector/unixdomain_connector_module.h"
#include "main/thread_config.h"
#include "profiler/profiler.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;


THREAD_LOCAL SimpleStats unixdomain_connector_stats;
THREAD_LOCAL ProfileStats unixdomain_connector_perfstats;

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }

unsigned instance_max = 1;
namespace snort
{
char* snort_strdup(const char* s)
{ return strdup(s); }

unsigned get_instance_id()
{ return 0; }

unsigned ThreadConfig::get_instance_max()
{ return instance_max; }

void ParseError(const char*, ...) { }
}

TEST_GROUP(unixdomain_connector_module)
{
};

TEST(unixdomain_connector_module, test_call)
{
    Value connector_val("unixdomain-c");
    Value base_path_val("/tmp/pub_sub1 /tmp/pub_sub2");
    Value setup_val("call");

    Parameter connector_param =
        {"connector", Parameter::PT_STRING, nullptr, nullptr, "connector"};
    Parameter base_path_param =
        {"paths", Parameter::PT_STR_LIST, nullptr, nullptr, "list of paths"};
    Parameter setup_param =
        {"setup", Parameter::PT_ENUM, "call | answer", nullptr, "establishment"};

    UnixDomainConnectorModule module;

    base_path_val.set(&base_path_param);
    CHECK(true == base_path_param.validate(base_path_val));
    setup_val.set(&setup_param);
    CHECK(true == setup_param.validate(setup_val));
    connector_val.set(&connector_param);
    CHECK(true == connector_param.validate(connector_val));

    instance_max = 2;

    CHECK(module.begin("unixdomain_connector", 0, nullptr));
    CHECK(module.begin("unixdomain_connector", 1, nullptr));
    CHECK(module.set("unixdomain_connector.paths", base_path_val, nullptr));
    CHECK(module.set("unixdomain_connector.connector", connector_val, nullptr));
    CHECK(module.set("unixdomain_connector.setup", setup_val, nullptr));
    CHECK(module.end("unixdomain_connector", 1, nullptr));
    CHECK(module.end("unixdomain_connector", 0, nullptr));

    ConnectorConfig::ConfigSet config_set = module.get_and_clear_config();

    CHECK(1 == config_set.size());

    const UnixDomainConnectorConfig& config  = static_cast<const UnixDomainConnectorConfig&>(*config_set.front());
    CHECK("/tmp/pub_sub1" == config.paths[0]);
    CHECK("/tmp/pub_sub2" == config.paths[1]);
    CHECK(UnixDomainConnectorConfig::Setup::CALL == config.setup);
    CHECK("unixdomain-c" == config.connector_name);
    CHECK(Connector::CONN_DUPLEX == config.direction);

    CHECK(nullptr != module.get_pegs());
    CHECK(nullptr != module.get_counts());
    CHECK(nullptr != module.get_profile());
}

TEST(unixdomain_connector_module, test_paths_count_failure)
{
    Value connector_val("unixdomain-a");
    Value base_path_val("/tmp/pub_sub1");
    Value setup_val("answer");
    Parameter connector_param =
        {"connector", Parameter::PT_STRING, nullptr, nullptr, "connector"};
    Parameter base_path_param =
        {"paths", Parameter::PT_STR_LIST, nullptr, nullptr, "list of paths"};
    Parameter setup_param =
        {"setup", Parameter::PT_ENUM, "call | answer", nullptr, "establishment"};

    UnixDomainConnectorModule module;

    base_path_val.set(&base_path_param);
    CHECK(true == base_path_param.validate(base_path_val));
    setup_val.set(&setup_param);
    CHECK(true == setup_param.validate(setup_val));
    connector_val.set(&connector_param);
    CHECK(true == connector_param.validate(connector_val));

    CHECK(module.begin("unixdomain_connector", 0, nullptr));
    CHECK(module.begin("unixdomain_connector", 1, nullptr));
    CHECK(module.set("unixdomain_connector.paths", base_path_val, nullptr));
    CHECK(module.set("unixdomain_connector.connector", connector_val, nullptr));
    CHECK(module.set("unixdomain_connector.setup", setup_val, nullptr));
    CHECK(module.end("unixdomain_connector", 1, nullptr));
    CHECK(module.end("unixdomain_connector", 0, nullptr));

    ConnectorConfig::ConfigSet config_set = module.get_and_clear_config();

    CHECK(1 == config_set.size());

    const UnixDomainConnectorConfig& config  = static_cast<const UnixDomainConnectorConfig&>(*config_set.front());
    CHECK("/tmp/pub_sub1" == config.paths[0]);
    CHECK(config.setup == UnixDomainConnectorConfig::Setup::ANSWER);
    CHECK("unixdomain-a" == config.connector_name);
    CHECK(Connector::CONN_DUPLEX == config.direction);
}

TEST(unixdomain_connector_module, test_answer)
{
    Value connector_val("unixdomain-a");
    Value base_path_val("/tmp/pub_sub1 /tmp/pub_sub2");
    Value setup_val("answer");
    Parameter connector_param =
        {"connector", Parameter::PT_STRING, nullptr, nullptr, "connector"};
    Parameter base_path_param =
        {"paths", Parameter::PT_STR_LIST, nullptr, nullptr, "list of paths"};
    Parameter setup_param =
        {"setup", Parameter::PT_ENUM, "call | answer", nullptr, "establishment"};

    UnixDomainConnectorModule module;

    base_path_val.set(&base_path_param);
    CHECK(true == base_path_param.validate(base_path_val));
    setup_val.set(&setup_param);
    CHECK(true == setup_param.validate(setup_val));
    connector_val.set(&connector_param);
    CHECK(true == connector_param.validate(connector_val));

    instance_max = 3;
    CHECK(module.begin("unixdomain_connector", 0, nullptr));
    CHECK(module.begin("unixdomain_connector", 1, nullptr));
    CHECK(module.set("unixdomain_connector.paths", base_path_val, nullptr));
    CHECK(module.set("unixdomain_connector.connector", connector_val, nullptr));
    CHECK(module.set("unixdomain_connector.setup", setup_val, nullptr));
    CHECK(module.end("unixdomain_connector", 1, nullptr) == false);
    CHECK(module.end("unixdomain_connector", 0, nullptr));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

