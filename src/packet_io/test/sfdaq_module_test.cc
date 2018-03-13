//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// sfdaq_module_test.cc author Michael Altizer <mialtize@cisco.com>

// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/snort_catch.h"
#include "main/snort_config.h"
#include "packet_io/sfdaq_config.h"
#include "packet_io/sfdaq_module.h"

using namespace snort;

TEST_CASE("Kitchen Sink", "[SFDAQModule]")
{
    SFDAQModule sfdm;
    SnortConfig sc;

    /* Generate the configuration */
    sfdm.begin("daq", 0, &sc);

    Value module_dir1("/test/dir/1");
    Value module_dir2("/test/dir/2");
    CHECK(sfdm.set("daq.module_dirs", module_dir1, &sc));
    CHECK(sfdm.set("daq.module_dirs", module_dir2, &sc));

    Value module_name("test_module");
    CHECK(sfdm.set("daq.module", module_name, &sc));

    Value input_spec("test_input");
    CHECK(sfdm.set("daq.input_spec", input_spec, &sc));

    Value var1("foo=bar");
    Value var2("debug");
    Value var3("hello=world");
    CHECK(sfdm.set("daq.variables", var1, &sc));
    CHECK(sfdm.set("daq.variables", var2, &sc));
    CHECK(sfdm.set("daq.variables", var3, &sc));

    Value snaplen(static_cast<double>(6666));
    CHECK(sfdm.set("daq.snaplen", snaplen, &sc));

    Value no_promisc(true);
    CHECK(sfdm.set("daq.no_promisc", no_promisc, &sc));

    CHECK(sfdm.begin("daq.instances", 0, &sc));
    CHECK(sfdm.begin("daq.instances", 1, &sc));

    CHECK_FALSE(sfdm.end("daq.instances", 1, &sc));
    CHECK(sfdm.begin("daq.instances", 2, &sc));

    Value instance_id(static_cast<double>(5));
    CHECK(sfdm.set("daq.instances.id", instance_id, &sc));

    Value instance_input_spec("instance_5_input");
    CHECK(sfdm.set("daq.instances.input_spec", instance_input_spec, &sc));

    Value instance_var1("instance5_var1=foo");
    Value instance_var2("instance5_var2");
    CHECK(sfdm.set("daq.instances.variables", instance_var1, &sc));
    CHECK(sfdm.set("daq.instances.variables", instance_var2, &sc));

    CHECK(sfdm.end("daq.instances", 2, &sc));
    CHECK(sfdm.end("daq.instances", 0, &sc));
    CHECK(sfdm.end("daq", 0, &sc));

    /* Validate the configuration */
    SFDAQConfig *cfg = sc.daq_config;

    REQUIRE((cfg->module_dirs.size() == 2));
    CHECK(cfg->module_dirs[0] == module_dir1.get_string());
    CHECK(cfg->module_dirs[1] == module_dir2.get_string());

    CHECK(cfg->module_name == module_name.get_string());

    CHECK(cfg->input_spec == input_spec.get_string());

    REQUIRE((cfg->variables.size() == 3));
    CHECK(cfg->variables[0].first == "foo");
    CHECK(cfg->variables[0].second == "bar");
    CHECK(cfg->variables[1].first == "debug");
    CHECK(cfg->variables[1].second.empty());
    CHECK(cfg->variables[2].first == "hello");
    CHECK(cfg->variables[2].second == "world");

    CHECK((cfg->mru_size == 6666));

    REQUIRE(cfg->instances.size() == 1);
    for (auto it : cfg->instances)
    {
        CHECK((it.first == 5));
        SFDAQInstanceConfig* icfg = it.second;
        CHECK(icfg->input_spec == instance_input_spec.get_string());
        REQUIRE((icfg->variables.size() == 2));
        CHECK(icfg->variables[0].first == "instance5_var1");
        CHECK(icfg->variables[0].second == "foo");
        CHECK(icfg->variables[1].first == instance_var2.get_string());
        CHECK(icfg->variables[1].second.empty());
    }

    /* Secondary config to overlay from, for example, the command line */
    SnortConfig sc2;

    sc2.daq_config->add_module_dir("cli_module_dir");
    sc2.daq_config->set_module_name("cli_module_name");
    sc2.daq_config->set_input_spec(nullptr);
    sc2.daq_config->set_input_spec("cli_input_spec");
    sc2.daq_config->set_variable("cli_global_variable=abc");
    sc2.daq_config->set_mru_size(3333);
    sc2.daq_config->set_input_spec(nullptr, 2);
    sc2.daq_config->set_input_spec("cli_instance_2_input", 2);
    sc2.daq_config->set_input_spec("cli_instance_5_input", 5);
    sc2.daq_config->set_variable("cli_instance_5_var1=def", 5);

    cfg->overlay(sc2.daq_config);

    REQUIRE(cfg->module_dirs.size() == 1);
    CHECK(cfg->module_dirs[0] == "cli_module_dir");
    CHECK(cfg->module_name == "cli_module_name");
    CHECK(cfg->input_spec == "cli_input_spec");
    REQUIRE(cfg->variables.size() == 1);
    CHECK(cfg->variables[0].first == "cli_global_variable");
    CHECK(cfg->variables[0].second == "abc");
    CHECK((cfg->mru_size == 3333));
    REQUIRE((cfg->instances.size() == 2));
    for (auto it : cfg->instances)
    {
        CHECK((it.first == 2 || it.first == 5));
        if (it.first == 2)
        {
            SFDAQInstanceConfig* icfg = it.second;
            CHECK(icfg->input_spec == "cli_instance_2_input");
            CHECK(icfg->variables.empty());
        }
        else if (it.first == 5)
        {
            SFDAQInstanceConfig* icfg = it.second;
            CHECK(icfg->input_spec == "cli_instance_5_input");
            REQUIRE(icfg->variables.size() == 1);
            CHECK(icfg->variables[0].first == "cli_instance_5_var1");
            CHECK(icfg->variables[0].second == "def");
        }
    }
}

