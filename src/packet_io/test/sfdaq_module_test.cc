//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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


TEST_CASE("parse sfdaq config", "[SFDAQModule]")
{
    SnortConfig sc;
    SFDAQModule sfdm;

    /* Generate the configuration */
    sfdm.begin("daq", 0, &sc);

    Value module_dir1("/test/dir/1");
    CHECK(sfdm.set("daq.module_dirs", module_dir1, &sc));

    Value module_dir2("/test/dir/2");
    CHECK(sfdm.set("daq.module_dirs", module_dir2, &sc));

    Value input1("test_input1");
    CHECK(sfdm.set("daq.inputs", input1, &sc));

    Value input2("test_input2");
    CHECK(sfdm.set("daq.inputs", input2, &sc));

    Value input3("test_input3");
    CHECK(sfdm.set("daq.inputs", input3, &sc));

    Value snaplen(static_cast<double>(6666));
    CHECK(sfdm.set("daq.snaplen", snaplen, &sc));

    Value batch_size(static_cast<double>(10));
    CHECK(sfdm.set("daq.batch_size", batch_size, &sc));

    CHECK(sfdm.begin("daq.modules", 0, &sc));

    SECTION("empty module config")
    {
        // Empty module table entry should fail
        CHECK(sfdm.begin("daq.modules", 1, &sc));
        CHECK_FALSE(sfdm.end("daq.modules", 1, &sc));
    }

    CHECK(sfdm.begin("daq.modules", 2, &sc));

    Value module_name("dump");
    CHECK(sfdm.set("daq.modules.name", module_name, &sc));

    Value mode_val("passive");
    Parameter mode_param = { "mode", Parameter::PT_ENUM, "passive | inline | read-file", "passive", "DAQ module mode" };
    mode_val.set(&mode_param);
    CHECK(sfdm.set("daq.modules.mode", mode_val, &sc));

    Value dump_var1("dump_var1=foo");
    CHECK(sfdm.set("daq.modules.variables", dump_var1, &sc));

    Value dump_var2("dump_var2");
    CHECK(sfdm.set("daq.modules.variables", dump_var2, &sc));

    CHECK(sfdm.end("daq.modules", 2, &sc));
    CHECK(sfdm.end("daq.modules", 0, &sc));
    CHECK(sfdm.end("daq", 0, &sc));

    SECTION("validate sfdaq config")
    {
        /* Validate the configuration */
        SFDAQConfig* cfg = sc.daq_config;
        REQUIRE((cfg->module_dirs.size() == 2));
        CHECK(cfg->module_dirs[0] == module_dir1.get_string());
        CHECK(cfg->module_dirs[1] == module_dir2.get_string());

        REQUIRE((cfg->inputs.size() == 3));
        CHECK(cfg->inputs[0] == input1.get_string());
        CHECK(cfg->inputs[1] == input2.get_string());
        CHECK(cfg->inputs[2] == input3.get_string());

        CHECK((cfg->mru_size == 6666));
        CHECK((cfg->batch_size == 10));

        REQUIRE(cfg->module_configs.size() == 1);
        for (auto it : cfg->module_configs)
        {
            SFDAQModuleConfig* mcfg = it;
            CHECK((mcfg->name == module_name.get_string()));
            CHECK((mcfg->mode == SFDAQModuleConfig::SFDAQ_MODE_PASSIVE));
            REQUIRE((mcfg->variables.size() == 2));
            CHECK(mcfg->variables[0].first == "dump_var1");
            CHECK(mcfg->variables[0].second == "foo");
            CHECK(mcfg->variables[1].first == dump_var2.get_string());
            CHECK(mcfg->variables[1].second.empty());
        }
    }

    SECTION("sfdaq command line config and overlay verification")
    {
        /* Secondary config to overlay from, for example, the command line */
        SFDAQConfig overlay_cfg;

        overlay_cfg.add_module_dir("cli_module_dir");
        overlay_cfg.add_input("cli_input");
        overlay_cfg.set_mru_size(3333);
        overlay_cfg.set_batch_size(12);

        SFDAQModuleConfig* cli_module_cfg = overlay_cfg.add_module_config("cli_module_name");

        cli_module_cfg->set_variable("cli_module_variable=abc");
        cli_module_cfg->mode = SFDAQModuleConfig::SFDAQ_MODE_READ_FILE;

        SFDAQModuleConfig* cli_dump_cfg = overlay_cfg.add_module_config("dump");

        cli_dump_cfg->mode = SFDAQModuleConfig::SFDAQ_MODE_INLINE;
        cli_dump_cfg->set_variable("dump_var3");
        cli_dump_cfg->set_variable("dump_var4=bar");
        cli_dump_cfg->set_variable("dump_var5=foo");

        SFDAQConfig* cfg = sc.daq_config;
        cfg->overlay(&overlay_cfg);

        REQUIRE(cfg->module_dirs.size() == 1);
        CHECK(cfg->module_dirs[0] == "cli_module_dir");

        REQUIRE((cfg->inputs.size() == 1));
        CHECK(cfg->inputs[0] == "cli_input");

        CHECK((cfg->mru_size == 3333));
        CHECK((cfg->batch_size == 12));

        REQUIRE(cfg->module_configs.size() == 2);
        for (auto it : cfg->module_configs)
        {
            SFDAQModuleConfig* mcfg = it;
            CHECK((mcfg->name == "cli_module_name" or mcfg->name == "dump"));
            if (mcfg->name == "cli_module_name")
            {
                CHECK(mcfg->mode == SFDAQModuleConfig::SFDAQ_MODE_READ_FILE);
                REQUIRE((mcfg->variables.size() == 1));
                CHECK(mcfg->variables[0].first == "cli_module_variable");
                CHECK(mcfg->variables[0].second == "abc");
            }
            else if (mcfg->name == "dump")
            {
                CHECK(mcfg->mode == SFDAQModuleConfig::SFDAQ_MODE_INLINE);
                REQUIRE((mcfg->variables.size() == 3));
                CHECK(mcfg->variables[0].first == "dump_var3");
                CHECK(mcfg->variables[0].second.empty());
                CHECK(mcfg->variables[1].first == "dump_var4");
                CHECK(mcfg->variables[1].second == "bar");
                CHECK(mcfg->variables[2].first == "dump_var5");
                CHECK(mcfg->variables[2].second == "foo");
            }
        }
    }
}
