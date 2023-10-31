//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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
    CHECK(true == sfdm.set("daq.module_dirs", module_dir1, &sc));

    Value module_dir2("/test/dir/2");
    CHECK(true == sfdm.set("daq.module_dirs", module_dir2, &sc));

    Value input1("test_input1");
    CHECK(true == sfdm.set("daq.inputs", input1, &sc));

    Value input2("test_input2");
    CHECK(true == sfdm.set("daq.inputs", input2, &sc));

    Value input3("test_input3");
    CHECK(true == sfdm.set("daq.inputs", input3, &sc));

    Value snaplen(static_cast<double>(6666));
    CHECK(true == sfdm.set("daq.snaplen", snaplen, &sc));

    Value batch_size(static_cast<double>(10));
    CHECK(true == sfdm.set("daq.batch_size", batch_size, &sc));

    CHECK(true == sfdm.begin("daq.modules", 0, &sc));

    SECTION("empty module config")
    {
        // Empty module table entry should fail
        CHECK(true == sfdm.begin("daq.modules", 1, &sc));
        CHECK(false == sfdm.end("daq.modules", 1, &sc));
    }

    CHECK(true == sfdm.begin("daq.modules", 2, &sc));

    Value module_name("dump");
    CHECK(true == sfdm.set("daq.modules.name", module_name, &sc));

    Value mode_val("passive");
    Parameter mode_param = { "mode", Parameter::PT_ENUM, "passive | inline | read-file", "passive", "DAQ module mode" };
    mode_val.set(&mode_param);
    CHECK(true == sfdm.set("daq.modules.mode", mode_val, &sc));

    Value dump_var1("dump_var1=foo");
    CHECK(true == sfdm.set("daq.modules.variables", dump_var1, &sc));

    Value dump_var2("dump_var2");
    CHECK(true == sfdm.set("daq.modules.variables", dump_var2, &sc));

    CHECK(true == sfdm.end("daq.modules", 2, &sc));
    CHECK(true == sfdm.end("daq.modules", 0, &sc));
    CHECK(true == sfdm.end("daq", 0, &sc));

    SECTION("validate sfdaq config")
    {
        /* Validate the configuration */
        SFDAQConfig* cfg = sc.daq_config;
        REQUIRE((2 == cfg->module_dirs.size()));
        CHECK(cfg->module_dirs[0] == module_dir1.get_string());
        CHECK(cfg->module_dirs[1] == module_dir2.get_string());

        REQUIRE((3 == cfg->inputs.size()));
        CHECK(cfg->inputs[0] == input1.get_string());
        CHECK(cfg->inputs[1] == input2.get_string());
        CHECK(cfg->inputs[2] == input3.get_string());

        CHECK((6666 == cfg->mru_size));
        CHECK((10 == cfg->batch_size));

        REQUIRE(1 == cfg->module_configs.size());
        for (auto it : cfg->module_configs)
        {
            SFDAQModuleConfig* mcfg = it;
            CHECK((mcfg->name == module_name.get_string()));
            CHECK((mcfg->mode == SFDAQModuleConfig::SFDAQ_MODE_PASSIVE));
            REQUIRE((2 == mcfg->variables.size()));
            CHECK("dump_var1" == mcfg->variables[0].first);
            CHECK("foo" == mcfg->variables[0].second);
            CHECK(mcfg->variables[1].first == dump_var2.get_string());
            CHECK(true == mcfg->variables[1].second.empty());
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

        REQUIRE(1 == cfg->module_dirs.size());
        CHECK("cli_module_dir" == cfg->module_dirs[0]);

        REQUIRE((1 == cfg->inputs.size()));
        CHECK("cli_input" == cfg->inputs[0]);

        CHECK((3333 == cfg->mru_size));
        CHECK((12 == cfg->batch_size));

        REQUIRE(2 == cfg->module_configs.size());
        for (auto it : cfg->module_configs)
        {
            SFDAQModuleConfig* mcfg = it;
            CHECK((mcfg->name == "cli_module_name" or mcfg->name == "dump"));
            if (mcfg->name == "cli_module_name")
            {
                CHECK(SFDAQModuleConfig::SFDAQ_MODE_READ_FILE == mcfg->mode);
                REQUIRE((1 == mcfg->variables.size()));
                CHECK("cli_module_variable" == mcfg->variables[0].first);
                CHECK("abc" == mcfg->variables[0].second);
            }
            else if (mcfg->name == "dump")
            {
                CHECK(SFDAQModuleConfig::SFDAQ_MODE_INLINE == mcfg->mode);
                REQUIRE((3 == mcfg->variables.size()));
                CHECK("dump_var3" == mcfg->variables[0].first);
                CHECK(true == mcfg->variables[0].second.empty());
                CHECK("dump_var4" == mcfg->variables[1].first);
                CHECK("bar" == mcfg->variables[1].second);
                CHECK("dump_var5" == mcfg->variables[2].first);
                CHECK("foo" == mcfg->variables[2].second);
            }
        }
    }
}
