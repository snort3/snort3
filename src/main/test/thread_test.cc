//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "main/thread_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

//-------------------------------------------------------------------------
// stubs
//-------------------------------------------------------------------------

static unsigned s_instance_max = 1;

namespace snort
{
static SnortConfig snort_conf;

SnortConfig::SnortConfig(const char*)
{
    daq_config = nullptr;
    thread_config = nullptr;
}

SnortConfig::~SnortConfig() = default;

const SnortConfig* SnortConfig::get_conf()
{ return &snort_conf; }

void ParseError(const char*, ...) { }

const char* get_error(int)
{ return ""; }

unsigned ThreadConfig::get_instance_max()
{ return s_instance_max; }

int ThreadConfig::get_instance_tid(int)
{ return 0; }

unsigned Snort::get_process_id()
{ return 0; }
} // namespace snort

using namespace snort;

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

static void reset_conf()
{
    snort_conf.log_dir.clear();
    snort_conf.run_prefix.clear();
    snort_conf.id_offset = 0;
    snort_conf.id_subdir = false;
    snort_conf.id_zero = false;
    s_instance_max = 1;
    set_instance_id(0);
}

//-------------------------------------------------------------------------
// get_instance_file tests
//-------------------------------------------------------------------------

TEST_GROUP(get_instance_file_tests)
{
    void setup() override { reset_conf(); }
};

TEST(get_instance_file_tests, default_path)
{
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("./name", file.c_str());
}

TEST(get_instance_file_tests, log_dir)
{
    snort_conf.log_dir = "/tmp/logs/";
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/logs/name", file.c_str());
}

TEST(get_instance_file_tests, log_dir_no_trailing_slash)
{
    snort_conf.log_dir = "/tmp/logs";
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/logs/name", file.c_str());
}

TEST(get_instance_file_tests, run_prefix)
{
    snort_conf.run_prefix = "snort";
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("./snort_name", file.c_str());
}

TEST(get_instance_file_tests, multi_thread)
{
    s_instance_max = 4;
    set_instance_id(2);
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("./2_name", file.c_str());
}

TEST(get_instance_file_tests, id_zero)
{
    snort_conf.id_zero = true;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("./0_name", file.c_str());
}

TEST(get_instance_file_tests, id_offset)
{
    s_instance_max = 2;
    snort_conf.id_offset = 10;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("./10_name", file.c_str());
}

TEST(get_instance_file_tests, run_prefix_multi_thread)
{
    snort_conf.run_prefix = "p";
    s_instance_max = 2;
    set_instance_id(1);
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("./p1_name", file.c_str());
}

TEST(get_instance_file_tests, id_subdir)
{
    snort_conf.log_dir = "/tmp";
    s_instance_max = 2;
    snort_conf.id_subdir = true;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/0/name", file.c_str());
}

TEST(get_instance_file_tests, log_dir_run_prefix)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.run_prefix = "p";
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/p_name", file.c_str());
}

TEST(get_instance_file_tests, log_dir_id_zero)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.id_zero = true;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/0_name", file.c_str());
}

TEST(get_instance_file_tests, log_dir_run_prefix_multi_thread)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.run_prefix = "p";
    s_instance_max = 2;
    set_instance_id(1);
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/p1_name", file.c_str());
}

TEST(get_instance_file_tests, run_prefix_id_zero)
{
    snort_conf.run_prefix = "p";
    snort_conf.id_zero = true;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("./p0_name", file.c_str());
}

TEST(get_instance_file_tests, run_prefix_id_offset)
{
    snort_conf.run_prefix = "p";
    s_instance_max = 2;
    snort_conf.id_offset = 10;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("./p10_name", file.c_str());
}

TEST(get_instance_file_tests, run_prefix_id_subdir)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.run_prefix = "p";
    s_instance_max = 2;
    snort_conf.id_subdir = true;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/p0/name", file.c_str());
}

TEST(get_instance_file_tests, id_zero_id_offset)
{
    snort_conf.id_zero = true;
    snort_conf.id_offset = 10;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("./10_name", file.c_str());
}

TEST(get_instance_file_tests, id_subdir_id_zero)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.id_zero = true;
    snort_conf.id_subdir = true;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/0/name", file.c_str());
}

TEST(get_instance_file_tests, multi_thread_id_offset_nonzero_id)
{
    s_instance_max = 4;
    set_instance_id(2);
    snort_conf.id_offset = 10;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("./12_name", file.c_str());
}

TEST(get_instance_file_tests, id_offset_id_subdir)
{
    snort_conf.log_dir = "/tmp";
    s_instance_max = 2;
    snort_conf.id_offset = 10;
    snort_conf.id_subdir = true;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/10/name", file.c_str());
}

TEST(get_instance_file_tests, run_prefix_id_zero_id_offset)
{
    snort_conf.run_prefix = "p";
    snort_conf.id_zero = true;
    snort_conf.id_offset = 10;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("./p10_name", file.c_str());
}

TEST(get_instance_file_tests, run_prefix_id_zero_id_subdir)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.run_prefix = "p";
    snort_conf.id_zero = true;
    snort_conf.id_subdir = true;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/p0/name", file.c_str());
}

TEST(get_instance_file_tests, run_prefix_id_offset_id_subdir)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.run_prefix = "p";
    s_instance_max = 2;
    snort_conf.id_offset = 10;
    snort_conf.id_subdir = true;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/p10/name", file.c_str());
}

TEST(get_instance_file_tests, id_zero_id_offset_id_subdir)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.id_zero = true;
    snort_conf.id_offset = 10;
    snort_conf.id_subdir = true;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/10/name", file.c_str());
}

TEST(get_instance_file_tests, run_prefix_id_zero_id_offset_id_subdir)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.run_prefix = "p";
    snort_conf.id_zero = true;
    snort_conf.id_offset = 10;
    snort_conf.id_subdir = true;
    std::string file;
    get_instance_file(file, "name");
    STRCMP_EQUAL("/tmp/p10/name", file.c_str());
}

//-------------------------------------------------------------------------
// get_main_file tests
//-------------------------------------------------------------------------

TEST_GROUP(get_main_file_tests)
{
    void setup() override { reset_conf(); }
};

TEST(get_main_file_tests, default_path)
{
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("./main_name", file.c_str());
}

TEST(get_main_file_tests, log_dir)
{
    snort_conf.log_dir = "/tmp/logs/";
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("/tmp/logs/main_name", file.c_str());
}

TEST(get_main_file_tests, log_dir_no_trailing_slash)
{
    snort_conf.log_dir = "/tmp/logs";
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("/tmp/logs/main_name", file.c_str());
}

TEST(get_main_file_tests, run_prefix)
{
    snort_conf.run_prefix = "snort";
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("./snortmain_name", file.c_str());
}

TEST(get_main_file_tests, id_zero)
{
    snort_conf.id_zero = true;
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("./name", file.c_str());
}

TEST(get_main_file_tests, run_prefix_id_zero)
{
    snort_conf.run_prefix = "snort";
    snort_conf.id_zero = true;
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("./snortname", file.c_str());
}

TEST(get_main_file_tests, log_dir_run_prefix)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.run_prefix = "p";
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("/tmp/pmain_name", file.c_str());
}

TEST(get_main_file_tests, log_dir_id_zero)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.id_zero = true;
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("/tmp/name", file.c_str());
}

TEST(get_main_file_tests, log_dir_run_prefix_id_zero)
{
    snort_conf.log_dir = "/tmp";
    snort_conf.run_prefix = "p";
    snort_conf.id_zero = true;
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("/tmp/pname", file.c_str());
}

TEST(get_main_file_tests, id_offset_ignored)
{
    snort_conf.id_offset = 10;
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("./main_name", file.c_str());
}

TEST(get_main_file_tests, id_subdir_ignored)
{
    snort_conf.id_subdir = true;
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("./main_name", file.c_str());
}

TEST(get_main_file_tests, multi_thread_ignored)
{
    s_instance_max = 4;
    set_instance_id(2);
    std::string file;
    get_main_file(file, "name");
    STRCMP_EQUAL("./main_name", file.c_str());
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
