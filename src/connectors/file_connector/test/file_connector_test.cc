//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// file_connector_test.cc author Ed Borgoyn <eborgoyn@cisco.com>
// unit test main

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "connectors/file_connector/file_connector.h"
#include "connectors/file_connector/file_connector_module.h"

#include "main/snort_debug.h"

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }

void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*) { }

void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }

const char* get_instance_file(std::string& file, const char* name)
{ UNUSED(file); UNUSED(name); return "filename"; }

void Debug::print(const char*, int, uint64_t, const char*, ...) { }

TEST_GROUP(file_connector_msg_handle)
{
};

TEST(file_connector_msg_handle, test)
{
    FileConnectorMsgHandle* handle = nullptr;
    handle = new FileConnectorMsgHandle(12);
    CHECK(handle != nullptr);
    CHECK(handle->connector_msg.length == 12);
    CHECK(handle->connector_msg.data != nullptr);
    delete handle;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

