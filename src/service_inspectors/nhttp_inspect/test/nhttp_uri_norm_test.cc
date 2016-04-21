//--------------------------------------------------------------------------
// Copyright (C) 2016 Cisco and/or its affiliates. All rights reserved.
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

// nhttp_uri_norm_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#include "log/messages.h"
#include "service_inspectors/nhttp_inspect/nhttp_uri_norm.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

void ParseWarning(WarningGroup, const char*, ...) {}
void ParseError(const char*, ...) {}
void show_stats(unsigned long*, PegInfo const*, unsigned int, char const*) {}
void show_stats(unsigned long*, PegInfo const*, std::vector<unsigned int, std::allocator<unsigned int> >&, char const*, _IO_FILE*) {}
void Value::get_bits(std::bitset<256ul>&) const {}
int SnortEventqAdd(unsigned int, unsigned int, RuleType) { return 0; }

TEST_GROUP(nhttp_inspect_uri_norm) { };

TEST(nhttp_inspect_uri_norm, normalize)
{
    Field input(20, (const uint8_t*) "/uri//to/%6eormalize");
    Field result;
    uint8_t buffer[100];
    NHttpParaList::UriParam uri_param;
    NHttpInfractions infractions;
    NHttpEventGen events;

    UriNormalizer::normalize(input, result, true, buffer, uri_param, infractions, events);
    CHECK(result.length == 17);
    CHECK(memcmp(result.start, "/uri/to/normalize", 17) == 0);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

