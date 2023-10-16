//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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

// rna_ua_fp_processor_test.cc author Russ Combs <rucombs@cisco.com>

// The goal of these tests is to validate make_mpse priority. Given that rna
// adds fingerprints via module and makes mpse in configure and that util
// does both steps in configure, there are two possible init sequences that
// can occur based on the ordering of configure calls:
//
// Sequential:
//
// 1. rna adds fingerprints
// 2. rna makes mpse
// 3. util adds fingerprints
// 4. util makes mpse with priority - replaces
//
// Interleaved:
//
// 1. rna adds fingerprints
// 2. util adds fingerprints
// 3. util makes mpse with priority
// 4. rna makes mpse - no change

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>
#include <string>

#include "network_inspectors/rna/rna_fingerprint_ua.h"
#include "search_engines/search_tool.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

//--------------------------------------------------------------------------
// stubs and mocks
//--------------------------------------------------------------------------

static unsigned s_count, s_prep_count;
static std::string s_data, s_prep_data;

namespace snort
{
    SearchTool::SearchTool(bool)
    { s_prep_count = s_count = 0; }

    SearchTool::~SearchTool()
    {
        s_prep_count = s_count = 0;
        s_data.clear();
        s_prep_data.clear();
    }

    void SearchTool::add(const char* s, unsigned n, void*, bool, bool)
    {
        s_count++;
        s_data.append(s, n);
    }

    void SearchTool::prep()
    {
        s_prep_count = s_count;
        s_prep_data = s_data;
    }
}

//--------------------------------------------------------------------------
// tests
//--------------------------------------------------------------------------

TEST_GROUP(rna_ua_fp_processor_test)
{
    UaFpProcessor* ua_proc;

    void setup() override
    { ua_proc = new UaFpProcessor; }

    void teardown() override
    { delete ua_proc; }
};

TEST(rna_ua_fp_processor_test, sequential_setup)
{
    UaFingerprint fp;

    fp.user_agent = "Pink ";
    ua_proc->push_agent(fp);
    ua_proc->make_mpse();

    CHECK(s_prep_count == 1);

    fp.user_agent = "Floyd";
    ua_proc->push_agent(fp);
    ua_proc->make_mpse(true);

    CHECK(s_prep_count == 2);
    CHECK(s_prep_data == "Pink Floyd");
}

TEST(rna_ua_fp_processor_test, interleaved_setup)
{
    UaFingerprint fp;

    fp.user_agent = "Pink ";
    ua_proc->push_agent(fp);

    CHECK(s_prep_count == 0);

    fp.user_agent = "Floyd";
    ua_proc->push_agent(fp);
    ua_proc->make_mpse(true);

    CHECK(s_prep_count == 2);
    CHECK(s_prep_data == "Pink Floyd");

    ua_proc->make_mpse();

    CHECK(s_prep_count == 2);
    CHECK(s_prep_data == "Pink Floyd");
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
