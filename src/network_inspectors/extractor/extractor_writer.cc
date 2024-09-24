//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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
// extractor_writer.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_writer.h"

using namespace snort;

ExtractorWriter* ExtractorWriter::make_writer(OutputType o_type)
{
    switch (o_type)
    {
    case OutputType::STD:
        return new StdExtractorWriter();
    case OutputType::MAX: // fallthrough
    default:
        return nullptr;
    }
}

StdExtractorWriter::StdExtractorWriter() : ExtractorWriter(), extr_std_log(TextLog_Init("stdout"))
{}

StdExtractorWriter::~StdExtractorWriter()
{
    TextLog_Term(extr_std_log);
}

void StdExtractorWriter::write(const char* ss)
{
    TextLog_Print(extr_std_log, "%s", ss);
}

void StdExtractorWriter::write(const char* ss, size_t len)
{
    TextLog_Print(extr_std_log, "%.*s", (int)len, ss);
}

void StdExtractorWriter::write(uint64_t n)
{
    TextLog_Print(extr_std_log, STDu64, n);
}

void StdExtractorWriter::lock()
{
    write_mutex.lock();
}

void StdExtractorWriter::unlock()
{
    TextLog_Flush(extr_std_log); // FIXIT-L: should be a part of API and have a well-defined point in the pipeline
    write_mutex.unlock();
}

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

#include <memory.h>

using namespace snort;

TEST_CASE("Output Type", "[extractor]")
{
    SECTION("to string")
    {
        OutputType std = OutputType::STD;
        OutputType max = OutputType::MAX;

        CHECK_FALSE(strcmp("stdout", std.c_str()));
        CHECK_FALSE(strcmp("(not set)", max.c_str()));
    }
}

#endif
