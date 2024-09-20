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
// extractor_logger.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_logger.h"

#include <cassert>

#include "extractor_csv_logger.h"
#include "extractor_json_logger.h"

ExtractorLogger* ExtractorLogger::make_logger(FormatType f_type, OutputType o_type)
{
    ExtractorLogger* logger = nullptr;

    switch (f_type)
    {
    case FormatType::CSV:
        logger = new CsvExtractorLogger(o_type);
        break;
    case FormatType::JSON:
        logger = new JsonExtractorLogger(o_type);
        break;
    case FormatType::MAX: // fallthrough
    default:
        break;
    }

    assert(logger);

    return logger;
}

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

#include <memory.h>

using namespace snort;

TEST_CASE("Format Type", "[extractor]")
{
    SECTION("to string")
    {
        FormatType csv = FormatType::CSV;
        FormatType json = FormatType::JSON;
        FormatType max = FormatType::MAX;

        CHECK_FALSE(strcmp("csv", csv.c_str()));
        CHECK_FALSE(strcmp("json", json.c_str()));
        CHECK_FALSE(strcmp("(not set)", max.c_str()));
    }
}

#endif
