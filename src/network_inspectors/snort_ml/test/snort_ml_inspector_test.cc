//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// snort_ml_inspector_test.cc author Samaresh Kumar Singh <ssam3003@gmail.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>
#include <cstdint>
#include <limits>

#include "catch/catch.hpp"

static inline size_t clamped_depth(int32_t cfg, int32_t actual)
{
    if (actual <= 0)
        return 0;
    if (cfg < 0)
        return static_cast<size_t>(actual);
    return std::min(static_cast<size_t>(cfg), static_cast<size_t>(actual));
}

//--------------------------------------------------------------------------
// clamped_depth
//
// cfg = -1 means "unlimited" so the result is the actual length;
// actual <= 0 means "nothing to scan" so the result is 0;
// otherwise it is the smaller of cfg and actual. Casting -1 to size_t
// previously produced SIZE_MAX which only worked by accident inside
// std::min; these tests pin the explicit semantics in place.
//--------------------------------------------------------------------------

TEST_CASE("SnortML clamped_depth unlimited cfg uses actual", "[snort_ml]")
{
    REQUIRE(clamped_depth(-1, 100) == 100u);
    REQUIRE(clamped_depth(-1, 1) == 1u);
}

TEST_CASE("SnortML clamped_depth zero actual returns zero", "[snort_ml]")
{
    REQUIRE(clamped_depth(-1, 0) == 0u);
    REQUIRE(clamped_depth(0, 0) == 0u);
    REQUIRE(clamped_depth(100, 0) == 0u);
}

TEST_CASE("SnortML clamped_depth negative actual returns zero", "[snort_ml]")
{
    REQUIRE(clamped_depth(-1, -5) == 0u);
    REQUIRE(clamped_depth(100, -1) == 0u);
}

TEST_CASE("SnortML clamped_depth cfg below actual", "[snort_ml]")
{
    REQUIRE(clamped_depth(50, 200) == 50u);
}

TEST_CASE("SnortML clamped_depth cfg above actual", "[snort_ml]")
{
    REQUIRE(clamped_depth(500, 200) == 200u);
}

TEST_CASE("SnortML clamped_depth cfg equals actual", "[snort_ml]")
{
    REQUIRE(clamped_depth(200, 200) == 200u);
}

TEST_CASE("SnortML clamped_depth max int32 actual", "[snort_ml]")
{
    REQUIRE(clamped_depth(-1, std::numeric_limits<int32_t>::max())
        == static_cast<size_t>(std::numeric_limits<int32_t>::max()));
}
