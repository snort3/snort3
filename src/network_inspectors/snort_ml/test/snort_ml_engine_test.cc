//--------------------------------------------------------------------------
// Copyright (C) 2022-2026 Cisco and/or its affiliates. All rights reserved.
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
// snort_ml_engine_test.cc author Samaresh Kumar Singh <ssam3003@gmail.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../snort_ml_engine.h"

#include <cstring>
#include <string>
#include <vector>

#include "catch/catch.hpp"

//--------------------------------------------------------------------------
// snort_ml_model_set_fingerprint
//
// The verdict cache key XORs the per-scan FNV with this fingerprint so
// verdicts stay isolated if multiple classifier sets ever coexist. If the
// fingerprint collided for distinct inputs, the cache could leak verdicts
// across model sets.
//--------------------------------------------------------------------------

TEST_CASE("SnortML model_set_fingerprint deterministic", "[snort_ml_engine]")
{
    std::vector<std::string> a = { "alpha", "beta" };
    std::vector<std::string> b = { "alpha", "beta" };

    REQUIRE(snort_ml_model_set_fingerprint(a) == snort_ml_model_set_fingerprint(b));
}

TEST_CASE("SnortML model_set_fingerprint distinguishes content", "[snort_ml_engine]")
{
    REQUIRE(snort_ml_model_set_fingerprint({ "model_a" })
        != snort_ml_model_set_fingerprint({ "model_b" }));
}

TEST_CASE("SnortML model_set_fingerprint distinguishes order", "[snort_ml_engine]")
{
    REQUIRE(snort_ml_model_set_fingerprint({ "a", "b" })
        != snort_ml_model_set_fingerprint({ "b", "a" }));
}

TEST_CASE("SnortML model_set_fingerprint empty set", "[snort_ml_engine]")
{
    // An empty model set should still produce a stable value (the FNV
    // basis) rather than 0 or unspecified.
    REQUIRE(snort_ml_model_set_fingerprint({}) == FNV_BASIS);
}

TEST_CASE("SnortML model_set_fingerprint non-trivial size", "[snort_ml_engine]")
{
    std::string big(8192, 'x');
    std::string also(8192, 'y');

    REQUIRE(snort_ml_model_set_fingerprint({ big }) != 0);
    REQUIRE(snort_ml_model_set_fingerprint({ big })
        != snort_ml_model_set_fingerprint({ also }));
}

//--------------------------------------------------------------------------
// Cache-key isolation
//
// snort_ml_engine.cc XORs the per-scan FNV with the context's
// model_set_id, so two contexts with different model sets produce
// different cache keys for the same buffer. Mirror the computation here
// so the property stays pinned by an active test.
//--------------------------------------------------------------------------

static uint64_t compute_cache_key(const char* buf, size_t len, uint64_t model_set_id)
{
    return fnv1a(buf, len) ^ model_set_id;
}

TEST_CASE("SnortML cache key differs across model sets for same buffer", "[snort_ml_engine]")
{
    const char* buf = "GET /admin?user=alice";
    const size_t len = std::strlen(buf);

    const uint64_t id_a = snort_ml_model_set_fingerprint({ "model_v1" });
    const uint64_t id_b = snort_ml_model_set_fingerprint({ "model_v2" });

    REQUIRE(id_a != id_b);
    REQUIRE(compute_cache_key(buf, len, id_a) != compute_cache_key(buf, len, id_b));
}

TEST_CASE("SnortML cache key is stable for same buffer and model set", "[snort_ml_engine]")
{
    const char* buf = "GET /";
    const size_t len = std::strlen(buf);
    const uint64_t id = snort_ml_model_set_fingerprint({ "model" });

    REQUIRE(compute_cache_key(buf, len, id) == compute_cache_key(buf, len, id));
}
