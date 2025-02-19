//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// numa.cc author Denys Zikratyi <dzikraty@cisco.com>

#include "numa.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

NumaMemPolicy convert_string_to_numa_mempolicy(const std::string& policy)
{
    static const std::unordered_map<std::string, NumaMemPolicy> string_to_numa_mempolicy = 
    {
        {"default", NumaMemPolicy::DEFAULT},
        {"preferred", NumaMemPolicy::PREFERRED},
        {"bind", NumaMemPolicy::BIND},
        {"local", NumaMemPolicy::LOCAL}
    };

    auto it = string_to_numa_mempolicy.find(policy);
    if (it != string_to_numa_mempolicy.end())
        return it->second;

    return NumaMemPolicy::UNKNOWN;
}

std::string stringify_numa_mempolicy(const NumaMemPolicy& policy)
{
    switch (policy) 
    {
    case NumaMemPolicy::DEFAULT: return "default"; 
    case NumaMemPolicy::PREFERRED: return "preferred";
    case NumaMemPolicy::BIND: return "bind";
    case NumaMemPolicy::LOCAL: return "local";
    default: return "unknown";
    }
}

// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------
#ifdef UNIT_TEST

TEST_CASE("Parse string to NumaMemPolicy positive test")
{
    CHECK(NumaMemPolicy::DEFAULT == convert_string_to_numa_mempolicy("default"));
    CHECK(NumaMemPolicy::PREFERRED == convert_string_to_numa_mempolicy("preferred"));
    CHECK(NumaMemPolicy::BIND == convert_string_to_numa_mempolicy("bind"));
    CHECK(NumaMemPolicy::LOCAL == convert_string_to_numa_mempolicy("local"));
}

TEST_CASE("Parse string to NumaMemPolicy negative test")
{
    CHECK(NumaMemPolicy::UNKNOWN == convert_string_to_numa_mempolicy("preferred_many"));
    CHECK(NumaMemPolicy::UNKNOWN == convert_string_to_numa_mempolicy("interleave"));
    CHECK(NumaMemPolicy::UNKNOWN == convert_string_to_numa_mempolicy("fake_policy"));
}

TEST_CASE("Parse NumaMemPolicy to string")
{
    CHECK("default" == stringify_numa_mempolicy(NumaMemPolicy::DEFAULT));
    CHECK("preferred" == stringify_numa_mempolicy(NumaMemPolicy::PREFERRED));
    CHECK("bind" == stringify_numa_mempolicy(NumaMemPolicy::BIND));
    CHECK("local" == stringify_numa_mempolicy(NumaMemPolicy::LOCAL));

    CHECK("unknown" == stringify_numa_mempolicy(NumaMemPolicy::UNKNOWN));
}

#endif
