//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// ips_option.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_option.h"

#include <cstring>

#include "hash/hash_key_operations.h"

using namespace snort;

//-------------------------------------------------------------------------

IpsOption::IpsOption(const char* s, option_type_t t)
{
    name = s;
    type = t;
}

uint32_t IpsOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;
    mix_str(a, b, c, get_name());
    finalize(a, b, c);
    return c;
}

bool IpsOption::operator==(const IpsOption& ips) const
{
    return !strcmp(get_name(), ips.get_name());
}

section_flags IpsOption::get_pdu_section(bool) const
{
    return section_to_flag(PS_NONE);
}

//-------------------------------------------------------------------------
// UNIT TESTS
//-------------------------------------------------------------------------
#ifdef UNIT_TEST
#include "catch/snort_catch.h"

class StubIpsOption : public IpsOption
{
public:
    StubIpsOption(const char* name, option_type_t option_type) :
        IpsOption(name, option_type)
    { }
};

TEST_CASE("IpsOption test", "[ips_option]")
{
    StubIpsOption main_ips("ips_test",
        option_type_t::RULE_OPTION_TYPE_OTHER);

    SECTION("buffer test")
    {
        REQUIRE(main_ips.get_buffer());  // only until api is updated
    }

    SECTION("IpsOperator == test")
    {
        StubIpsOption case_diff_name("not_hello_world",
            option_type_t::RULE_OPTION_TYPE_LEAF_NODE);

        REQUIRE((main_ips == case_diff_name) == false);

        StubIpsOption case_diff_option("hello_world",
            option_type_t::RULE_OPTION_TYPE_CONTENT);
        REQUIRE((main_ips == case_diff_option) == false);

        StubIpsOption case_option_na("hello_world",
            option_type_t::RULE_OPTION_TYPE_OTHER);
        REQUIRE((main_ips == case_option_na) == false);
    }

    SECTION("hash test")
    {
        StubIpsOption other_main_ips("ips_test",
            option_type_t::RULE_OPTION_TYPE_OTHER);

        SECTION("hash test with short string")
        {
            StubIpsOption main_ips_short("ips_test",
                option_type_t::RULE_OPTION_TYPE_OTHER);
            REQUIRE((other_main_ips.hash() == main_ips_short.hash()) == true);

            StubIpsOption main_ips_short_diff("not_ips_test",
                option_type_t::RULE_OPTION_TYPE_OTHER);
            REQUIRE((other_main_ips.hash() == main_ips_short_diff.hash()) == false);
        }

        SECTION("hash test with long string")
        {
            std::string really_long_string =
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101";

            StubIpsOption main_ips_long_first(really_long_string.c_str(),
                option_type_t::RULE_OPTION_TYPE_OTHER);
            StubIpsOption main_ips_long_second(really_long_string.c_str(),
                option_type_t::RULE_OPTION_TYPE_OTHER);
            REQUIRE(main_ips_long_first.hash() == main_ips_long_second.hash());

            REQUIRE(main_ips_long_first.hash() != other_main_ips.hash());
        }
    }
}

#endif
