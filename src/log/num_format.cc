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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "num_format.h"

#include <atomic>

// libc locales are not used because musl never provides a thousands
// separator and snort does not call setlocale anyway

static std::atomic<char> s_sep { '\0' };

namespace
{
class CountPunct : public std::numpunct<char>
{
public:
    explicit CountPunct(char c) : sep(c) { }

protected:
    char do_thousands_sep() const override
    { return sep ? sep : ','; }

    char do_decimal_point() const override
    { return sep == '.' ? ',' : '.'; }

    std::string do_grouping() const override
    { return sep ? "\3" : ""; }

private:
    char sep;
};
}

namespace snort
{
void set_thousands_separator(char c)
{ s_sep.store(c, std::memory_order_relaxed); }

char get_thousands_separator()
{ return s_sep.load(std::memory_order_relaxed); }

char get_decimal_point()
{ return get_thousands_separator() == '.' ? ',' : '.'; }

std::string format_count(uint64_t n)
{
    std::string digits = std::to_string(n);
    const char sep = get_thousands_separator();

    if ( !sep or digits.size() <= 3 )
        return digits;

    std::string out;
    out.reserve(digits.size() + digits.size() / 3);

    size_t lead = digits.size() % 3;
    if ( !lead )
        lead = 3;

    out.append(digits, 0, lead);

    for ( size_t i = lead; i < digits.size(); i += 3 )
    {
        out += sep;
        out.append(digits, i, 3);
    }
    return out;
}

std::string format_signed(int64_t n)
{
    if ( n >= 0 )
        return format_count(static_cast<uint64_t>(n));

    // negate in unsigned space so INT64_MIN does not overflow
    return "-" + format_count(0 - static_cast<uint64_t>(n));
}

void localize_decimal(char* s)
{
    if ( get_decimal_point() == '.' )
        return;

    for ( ; *s; ++s )
    {
        if ( *s == '.' )
            *s = ',';
    }
}

std::locale count_locale()
{ return std::locale(std::locale::classic(), new CountPunct(get_thousands_separator())); }
}

#ifdef CATCH_TEST_BUILD

#include <sstream>

#include "catch/catch.hpp"

using namespace snort;

TEST_CASE("format_count", "[num_format]")
{
    set_thousands_separator('\0');
    CHECK(format_count(48210) == "48210");

    set_thousands_separator(',');
    CHECK(format_count(0) == "0");
    CHECK(format_count(999) == "999");
    CHECK(format_count(1000) == "1,000");
    CHECK(format_count(48210) == "48,210");
    CHECK(format_count(2407633) == "2,407,633");
    CHECK(format_count(UINT64_MAX) == "18,446,744,073,709,551,615");
    CHECK(format_signed(-1234567) == "-1,234,567");
    CHECK(format_signed(INT64_MIN) == "-9,223,372,036,854,775,808");

    set_thousands_separator('.');
    CHECK(format_count(2405020) == "2.405.020");

    char pct[] = "12.345";
    localize_decimal(pct);
    CHECK(std::string(pct) == "12,345");

    std::ostringstream ss;
    ss.imbue(count_locale());
    ss << std::fixed;
    ss.precision(1);
    ss << 1234567 << ' ' << 1234.5;
    CHECK(ss.str() == "1.234.567 1.234,5");

    set_thousands_separator('\0');
}

#endif
