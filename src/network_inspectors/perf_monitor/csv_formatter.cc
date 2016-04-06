//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// csv_formatter.cc author Carter Waxman <cwaxman@cisco.com>

#include "csv_formatter.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

using namespace std;

SectionRef CSVFormatter::register_section(string name)
{
    return PerfFormatter::register_section(name);
}

FieldRef CSVFormatter::register_field(SectionRef section, string name)
{
    return PerfFormatter::register_field(section, name);
}

void CSVFormatter::init_output(FILE* fh)
{

}

void CSVFormatter::write(FILE* fh, time_t timestamp)
{

}

void CSVFormatter::clear()
{
    PerfFormatter::clear();
}

#ifdef UNIT_TEST

TEST_CASE("header output", "[perf csv_formatter]")
{
    char* fake_file, cooked =
        "#timestamp,name.one,name.two,other.three,other.four\n";

    CSVFormatter f;
    FILE* fh = tmpfile();

    SectionRef s = f.register_section("name");
    f.register_field(s, "one");
    f.register_field(s, "two");
    s = f.register_section("two");
    f.register_field(s, "three");
    f.register_field(s, "four");
    f.init_output(fh);

    auto size = tell(fh);
    rewind(fh);

    fread(
    fclose(fh);
}

#endif
