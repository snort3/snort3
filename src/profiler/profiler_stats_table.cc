//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// profiler_stats_table.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "profiler_stats_table.h"

#include <cassert>
#include <cstring>
#include <iomanip>
#include <sstream>

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

static constexpr unsigned WIDTH = 50;
static constexpr char ENDL = '\n';

const StatsTable::Header StatsTable::HEADER { '=' };
const StatsTable::Sep StatsTable::SEP { '-' };
const StatsTable::Row StatsTable::ROW { };

StatsTable::StatsTable(const Field* fields, std::ostream& os) :
    fields(fields), os(os), cur(nullptr)
{ assert(fields); }

StatsTable::~StatsTable()
{ finish(); }

void StatsTable::header(char c)
{
    os.fill(' ');

    const auto* field = fields;
    while ( field->name )
    {
        format(*field);
        os << field->name;
        ++field;
    }

    os << ENDL;

    if ( c )
    {
        field = fields;
        while ( field->name )
        {
            format(*field);
            os << std::string(strlen(field->name), c);
            ++field;
        }

        os << ENDL;
    }
}

void StatsTable::sep(char c)
{ os << std::string(WIDTH, c) << ENDL; }

void StatsTable::row()
{
    finish();
    cur = fields;
}

StatsTable& StatsTable::operator<<(StatsTable::Header h)
{
    header(h.c);
    return *this;
}

StatsTable& StatsTable::operator<<(StatsTable::Sep s)
{
    sep(s.c);
    return *this;
}

StatsTable& StatsTable::operator<<(StatsTable::Row)
{
    row();
    return *this;
}

void StatsTable::finish()
{
    if ( cur )
    {
        cur = nullptr;
        os << ENDL;
    }
}

void StatsTable::format(const StatsTable::Field& field)
{
    os.flags(field.flags);
    os << std::fixed;

    if ( field.fill )
        os << std::setfill(field.fill);

    if ( field.width >= 0 )
        os << std::setw(field.width);

    if ( field.precision >= 0 )
        os << std::setprecision(field.precision);
}

#ifdef UNIT_TEST

static const StatsTable::Field s_test_fields[] =
{
    { "foo", 7, ' ', 2, std::ios_base::fmtflags() },
    { "bar", 6, ' ', 0, std::ios_base::fmtflags() },
    { nullptr, 0, '\0', 0, std::ios_base::fmtflags() }
};

TEST_CASE( "profiler stats table", "[profiler][profiler_stats_table]" )
{
    std::ostringstream ss;
    StatsTable table(s_test_fields, ss);

    SECTION( "header" )
    {
        std::string expected = "    foo   bar\n";

        SECTION( "without separator" )
        {
            table << StatsTable::Header { '\0' };
            auto result = ss.str();
            CHECK( result == expected );
        }

        SECTION( "with default separator" )
        {
            expected += "    ===   ===\n";
            table << StatsTable::HEADER;
            auto result = ss.str();
            CHECK( result == expected );
        }
    }

    SECTION( "separator" )
    {
        SECTION( "default separator" )
        {
            std::string expected = std::string(WIDTH, '-') + "\n";
            table << StatsTable::SEP;
            auto result = ss.str();
            CHECK( result == expected );
        }

        SECTION( "custom separator" )
        {
            std::string expected = std::string(WIDTH, '*') + "\n";
            table << StatsTable::Sep { '*' };
            auto result = ss.str();
            CHECK( result == expected );
        }
    }

    SECTION( "row" )
    {
        SECTION( "partial row" )
        {
            std::string expected = "  12.53\n  13.11\n";
            table << StatsTable::ROW << 12.535f;
            CHECK( table.next() == "bar" );
            table << StatsTable::ROW << 13.112f;
            CHECK( table.next() == "bar" );
            table.finish();
            auto result = ss.str();
            CHECK( result == expected );
        }

        SECTION( "complete rows" )
        {
            std::string expected = "  12.53     1\n  29.33     2\n";
            table << StatsTable::ROW << 12.535f << 1.0f;
            CHECK( table.next().empty() );
            table << StatsTable::ROW << 29.333f << 2.0f;
            CHECK( table.next().empty() );
            table.finish();
            auto result = ss.str();
            CHECK( result == expected );
        }
    }

    SECTION( "templated operator <<" )
    {
        table << "buzz";
        auto result = ss.str();
        CHECK( result == "buzz" );
    }
}

#endif
