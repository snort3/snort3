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

#include <cstdio>
#include <cstring>
#endif

using namespace std;

SectionRef CSVFormatter::register_section(string name)
{
    section_names.push_back(name);
    field_names.push_back(vector<string>());

    return PerfFormatter::register_section(name);
}

FieldRef CSVFormatter::register_field(SectionRef section, string name)
{
    field_names[section].push_back(name);
    return PerfFormatter::register_field(section, name);
}

void CSVFormatter::finalize_fields(FILE* fh)
{
    string header = "#timestamp";

    for( unsigned i = 0; i < section_names.size(); i++ )
    {
        string section = section_names[i];

        for( auto& field : field_names[i] )
            header += "," + section + "." + field;
    }
    header += "\n";
    section_names.clear();
    field_names.clear();

    fwrite(header.c_str(), header.size(), 1, fh);
    fflush(fh);
}

void CSVFormatter::write(FILE* fh, time_t timestamp)
{
    fprintf(fh, "%" PRIu64, (uint64_t)timestamp);

    for( unsigned i = 0; i < values.size(); i++ )
    {
        for( unsigned j = 0; j < values[i].size(); j++ )
        {
            switch( types[i][j] )
            {
                case FT_DOUBLE:
                    fprintf(fh, ",%g", values[i][j].d);
                    break;
                case FT_PEG_COUNT:
                    fprintf(fh, ",%" PRIu64, values[i][j].pc);
                    break;
                case FT_UNSET:
                    fputs(",0", fh);
                    break; 
            }
        }
    }
    fputs("\n", fh);
    fflush(fh);
}

#ifdef UNIT_TEST

TEST_CASE("csv output", "[CSVFormatter]")
{
    const char* cooked =
        "#timestamp,name.one,name.two,other.three,other.four\n"
        "1234567890,0,1,2,34.5678\n"
        "2345678901,0,0,0,0\n";
    FieldRef fr[4];
    
    FILE* fh = tmpfile();
    CSVFormatter f;

    SectionRef s = f.register_section("name");
    fr[0] = f.register_field(s, "one");
    fr[1] = f.register_field(s, "two");
    s = f.register_section("other");
    fr[2] = f.register_field(s, "three");
    fr[3] = f.register_field(s, "four");
    f.finalize_fields(fh);

    f.set_field(fr[0], (PegCount)0);
    f.set_field(fr[1], (PegCount)1);
    f.set_field(fr[2], (PegCount)2);
    f.set_field(fr[3], 34.5678);
    f.write(fh, (time_t)1234567890);

    f.clear();
    f.write(fh, (time_t)2345678901);

    auto size = ftell(fh);
    char* fake_file = (char*) malloc(size + 1);

    rewind(fh);
    fread(fake_file, size, 1, fh);
    fake_file[size] = '\0';
    
    CHECK( !strcmp(cooked, fake_file) );

    free(fake_file);
    fclose(fh);
}

#endif
