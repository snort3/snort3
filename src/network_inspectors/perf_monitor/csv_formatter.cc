//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "csv_formatter.h"

#include <sstream>

#ifdef UNIT_TEST
#include <cstdio>
#include <cstring>

#include "catch/snort_catch.h"
#include "utils/util.h"
#endif

using namespace std;

void CSVFormatter::finalize_fields()
{
    header = "#timestamp";

    for( unsigned i = 0; i < section_names.size(); i++ )
    {
        string section = section_names[i];

        for( auto& field : field_names[i] )
        {
            header += ",";
            header += section;
            header += ".";
            header += field;
        }
    }
    header += "\n";
    section_names.clear();
    field_names.clear();
}

void CSVFormatter::init_output(FILE* fh)
{
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
                case FT_PEG_COUNT:
                    fprintf(fh, ",%" PRIu64, *values[i][j].pc);
                    break;

                case FT_STRING:
                    fprintf(fh, ",%s", values[i][j].s ?
                        values[i][j].s : "");
                    break;

                case FT_IDX_PEG_COUNT:
                {
                    std::ostringstream ss;
                    PegCount size = 0;

                    for( PegCount pc : *values[i][j].ipc )
                    {
                        if( pc )
                        {
                            ss << "," << pc;
                            size++;
                        }
                    }
                    fprintf(fh, ",%" PRIu64 "%s", size, ss.str().c_str());
                    break;
                }
            }
        }
    }
    fputs("\n", fh);
    fflush(fh);
}

#ifdef UNIT_TEST

TEST_CASE("csv output", "[CSVFormatter]")
{
    PegCount one = 0, two = 1, three = 2;
    char five[32] = "hellothere";
    std::vector<PegCount> kvp;

    const char* cooked =
        "#timestamp,name.one,name.two,other.three,other.five,other.kvp\n"
        "1234567890,0,1,2,hellothere,3,50,60,70\n"
        "2345678901,0,0,0,,0\n";

    FILE* fh = tmpfile();
    CSVFormatter f("csv_formatter");

    f.register_section("name");
    f.register_field("one", &one);
    f.register_field("two", &two);
    f.register_section("other");
    f.register_field("three", &three);
    f.register_field("five", five);
    f.register_field("kvp", &kvp);
    f.finalize_fields();
    f.init_output(fh);

    kvp.push_back(50);
    kvp.push_back(60);
    kvp.push_back(70);

    f.write(fh, (time_t)1234567890);

    two = 0;
    three = 0;
    five[0] = '\0';
    kvp.clear();
    f.write(fh, (time_t)2345678901);

    auto size = ftell(fh);
    char* fake_file = (char*)snort_alloc(size + 1);

    rewind(fh);
    fread(fake_file, size, 1, fh);
    fake_file[size] = '\0';

    CHECK( !strcmp(cooked, fake_file) );

    snort_free(fake_file);
    fclose(fh);
}

#endif
