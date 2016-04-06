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

// text_formatter.cc author Carter Waxman <cwaxman@cisco.com>

#include "text_formatter.h"

#include "utils/stats.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"

#include <cstdio>
#include <cstring>
#endif

using namespace std;

SectionRef TextFormatter::register_section(string name)
{
    section_names.push_back(name);
    field_names.push_back(vector<string>());

    return PerfFormatter::register_section(name);
}

FieldRef TextFormatter::register_field(SectionRef section, string name)
{
    field_names[section].push_back(name);
    return PerfFormatter::register_field(section, name);
}

void TextFormatter::write(FILE* fh, time_t)
{
    for( unsigned i = 0; i < values.size(); i++ )
    {
        bool head = false;

        for( unsigned j = 0; j < values[i].size(); j++ )
        {
            switch( types[i][j] )
            {
                case FT_DOUBLE:
                    if( !head && values[i][j].d != 0 )
                    {
                        LogLabel(section_names[i].c_str(), fh);
                        head = true;
                    }
                    LogStat(field_names[i][j].c_str(), values[i][j].d, fh);
                    break;
                case FT_PEG_COUNT:
                    if( !head && values[i][j].pc != 0 )
                    {
                        LogLabel(section_names[i].c_str(), fh);
                        head = true;
                    }
                    LogCount(field_names[i][j].c_str(), values[i][j].pc, fh);
                    break;
                case FT_UNSET:
                    break; 
            }
        }
    }
    fflush(fh);
}

#ifdef UNIT_TEST

TEST_CASE("text output", "[TextFormatter]")
{
    const char* cooked =
        "--------------------------------------------------\n"
        "name\n"
        "                      one: 1\n"
        "--------------------------------------------------\n"
        "other\n"
        "                     four: 34.5678\n";

        
    FieldRef fr[4];
    
    FILE* fh = tmpfile();
    TextFormatter f;

    SectionRef s = f.register_section("name");
    fr[0] = f.register_field(s, "one");
    fr[1] = f.register_field(s, "two");
    s = f.register_section("other");
    fr[2] = f.register_field(s, "three");
    fr[3] = f.register_field(s, "four");
    f.finalize_fields(fh);

    f.set_field(fr[0], (PegCount)1);
    f.set_field(fr[1], (PegCount)0);
    f.set_field(fr[2], (PegCount)0);
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
