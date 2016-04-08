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

void TextFormatter::register_section(string name)
{
    section_names.push_back(name);
    field_names.push_back(vector<string>());
    PerfFormatter::register_section(name);
}

void TextFormatter::register_field(string name)
{
    field_names[last_section].push_back(name);
    PerfFormatter::register_field(name);
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

                case FT_STRING:
                    if( values[i][j].s )
                    {
                        if( !head )
                        {
                            LogLabel(section_names[i].c_str(), fh);
                            head = true;
                        }
                        LogValue(field_names[i][j].c_str(), values[i][j].s, fh);
                    }
                    break;

                case FT_IDX_PEG_COUNT:
                {
                    vector<PegCount>* vals = values[i][j].ipc;
                    for( unsigned k = 0; k < vals->size(); k++ )
                    {
                        if( !vals->at(k) )
                            continue;

                        if( !head )
                        {
                            LogLabel(section_names[i].c_str(), fh);
                            head = true;
                        }
                        std::ostringstream ss;
                        ss << field_names[i][j] << "." << k;
                        LogCount(ss.str().c_str(), vals->at(k), fh);
                    }
                    break;
                }

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
        "                     four: 34.5678\n"
        "--------------------------------------------------\n"
        "str\n"
        "                     five: hellothere\n"
        "--------------------------------------------------\n"
        "vec\n"
        "                 vector.0: 50\n"
        "                 vector.2: 70\n";
        
    FILE* fh = tmpfile();
    TextFormatter f;

    f.register_section("name");
    f.register_field("one");
    f.register_field("two");
    f.register_section("other");
    f.register_field("three");
    f.register_field("four");
    f.register_section("str");
    f.register_field("five");
    f.register_section("vec");
    f.register_field("vector");
    f.finalize_fields(fh);

    f.set_field(0, 0, (PegCount)1);
    f.set_field(0, 1, (PegCount)0);
    f.set_field(1, 0, (PegCount)0);
    f.set_field(1, 1, 34.5678);
    f.set_field(2, 0, "hellothere");

    std::vector<PegCount> kvp;
    kvp.push_back(50);
    kvp.push_back(0);
    kvp.push_back(70);
    f.set_field(3, 0, &kvp);
    
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
