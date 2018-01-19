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

// json_formatter.cc author Carter Waxman <cwaxman@cisco.com>

#include "json_formatter.h"

#include <sstream>

#include "utils/stats.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef UNIT_TEST
#include <cstdio>
#include <cstring>

#include "catch/snort_catch.h"
#include "utils/util.h"
#endif

using namespace std;

void JSONFormatter::init_output(FILE* fh)
{
    fwrite("[", 1, 1, fh);
    first_write = true;
}

void JSONFormatter::write(FILE* fh, time_t cur_time)
{
    std::ostringstream ss;

    if( first_write )
        first_write = false;
    else
        ss << ",";

    ss << "{\"timestamp\":" << cur_time;

    for( unsigned i = 0; i < values.size(); i++ )
    {
        bool head = false;
        
        for( unsigned j = 0; j < values[i].size(); j++ )
        {
            switch( types[i][j] )
            {
                case FT_PEG_COUNT:
                    if( *values[i][j].pc != 0 )
                    {
                        if( !head ) 
                        {
                            ss << ",\"" << section_names[i] << "\":{";
                            head = true;
                        }
                        else
                            ss << ",";
                        ss << "\"" << field_names[i][j] << "\":" << *values[i][j].pc;
                    }
                    break;

                case FT_STRING:
                    if( *values[i][j].s )
                    {
                        if( !head )
                        {
                            ss << ",\"" << section_names[i] << "\":{";
                            head = true;
                        }
                        else
                            ss << ",";
                        ss << "\"" << field_names[i][j] << "\":\"" << values[i][j].s << "\"";
                    }
                    break;

                case FT_IDX_PEG_COUNT:
                {
                    bool vec_head = false;

                    vector<PegCount>* vals = values[i][j].ipc;
                    for( unsigned k = 0; k < vals->size(); k++ )
                    {
                        if( !vals->at(k) )
                            continue;

                        if( !vec_head )
                        {
                            if( !head )
                            {
                                ss << ",\"" << section_names[i] << "\":{";
                                head = true;
                            }
                            else
                                ss << ",";

                            ss << "\"" << field_names[i][j] << "\":{";
                            vec_head = true;
                        }
                        else
                            ss << ",";

                        ss << "\"" << k << "\":" << vals->at(k);
                    }
                    if( vec_head )
                        ss << "}";

                    break;
                }
            }
        }
        if ( head )
            ss << "}";
    }
    ss << "}";
    auto out = ss.str();
    fwrite(out.c_str(), out.size(), 1, fh);
    fflush(fh);
}

void JSONFormatter::finalize_output(FILE* fh)
{ fwrite("]\n", 2, 1, fh); }

#ifdef UNIT_TEST

string cooked = R"g([{"timestamp":1234567890,"name":{"one":1},"str":{"five":"hellothere"},)g"
                R"g("vec":{"vector":{"0":50,"2":70}}},{"timestamp":2345678901}])g" "\n";

TEST_CASE("json output", "[JSONFormatter]")
{
    PegCount one = 1, two = 0, three = 0;
    char five[32] = "hellothere";
    vector<PegCount> kvp;

    FILE* fh = tmpfile();
    JSONFormatter f("test");

    f.register_section("name");
    f.register_field("one", &one);
    f.register_field("two", &two);
    f.register_section("other");
    f.register_field("three", &three);
    f.register_section("str");
    f.register_field("five", five);
    f.register_section("vec");
    f.register_field("vector", &kvp);
    f.finalize_fields();
    f.init_output(fh);

    kvp.push_back(50);
    kvp.push_back(0);
    kvp.push_back(70);
    
    f.write(fh, (time_t)1234567890);

    one = 0;
    five[0] = '\0';
    kvp.clear();
    f.write(fh, (time_t)2345678901);
    f.finalize_output(fh);

    auto size = ftell(fh);
    char* fake_file = (char*)snort_alloc(size + 1);

    rewind(fh);
    fread(fake_file, size, 1, fh);
    fake_file[size] = '\0';

    CHECK( cooked == fake_file );

    snort_free(fake_file);
    fclose(fh);
}

#endif
