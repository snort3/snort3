/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// snort2lua.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <iostream>
#include <fstream>

#include "converter.h"
#include "init_state.h"
#include "snort2lua_util.h"

static void convert(Converter *cv, std::string input_file)
{
    std::ifstream in;
    std::string orig_text;

    in.open(input_file,  std::ifstream::in);
    cv->reset_state();

    while(!in.eof())
    {
        std::string tmp;
        std::getline(in, tmp);
        util::ltrim(tmp);
        orig_text += ' ' + tmp;
        util::trim(orig_text);

        if (orig_text.empty())
        {
            cv->add_comment_to_file("");
        }
        else if (orig_text.front() == '#')
        {
            orig_text.erase(orig_text.begin());
            cv->add_comment_to_file(orig_text);
            orig_text.clear();
        }
        else if ( orig_text.back() == '\\')
        {
            orig_text.pop_back();
            util::rtrim(orig_text);
        }
        else
        {
            std::stringstream data_stream(orig_text);
            while(data_stream.tellg() != -1)
            {
                if (!cv->convert_line(data_stream))
                {
                    cv->log_error("Failed to entirely convert: " + orig_text);
                    break;
                }
            }

            orig_text.clear();
            cv->reset_state();
        }
    }

}


static void show_usage()
{
    std::cout << "usage:  snort2lua <input_conf_file> <output_lua_file>" << std::endl;
}

int main (int argc, char* argv[])
{
    std::ifstream in;
    std::ofstream out;
    std::string input_name, output_name;
    Converter cv;

    if (argc != 3)
    {
        show_usage();
        return -1;
    }

    input_name = std::string(argv[1]);
    output_name = std::string(argv[2]);

    if (in.fail())
    {
        std:: cout << "Error:  could not open input file " << argv[1] << std::endl;
        return -1;
    }

    if(out.fail())
    {
        std:: cout << "Error: could not open output file " << argv[2] << std::endl;
        return -1;
    }

    convert(&cv, input_name);


    // finally, lets print the converter to file
    out.open(argv[2],  std::ifstream::out);
    out << "require(\"snort_config\")  -- for loading" << std::endl << std::endl;
    out << cv;

    in.close();
    out.close();
    return 0;
}
