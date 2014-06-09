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


#if 0
#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>

static inline std::string *ltrim(std::string *s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
}


static inline std::string *rtrim(std::string *s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
};

static inline std::string &trim(std::string &s)
{
    return ltrim(rtrim(s));
}
#endif

static bool convert(std::ifstream& in, std::ofstream& out)
{
    Converter cv;
    cv.reset_state();
//    state->inititalize();
//    Converter::reset_state();

    while(!in.eof())
    {
        std::string next_line;
        bool last_line = true;

        std::getline(in, next_line);

        if (next_line.empty())
        {
            out << std::endl;
        }
        else
        {
            if (next_line.back() == '\\')
            {
                last_line = false;
                next_line.pop_back();
            }

            std::stringstream data_stream(next_line);
            while(data_stream.tellg() != -1)
            {
                #if 0
                std::cout << data_stream.str() << std::endl;
                std::cout << "size of data_stream: " << data_stream.str().size() << std::endl;
                std::cout << "size of tellg: " << data_stream.tellg() << std::endl;
                std::cout << "is empty? " << data_stream.str().empty() << std::endl;
//                cv.print_line(data_stream);
#endif
                if (!cv.convert_line(data_stream, last_line, out))
                {
                    std::cout << "ERROR: Failed to convert line: " << std::endl;
                    std::cout << "\t\t" << next_line << std::endl; 
                    return false;
                }
            }
        }

        if (last_line)
            cv.reset_state();

    }
    return true;
}

static void show_usage()
{
    std::cout << "usage:  snort2lua <input_conf_file> <output_lua_file" << std::endl;
}

int main (int argc, char* argv[])
{
    std::ifstream in;
    std::ofstream out;

    if (argc != 3)
    {
        show_usage();
        return -1;
    }

    in.open(argv[1],  std::ifstream::in);
    out.open(argv[2],  std::ifstream::out);

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

    if (!convert(in, out))
    {
        std::cout << "Error: failed to convert files!" << std::endl;
    }

    in.close();
    out.close();
    return 0;
}
