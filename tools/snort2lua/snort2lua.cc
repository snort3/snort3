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

static bool convert(std::ifstream& in, std::ofstream& out)
{
    Converter* state = new InitState();

    while(!in.eof())
    {
        std::string next_line;
        bool line_continuation = false;

        std::getline(in, next_line);

        if (next_line.empty())
        {
            out << std::endl;
        }
        else
        {
            if (next_line.back() == '\\')
            {
                line_continuation = true;
                next_line.pop_back();
            }

            state->convert(next_line, out);
        }

        if (!line_continuation)
            state->reset_state();

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
