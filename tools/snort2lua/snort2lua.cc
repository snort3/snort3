//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// snort2lua.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <iostream>
#include <fstream>

#include "helpers/converter.h"
#include "init_state.h"
#include "helpers/s2l_util.h"
#include "helpers/parse_cmd_line.h"

/*********************************************
 **************  MAIN FILES  *****************
 *********************************************/

static void print_line(const std::string& s)
{
    if (!DataApi::is_quiet_mode())
        std::cout << s << std::endl;
}

int main(int argc, char* argv[])
{
    bool fail = false;

    if (!parser::parse_cmd_line(argc, argv))
    {
        print_line("ERROR:  Invalid command line options provided!");
        return -1;
    }

    // Defaults are set in parse_cmd_line.cc
    const std::string output_file = parser::get_out_file();
    const std::string error_file = parser::get_error_file();
    const std::string rule_file = parser::get_rule_file();
    const std::string conf_file = parser::get_conf();

    // configuration file is required and no default is provided
    if (conf_file.empty())
    {
        print_line("ERROR:  Snort configuration file required!!");
        print_line("        Use either '-c' or '--conf-file' option");
        return -1;
    }

    // MAIN CONVERSION FUNCTION!!
    Converter cv;
    if (cv.convert(conf_file, output_file, rule_file, error_file) < 0)
    {
        print_line("Failed Conversion of file " + conf_file);
        fail = true;
    }

    if (fail || cv.failed_conversions())
        return -2;
    return 0;
}

