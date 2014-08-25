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
// snort2lua.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <iostream>
#include <fstream>

#include "utils/converter.h"
#include "init_state.h"
#include "utils/s2l_util.h"
#include "utils/parse_cmd_line.h"


/*********************************************
 **************  MAIN FILES  *****************
 *********************************************/

static void print_line(std::string s)
{
    if (!data_api.is_quiet_mode())
        std::cout << s << std::endl;
}

int main (int argc, char* argv[])
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
    cv.initialize(&init_state_ctor);
    if (cv.convert_file(conf_file) < 0)
    {
        print_line("Failed Conversion of file " + conf_file);
        fail = true;
    }

    // keep track whether we're printing rules into a seperate file.
    bool rule_file_specifed = false;

    // if no rule file is specified (or the same output and rule file specified),
    // rules will be printed in the 'default_rules' variable. Set that up
    // now.  Otherwise, set up the include file.
    if (rule_api.empty())
    {
        if (rule_file.empty() || !rule_file.compare(output_file))
        {
            std::string s = std::string("$default_rules");
            rule_file_specifed = false;

            table_api.open_top_level_table("ips");
            table_api.add_option("rules", s);
            table_api.close_table();
        }
        else
        {
            rule_file_specifed = true;

            table_api.open_top_level_table("ips");
            table_api.add_option("include", rule_file);
            table_api.close_table();
        }
    }

    // Snort++ requires a binder table to be instantiated,
    // although not necessarily filled.  So, just add this table.
    // If its already added, these lines won't have any effect
    table_api.open_top_level_table("binder");
    table_api.close_table();

    // finally, lets print the converter to file

    std::ofstream out;
    out.open(output_file,  std::ifstream::out);
    out << "require(\"snort_config\")  -- for loading\n\n";

    if (!rule_file_specifed)
    {
        data_api.print_data(out);
        rule_api.print_rules(out, rule_file_specifed);
        table_api.print_tables(out);
        data_api.print_comments(out);


        out << std::endl;

        if ((data_api.failed_conversions() || rule_api.failed_conversions()) &&
            !data_api.is_quiet_mode())
        {
            std::ofstream rejects;  // in this case, rejects are regular configuration options
            rejects.open(error_file, std::ifstream::out);
            data_api.print_errors(rejects);
            rejects << std::endl;
            rejects.close();
        }
    }
    else
    {
        std::ofstream rules;
        rules.open(rule_file, std::ifstream::out);

        data_api.print_data(out);
        rule_api.print_rules(rules, rule_file_specifed);
        table_api.print_tables(out);
        data_api.print_comments(out);

        // flush all data
        out << std::endl;
        rules << std::endl;
        rules.close();

        if ((data_api.failed_conversions() || rule_api.failed_conversions()) &&
            !data_api.is_quiet_mode())
        {
            std::ofstream rejects;
            rejects.open(error_file, std::ifstream::out);
            data_api.print_errors(rejects);
            rejects << std::endl;
            rejects.close();
        }
    }


    out.close();

    if (fail || data_api.failed_conversions() || rule_api.failed_conversions())
        return -2;
    return 0;
}
