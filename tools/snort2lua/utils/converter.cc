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
// converter.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "utils/converter.h"
#include "conversion_state.h"
#include "data/data_types/dt_comment.h"
#include "utils/s2l_util.h"
#include "init_state.h"



bool Converter::parse_includes = true;
bool Converter::convert_rules_mult_files = true;
bool Converter::convert_conf_mult_files = true;


Converter::Converter()
    :   state(nullptr),
        error(false)
{
}

Converter::~Converter()
{
    if (state)
        delete state;
}

void Converter::set_state(ConversionState* c)
{
    delete state;
    state = c;
}

void Converter::reset_state()
{
    if (state)
        delete state;

    state = new InitState(*this);
    data_api.reset_state();
    table_api.reset_state();
    rule_api.reset_state();
}

// FIXIT-M J  Fix this -- rule, table, and data should be associated with a Converter
void Converter::parse_include_file(std::string input_file)
{
    std::vector<Variable*> vars;
    std::vector<Table*> tables;
    std::vector<Rule*> rules;
    std::vector<Include*> includes;
    Comments* comments;

    // TODO get rid of any variables in the name

    if (convert_conf_mult_files)
    {
        comments = new Comments(start_comments, 0,
                    Comments::CommentType::MULTI_LINE);

        data_api.swap_conf_data(vars, includes, comments);
        table_api.swap_tables(tables);
    }

    if (convert_rules_mult_files)
        rule_api.swap_rules(rules);



    if (parse_file(input_file) < 0)
        error = true; // return a negative number to main snort2lua method


    if (convert_conf_mult_files)
    {
        // print configuration file
        if (!table_api.empty() || data_api.empty())
        {
            std::ofstream out;
            out.open(input_file + ".lua");
            data_api.print_data(out);
            table_api.print_tables(out);
            data_api.print_comments(out);
            out << std::endl;
            out.close();

            data_api.add_include_file(input_file + ".lua");
        }

        data_api.swap_conf_data(vars, includes, comments);
        table_api.swap_tables(tables);
        delete comments;
    }


    if (convert_rules_mult_files)
    {
        if (!rule_api.empty())
        {
            std::ofstream out;
            out.open(input_file + ".rules");
            rule_api.print_rules(out, true); // true == output to rule file, NOT lua file
            out.close();

            rule_api.add_hdr_data("include " + input_file + ".rules");
        }

        rule_api.swap_rules(rules);
    }
}

int Converter::parse_file(std::string input_file)
{
    std::ifstream in;
    std::string orig_text;

    // theoretically, I can save this state.  But there's
    // no need since any function calling this method
    // will set the state when it's done anyway.
    reset_state();

    if (!util::file_exists(input_file))
        return -1;

    in.open(input_file, std::ifstream::in);
    while(!in.eof())
    {
        std::string tmp;
        std::getline(in, tmp);
        util::rtrim(tmp);

        std::size_t first_non_white_char = tmp.find_first_not_of(' ');
        if ((first_non_white_char == std::string::npos) ||
                 (tmp[first_non_white_char] == '#') ||
                 (tmp[first_non_white_char] == ';')) // no, i did not know that semicolons made a line a comment
        {
            util::trim(tmp);

            if (!tmp.empty())
            {
                // first charachter is either a '#' or a ';'
                tmp.erase(tmp.begin());
                util::ltrim(tmp);
            }

            data_api.add_comment(tmp);
        }
        else if ( tmp[tmp.find_last_not_of(' ')] == '\\')
        {
            util::rtrim(tmp);
            tmp.pop_back();
            orig_text += tmp;
        }
        else
        {
            orig_text += tmp;
            std::istringstream data_stream(orig_text);
            while(data_stream.peek() != EOF)
            {
                if ((state == nullptr) || !state->convert(data_stream))
                {
                    data_api.failed_conversion(data_stream);
                    break;
                }
            }

            orig_text.clear();
            reset_state();
        }
    }

    // this is set by parse_include_file
    return error ? -3 : 0;
}

bool Converter::initialize()
{
    state = new InitState(*this);

    if (state == nullptr)
    {
        DataApi::developer_error("Failed Converter initialization!");
        return false;
    }

    return true;
}

int Converter::convert(std::string input,
                        std::string output_file,
                        std::string rule_file,
                        std::string error_file)
{
    int rc;
    initialize();

    rc = parse_file(input);

    if (rc < 0)
        return rc;


    // keep track whether we're printing rules into a seperate file.
    bool rule_file_specifed = false;


    if (!rule_api.empty())
    {
        std::cout << "rule_file" << rule_file << std::endl;
        std::cout << "out_file " << output_file << std::endl;
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
    data_api.print_data(out);


    if (!rule_file_specifed)
    {
        rule_api.print_rules(out, rule_file_specifed);
    }
    else
    {
        std::ofstream rules;
        rules.open(rule_file, std::ifstream::out);
        rule_api.print_rules(rules, rule_file_specifed);
        rules.close();
    }


    table_api.print_tables(out);
    data_api.print_comments(out);



    if ((failed_conversions()) && !DataApi::is_quiet_mode())
    {
        if (error_file.empty())
        {
            if (data_api.failed_conversions())
                data_api.print_errors(out);

            if (rule_api.failed_conversions())
                rule_api.print_rejects(out);
        }
        else
        {
            std::ofstream rejects;  // in this case, rejects are regular configuration options
            rejects.open(error_file, std::ifstream::out);

            if (data_api.failed_conversions())
                data_api.print_errors(rejects);

            if (rule_api.failed_conversions())
                rule_api.print_rejects(rejects);

            rejects.close();
        }
    }


    out.close();
    return rc;
}
