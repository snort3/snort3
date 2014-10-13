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

Converter cv;

Converter::Converter()
    :   state(nullptr),
        init_state_ctor(nullptr),
        parse_includes(true),
        convert_rules_mult_files(true),
        convert_conf_mult_files(true),
        error(false)
{
}

Converter::~Converter()
{
    if (state)
        delete state;
}

bool Converter::initialize(conv_new_f func)
{
    init_state_ctor = func;
    state = init_state_ctor();

    if (state == nullptr)
    {
        data_api.developer_error("Failed Converter initialization!");
        return false;
    }

    return true;
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

    state = init_state_ctor();
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



    if (convert_file(input_file) < 0)
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

int Converter::convert_file(std::string input_file)
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
