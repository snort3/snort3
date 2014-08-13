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

#include <iostream>
#include "utils/converter.h"
#include "conversion_state.h"
#include "utils/s2l_util.h"
#include "data/dt_comment.h"


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

bool Converter::initialize(conv_new_f func, LuaData* ld)
{
    init_state_ctor = func;
    this->ld = ld;
    state = init_state_ctor(this, ld);

    if (state == nullptr)
    {
        std::cout << "Failed Converter initialization!" << std::endl;
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

    state = init_state_ctor(this, ld);
    ld->reset_state();
}

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
        ld->swap_conf_data(vars, tables, includes, comments);
    }

    if (convert_rules_mult_files)
        ld->swap_rules(rules);

    if (convert_file(input_file) < 0)
    {
        if (convert_conf_mult_files)
        {
            ld->swap_conf_data(vars, tables, includes, comments);
            delete comments;
        }

        if (convert_rules_mult_files)
            ld->swap_rules(rules);

        // add this new file as a snort style rule
        error = true;
        ld->add_hdr_data("include " + input_file);
        return;
    }


    if (convert_conf_mult_files)
    {
        // print configuration file
        std::ofstream out;
        out.open(input_file + ".lua");
        ld->print_conf_options(out);
        out << std::endl;
        out.close();

        ld->swap_conf_data(vars, tables, includes, comments);
        ld->add_include_file(input_file + ".lua");
        delete comments;
    }

    if (convert_rules_mult_files)
    {
        std::ofstream out;
        out.open(input_file + ".rules");
        ld->print_rules(out, true); // true == output to rule file, NOT lua file
        out.close();
        ld->swap_rules(rules);


        // add this new file as a snort style rule
        ld->add_hdr_data("include " + input_file + ".rules");
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

            ld->add_comment(tmp);
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
                    ld->failed_conversion(data_stream);
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
