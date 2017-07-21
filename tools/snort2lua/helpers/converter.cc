//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// converter.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <stdexcept>

#include "helpers/converter.h"
#include "conversion_state.h"
#include "data/data_types/dt_comment.h"
#include "data/data_types/dt_rule.h"
#include "data/data_types/dt_table.h"
#include "helpers/s2l_util.h"
#include "init_state.h"

bool Converter::parse_includes = true;
bool Converter::empty_args = false;
bool Converter::convert_rules_mult_files = true;
bool Converter::convert_conf_mult_files = true;

Converter::Converter()
    :   state(nullptr),
    error(false),
    multiline_state(false)
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

int Converter::parse_include_file(std::string input_file)
{
    std::vector<Variable*> vars;
    std::vector<Table*> tables;
    std::vector<Rule*> rules;
    std::vector<Include*> includes;
    Comments* comments;
    int rc;

    if (!parse_includes)
        return 0;

    // FIXIT-L get rid of any variables in the name

    if (convert_conf_mult_files)
    {
        comments = new Comments(start_comments, 0,
            Comments::CommentType::MULTI_LINE);

        data_api.swap_conf_data(vars, includes, comments);
        table_api.swap_tables(tables);
    }

    if (convert_rules_mult_files)
        rule_api.swap_rules(rules);

    rc = parse_file(input_file);

    if (convert_conf_mult_files)
    {
        bool include_file = false;

        // print configuration file
        if (!table_api.empty() || !data_api.empty())
        {
            std::ofstream out;
            out.open(input_file + ".lua");
            data_api.print_data(out);
            table_api.print_tables(out);
            data_api.print_comments(out);
            out << std::endl;
            out.close();

            include_file = true;
        }

        data_api.swap_conf_data(vars, includes, comments);
        table_api.swap_tables(tables);
        delete comments;

        if (include_file)
            data_api.add_include_file(input_file + ".lua");
    }

    if (convert_rules_mult_files)
    {
        bool include_rules = false;

        if (!rule_api.empty())
        {
            std::ofstream out;
            out.open(input_file + ".rules");
            rule_api.print_rules(out, true); // true == output to rule file, NOT lua file
            out.close();

            include_rules = true;
        }

        rule_api.swap_rules(rules);

        if (include_rules)
            rule_api.include_rule_file(input_file + ".rules");
    }

    for (auto r : rules)
        delete r;

    for (auto t : tables)
        delete t;

    return rc;
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
    unsigned line_num = 0;
    while (!in.eof())
    {
        std::string tmp;
        std::getline(in, tmp);
        util::rtrim(tmp);

        data_api.set_current_file(input_file); //Set at each line to handle recursion correctly
        data_api.set_current_line(++line_num);

        std::size_t first_non_white_char = tmp.find_first_not_of(' ');
        if ((first_non_white_char == std::string::npos) ||
            (tmp[first_non_white_char] == '#') ||
            (tmp[first_non_white_char] == ';'))      // no, i did not know that semicolons made a
                                                     // line a comment
        {
            util::trim(tmp);

            if (!tmp.empty())
            {
                // first character is either a '#' or a ';'
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

            try
            {
                while (data_stream.peek() != EOF)
                {
                    if ((state == nullptr) || !state->convert(data_stream))
                    {
                        data_api.failed_conversion(data_stream);
                        break;
                    }
                }
                if(empty_args)
                {
                    set_empty_args(false);
                    if (state && !state->convert(data_stream))
                    {
                        data_api.failed_conversion(data_stream);
                    }
                }
            }
            catch (const std::invalid_argument& e)
            {
                data_api.failed_conversion(data_stream, e.what());
            }
            catch (const std::out_of_range& e)
            {
                data_api.failed_conversion(data_stream, e.what());
            }

            orig_text.clear();

            if ( !multiline_state )
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

    if (rule_file.empty())
        rule_file = output_file;

    if (error_file.empty())
        error_file = output_file + ".rej";

    if (!rule_api.empty() &&
        table_api.empty() &&
        data_api.empty())
    {
        std::ofstream rules;
        rules.open(rule_file, std::ifstream::out);
        rule_api.print_rules(rules, true);

        if (!DataApi::is_quiet_mode() && rule_api.failed_conversions())
        {
            if (!error_file.compare(rule_file))
            {
                rule_api.print_rejects(rules);
            }
            else
            {
                std::ofstream rejects;  // in this case, rejects are regular configuration options
                rejects.open(error_file, std::ifstream::out);
                rule_api.print_rejects(rejects);
                rejects.close();
            }
        }

        rules.close();
    }
    else if (!rule_api.empty() || !table_api.empty() || !data_api.empty())
    {
        // finally, lets print the converter to file
        std::ofstream out;
        out.open(output_file,  std::ifstream::out);

        out << "---------------------------------------------------------------------------\n";
        out << "-- Snort++ prototype configuration\n";
        out << "---------------------------------------------------------------------------\n";
        out << "\n";
        out << "---------------------------------------------------------------------------\n";
        out << "-- setup environment\n";
        out << "---------------------------------------------------------------------------\n";
        out << "-- given:\n";
        out << "-- export DIR=/install/path\n";
        out << "-- configure --prefix=$DIR\n";
        out << "-- make install\n";
        out << "--\n";
        out << "-- then:\n";
        out << "-- export LUA_PATH=$DIR/include/snort/lua/?.lua\\;\\;\n";
        out << "-- export SNORT_LUA_PATH=$DIR/conf/\n";
        out << "---------------------------------------------------------------------------\n";
        out << "\n";
        out << "\n";
        out << "\n";
        out << "require(\"snort_config\")\n\n";
        out << "dir = os.getenv('SNORT_LUA_PATH')\n";
        out << "\n";
        out << "if ( not dir ) then\n";
        out << "    dir = '.'\n";
        out << "end\n";
        out << "\n";
        out << "dofile(dir .. '/snort_defaults.lua')\n";
        out << "\n";
        out << "\n";
        data_api.print_data(out);

        if (!rule_api.empty())
        {
            if (rule_file.empty() || !rule_file.compare(output_file))
            {
                rule_api.print_rules(out, false);

                std::string s = std::string("$local_rules");
                table_api.open_top_level_table("ips");
                table_api.add_option("rules", s);
                table_api.close_table();
            }
            else
            {
                std::ofstream rules;
                rules.open(rule_file, std::ifstream::out);
                rule_api.print_rules(rules, true);
                rules.close();

                table_api.open_top_level_table("ips");
                table_api.add_option("include", rule_file);
                table_api.close_table();
            }
        }

        table_api.print_tables(out);
        data_api.print_comments(out);

        if ((failed_conversions()) && !DataApi::is_quiet_mode())
        {
            if (!error_file.compare(output_file))
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
    }

    if (failed_conversions())
    {
        std::size_t errors = data_api.num_errors() + rule_api.num_errors();
        std::cerr << "ERROR: " << errors << " errors occurred while converting\n";
        std::cerr << "ERROR: see " << error_file << " for details" << std::endl;
        std::ofstream rejects;  // in this case, rejects are regular configuration options
        rejects.open(error_file, std::ifstream::out);

        if (data_api.failed_conversions())
            data_api.print_errors(rejects);

        if (rule_api.failed_conversions())
            rule_api.print_rejects(rejects);

        rejects.close();
    }
    return rc;
}

