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
// converter.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "converter.h"

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <unordered_map>

#include "helpers/converter.h"
#include "conversion_state.h"
#include "data/data_types/dt_comment.h"
#include "data/data_types/dt_rule.h"
#include "data/data_types/dt_table.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"
#include "init_state.h"

TableDelegation table_delegation = 
{
    { "binder", true },
    { "ips", true },
    { "network", true },
    { "normalizer", true},
};

std::string Converter::ips_pattern;
bool Converter::parse_includes = true;
bool Converter::empty_args = false;
bool Converter::convert_rules_mult_files = true;
bool Converter::convert_conf_mult_files = true;
bool Converter::bind_wizard = false;

Converter::Converter() :
    table_api(&top_table_api, table_delegation),
    state(nullptr),
    error(false),
    multiline_state(false)
{ }

Converter::~Converter()
{
    if (state)
        delete state;
}

void Converter::set_state(ConversionState* c, bool delete_old)
{
    if ( delete_old && state )
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

int Converter::parse_include_file(const std::string& input_file)
{
    std::vector<Variable*> vars;
    std::vector<Table*> tables;
    std::vector<Rule*> rules;
    std::vector<Include*> includes;
    Comments* comments;
    Comments* unsupported;

    int rc;

    if (!parse_includes)
        return 0;

    // FIXIT-L get rid of any variables in the name

    if (convert_conf_mult_files)
    {
        comments = new Comments(start_comments, 0,
            Comments::CommentType::MULTI_LINE);

        unsupported = new Comments(start_unsupported, 0,
            Comments::CommentType::MULTI_LINE);

        data_api.swap_conf_data(vars, includes, comments, unsupported);
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
            data_api.print_unsupported(out);
            data_api.print_comments(out);
            out << std::endl;
            out.close();

            include_file = true;
        }

        data_api.swap_conf_data(vars, includes, comments, unsupported);
        table_api.swap_tables(tables);
        delete comments;
        delete unsupported;

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

int Converter::parse_file(
    const std::string& input_file,
    const std::string* rule_file,
    bool reset)
{
    std::ifstream in;
    std::ofstream rules;
    std::string orig_text;

    bool line_by_line = rule_file and input_file.length() >= 6 and
        input_file.substr(input_file.length() - 6) == ".rules";

    if ( line_by_line )
    {
        rules.open(*rule_file, std::ifstream::out);
        rule_api.print_rules(rules, true);
    }
    // theoretically, I can save this state.  But there's
    // no need since any function calling this method
    // will set the state when it's done anyway.
    if ( reset )
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

        if ( tmp.empty() )
            continue;

        // same critea used for rtrim
        // http://en.cppreference.com/w/cpp/string/byte/isspace
        std::size_t first_non_white_char = tmp.find_first_not_of(" \f\n\r\t\v");

        bool comment = (tmp[first_non_white_char] == '#') or (tmp[first_non_white_char] == ';');
        bool commented_rule = tmp.substr(0, 7) == "# alert";

        if ( !commented_rule && ((first_non_white_char == std::string::npos) || comment) )
        {
            if ( line_by_line )
                rules << tmp << std::endl;

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

            if (commented_rule)
            {
                std::string hash_char;
                data_stream >> hash_char;
            }

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
                if (commented_rule)
                    rule_api.make_rule_a_comment();

                if ( line_by_line )
                {
                    rule_api.print_rules(rules, true);
                    rule_api.clear();
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

            if ( reset && !multiline_state )
                reset_state();
        }
    }
    if ( line_by_line )
    {
        rules.close();
        rule_api.reset_state();
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

Binder& Converter::make_binder(Binder& b)
{
    binders.push_back(std::make_shared<Binder>(b));
    return *binders.back();
}

Binder& Converter::make_binder()
{
    binders.push_back(std::make_shared<Binder>(table_api));
    return *binders.back();
}

Binder& Converter::make_pending_binder(int ips_policy_id)
{
    PendingBinder b(ips_policy_id, std::make_shared<Binder>(table_api));
    pending_binders.push_back(b);
    return *pending_binders.back().second;
}

void Converter::add_bindings()
{
    std::unordered_map<int, std::shared_ptr<Binder>> policy_map;
    for ( auto& b : binders )
    {
        if ( b->has_ips_policy_id() && b->get_use_file().second == Binder::IT_FILE )
            policy_map[b->get_when_ips_policy_id()] = b;
    }

    for ( auto it = pending_binders.rbegin(); it != pending_binders.rend(); it++ )
    {
        auto& pb = *it;
        auto result = policy_map.find(pb.first);

        if ( result == policy_map.end() )
        {
            pb.second->print_binding(false);
            data_api.error("Unable to satisfy pending binding for policy id " +
                std::to_string(pb.first));

            continue;
        }

        auto b = result->second;
        b->print_binding(false);  // FIXIT-M is it desired to keep this around? not for nap case

        // FIXIT-M as of writing, this assumes pending is only for nap rules
        pb.second->set_use_file(b->get_use_file().first, Binder::IT_INSPECTION);

        pb.second->set_use_type(b->get_use_type());
        pb.second->set_use_name(b->get_use_name());
        pb.second->set_use_service(b->get_use_service());
        pb.second->set_use_action(b->get_use_action());

        binders.push_back(pb.second);
    }
    pending_binders.clear();
    policy_map.clear();

    // vector::clear()'s ordering isn't deterministic but this is
    // keep in place for stable regressions
    std::stable_sort(binders.rbegin(), binders.rend());
    while ( !binders.empty() )
        binders.pop_back();
}

int Converter::convert(
    const std::string& input,
    const std::string& output_file,
    std::string rule_file,
    std::string error_file)
{
    int rc;
    initialize();

    if (rule_file.empty())
        rule_file = output_file;

    rc = parse_file(input, &rule_file);

    if ( bind_wizard )
    {
        // add wizard = default_wizard before binder
        data_api.set_variable("wizard", "default_wizard", false);

        // add binding for wizard at bottom of table
        auto& wiz = make_binder();
        wiz.set_use_type("wizard");
        wiz.set_priority(Binder::PRIORITY_LAST);
    }

    add_bindings();

    if (error_file.empty())
        error_file = output_file + ".rej";

    if (!rule_api.empty() &&
        table_api.empty() &&
        top_table_api.empty() &&
        data_api.empty())
    {
        std::ofstream rules;
        rules.open(rule_file, std::ifstream::out);
        rule_api.print_rules(rules, true);

        if (!DataApi::is_quiet_mode() && rule_api.failed_conversions())
        {
            if (error_file == rule_file)
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
    else if (!rule_api.empty() || !table_api.empty() ||
             !top_table_api.empty() || !data_api.empty())
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
            if (rule_file.empty() || rule_file == output_file)
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
        top_table_api.print_tables(out);
        data_api.print_unsupported(out);
        data_api.print_comments(out);

        if ((failed_conversions()) && !DataApi::is_quiet_mode())
        {
            if (error_file == output_file)
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

