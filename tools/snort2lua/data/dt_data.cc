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
// dt_data.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "dt_data.h"
#include "helpers/s2l_util.h"
#include <iostream>
#include <sstream>
#include <cstring>

#include "data/data_types/dt_table.h"
#include "data/data_types/dt_var.h"
#include "data/data_types/dt_comment.h"
#include "data/data_types/dt_rule.h"
#include "data/data_types/dt_include.h"

DataApi::PrintMode DataApi::mode = DataApi::PrintMode::DEFAULT;
std::size_t DataApi::dev_warnings = 0;
std::size_t DataApi::errors_count = 0;

DataApi::DataApi() : curr_data_bad(false)
{
    comments = new Comments(start_comments, 0,
        Comments::CommentType::MULTI_LINE);
    errors = new Comments(start_errors, 0,
        Comments::CommentType::MULTI_LINE);
    unsupported = new Comments(start_unsupported, 0,
        Comments::CommentType::MULTI_LINE);
}

DataApi::~DataApi()
{
    for (auto v : vars)
        delete v;

    for (auto i : includes)
        delete i;

    delete comments;
    delete errors;
    delete unsupported;
}

std::string DataApi::translate_variable(const std::string& var_name)
{
    for (auto v : vars)
        if (var_name == v->get_name())
            return v->get_value(this);

    return std::string();
}

/*
 * I am ashamed to say, but I have absolutely no idea what
 * Snort attempts to do when 'expanding' variables.  Since I also
 * have absolutely no inclination to figure out this mess,
 * I copied the Snort version of ExpandVars and made some
 * minor adjustments.
 *
 * Given a Snort style string to expand, this function will return
 * the expanded string
 */
std::string DataApi::expand_vars(const std::string& string)
{
    std::string estring;
    estring.resize(1024, '\0');

    char rawvarname[128], varname[128], varaux[128], varbuffer[128];
    char varmodifier;
    const char* varcontents;
    std::size_t varname_completed, i, j, iv, jv, l_string, name_only;
    int quote_toggle = 0;

    if (string.empty() || string.rfind('$') == std::string::npos)
        return string;

    i = j = 0;
    l_string = string.size();

    while (i < l_string && j < std::string::npos)
    {
        char c = string[i++];

        if (c == '"')
        {
            /* added checks to make sure that we are inside a quoted string
             */
            quote_toggle ^= 1;
        }

        if (c == '$' && !quote_toggle)
        {
            std::memset((char*)rawvarname, 0, sizeof(rawvarname));
            varname_completed = 0;
            name_only = 1;
            iv = i;
            jv = 0;

            if (string[i] == '(')
            {
                name_only = 0;
                iv = i + 1;
            }

            while (!varname_completed
                && iv < l_string
                && jv < (int)sizeof(rawvarname) - 1)
            {
                c = string[iv++];

                if ((name_only && !(isalnum(c) || c == '_'))
                    || (!name_only && c == ')'))
                {
                    varname_completed = 1;

                    if (name_only)
                        iv--;
                }
                else
                {
                    rawvarname[jv++] = (char)c;
                }
            }

            if (varname_completed || iv == l_string)
            {
                char* p;

                i = iv;

                varcontents = nullptr;

                std::memset((char*)varname, 0, sizeof(varname));
                std::memset((char*)varaux, 0, sizeof(varaux));
                varmodifier = ' ';

                p = strchr(rawvarname, ':');
                if (p)
                {
                    std::strncpy(varname, rawvarname, (std::size_t)(p - rawvarname));

                    if (strlen(p) >= 2)
                    {
                        varmodifier = *(p + 1);
                        std::strncpy(varaux, p + 2, sizeof(varaux));
                    }
                }
                else
                    std::strncpy(varname, rawvarname, sizeof(varname));

                std::memset((char*)varbuffer, 0, sizeof(varbuffer));

                std::string tmp = translate_variable(varname);
                varcontents = tmp.c_str();

                switch (varmodifier)
                {
                case '-':
                    if (!varcontents || !strlen(varcontents))
                        varcontents = varaux;
                    break;

                case '?':
                    if (!varcontents || !strlen(varcontents))
                        return std::string();
                    break;
                }

                /* If variable not defined now, we're toast */
                if (!varcontents || !strlen(varcontents))
                {
                    return std::string();
                }

                if (varcontents)
                {
                    std::size_t l_varcontents = strlen(varcontents);

                    iv = 0;

                    if (estring.size() < j + l_varcontents)
                        estring.resize(estring.size() * 2);

                    while (iv < l_varcontents && j < estring.size() - 1)
                        estring[j++] = varcontents[iv++];
                }
            }
            else
            {
                if (estring.size() < j+ 1)
                    estring.resize(estring.size() * 2, '\0');

                estring[j++] = '$';
            }
        }
        else
        {
            if (estring.size() < j+ 1)
                estring.resize(estring.size() * 2, '\0');

            estring[j++] = (char)c;
        }
    }

    if (estring.size() < j)
        estring.resize(estring.size() + 1, '\0');
    else
        estring.resize(j);

    estring[j] = '\0';
    return estring;
}

bool DataApi::failed_conversions() const
{ return errors_count > 0; }

std::size_t DataApi::num_errors() const
{ return errors_count; }

std::string DataApi::get_file_line()
{
    std::string error_string = "Failed to convert ";
    error_string += *current_file + ":";
    error_string += std::to_string(current_line);
    return error_string;
}

void DataApi::error(const std::string& error)
{
    errors->add_text(error);
    errors_count++;
}

void DataApi::failed_conversion(const std::istringstream& stream, const std::string& unknown_option)
{
    // we only need to go through this once.
    if (!curr_data_bad)
    {
        errors->add_text(std::string());
        errors->add_text(get_file_line());
        errors->add_text(stream.str());
        curr_data_bad = true;
        errors_count++;
    }
    if ( !unknown_option.empty() )
        errors->add_text("^^^^ unknown_syntax=" + unknown_option);
}

void DataApi::set_variable(const std::string& name, const std::string& value, bool quoted)
{
    Variable* var = new Variable(name);
    vars.push_back(var);
    var->set_value(value, quoted);
}

bool DataApi::add_variable(const std::string& name, const std::string& value)
{
    for (auto v : vars)
        if (name == v->get_name())
            return v->add_value(value);

    Variable* var = new Variable(name);
    vars.push_back(var);
    return var->add_value(value);
}

void DataApi::reset_state()
{
    curr_data_bad = false;
}

bool DataApi::add_include_file(const std::string& file_name)
{
    Include* incl = new Include(file_name);

    if (incl == nullptr)
        return false;

    includes.push_back(incl);
    return true;
}

void DataApi::developer_error(const std::string& error_string)
{
    dev_warnings++;

    if (!is_quiet_mode())
        std::cout << "RUNTIME ERROR: " << error_string << std::endl;
}

void DataApi::add_comment(const std::string& c)
{ comments->add_text(c); }

void DataApi::add_unsupported_comment(const std::string& c)
{ unsupported->add_text(c); }

void DataApi::print_errors(std::ostream& out)
{
    if (is_default_mode() &&
        !errors->empty())
    {
        out << (*errors) << "\n";
    }
}

void DataApi::print_data(std::ostream& out)
{
    for (Variable* v : vars)
        out << (*v) << "\n\n";

    for (Include* i : includes)
        out << (*i) << "\n\n";
}

void DataApi::print_comments(std::ostream& out)
{
    if (is_default_mode() && !comments->empty())
        out << (*comments) << "\n";
}

void DataApi::print_unsupported(std::ostream& out)
{
    if (is_default_mode() && !unsupported->empty())
        out << (*unsupported) << "\n";
}

void DataApi::swap_conf_data(std::vector<Variable*>& new_vars,
    std::vector<Include*>& new_includes,
    Comments*& new_comments, Comments*& new_unsupported)
{
    vars.swap(new_vars);
    includes.swap(new_includes);

    Comments* tmp = new_comments;
    new_comments = comments;
    comments = tmp;

    tmp = new_unsupported;
    new_unsupported = unsupported;
    unsupported = tmp;
}

