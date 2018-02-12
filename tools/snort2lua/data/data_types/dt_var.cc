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
// dt_var.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "data/data_types/dt_var.h"
#include "data/dt_data.h"
#include "helpers/s2l_util.h"

Variable::Variable(const std::string& name, int depth)
{
    this->name = name;
    this->depth = depth;
}

Variable::~Variable()
{
    for (VarData* v : vars)
        delete v;
}

std::string Variable::get_value(DataApi* ld)
{
    std::string variable;
    bool first_line = true;

    for (auto v : vars)
    {
        if (first_line)
            first_line = false;
        else
            variable.push_back(' ');

        if (v->type == VarType::STRING)
            variable.append(std::string(v->data));
        else
            variable.append(std::string(ld->translate_variable(v->data)));
    }

    return variable;
}

void Variable::set_value(std::string val, bool quoted)
{
    VarData* vd = new VarData();
    vd->type = quoted ? VarType::STRING : VarType::VARIABLE;
    vd->data = val;
    vars.push_back(vd);
}

// does this need a new variable?
bool Variable::add_value(std::string elem)
{
    std::string s;
    std::string end;
    util::trim(elem);

    if (elem.size() <= 1)
    {
        s = elem;
        end = "";
    }
    else
    {
        const std::size_t pos = elem.find('$', 1);
        if (pos == std::string::npos)
        {
            s = elem;
            end = "";
        }
        else
        {
            s = elem.substr(0, pos);
            end = elem.substr(pos, std::string::npos);
        }
    }

    if (s.front() == '$')
    {
        // add a space between strings
        if (!vars.empty())
        {
            if (vars.back()->type == VarType::STRING)
                vars.back()->data += " ";
            else
                add_value(" ");
        }

        s.erase(s.begin());
        VarData* vd = new VarData();
        vd->type = VarType::VARIABLE;
        vd->data = s;
        vars.push_back(vd);
    }
    else if (!vars.empty() && vars.back()->type == VarType::STRING)
    {
        VarData* vd = vars.back();
        vd->data += " " + s;
    }
    else
    {
        VarData* vd = new VarData();
        vd->type = VarType::STRING;

        // if the previous variable was a symbol, we need a space separator.
        if (!vars.empty())
            s.insert(0, " ");

        vd->data = s;
        vars.push_back(vd);
    }

    if (!end.empty())
        return add_value(end);

    return true;
}

static inline void print_newline(std::ostream& out,
    std::size_t& count,
    const std::string& whitespace)
{
    out << "\n" << whitespace;
    count = whitespace.size();
}

std::ostream& operator<<(std::ostream& out, const Variable& var)
{
    std::string whitespace;
    bool first_var = true;
    std::size_t count = 0;

    for (int i = 0; i < var.depth; i++)
        whitespace += "    ";

    out << (var.print_whitespace ? whitespace : "") << var.name << " = ";

    if ( var.print_whitespace )
        count += whitespace.size();

    count += var.name.size() + 3;

    if ( var.print_whitespace )
        whitespace += "    ";

    for (Variable::VarData* v : var.vars)
    {
        // keeping lines below max_line_length characters
        if ((count + 4) > var.max_line_length)
            print_newline(out, count, whitespace);

        // string concatenation
        if (!first_var)
        {
            out << " .. ";
            count += 4;
        }
        else
            first_var = false;

        // print string
        if ( v->type == Variable::VarType::VARIABLE )
        {
            if ( var.print_whitespace && v->data.size() + count > var.max_line_length )
                print_newline(out, count, whitespace);

            out << v->data;
            count += v->data.size();
        }
        else if ( !var.print_whitespace || (count + v->data.size()) < var.max_line_length )
        {
            out << "'" << v->data << "'";
            count += v->data.size() + 2;
        }
        else
        {
            if (count + 3 > var.max_line_length)
                print_newline(out, count, whitespace);

            util::sanitize_lua_string(v->data);
            out << "[[ ";
            count += 3;

            std::size_t printed_length = 0;
            std::size_t str_size = v->data.size();
            bool first_loop = true;

            while (printed_length < str_size)
            {
                if (first_loop)
                    first_loop = false;
                else
                    print_newline(out, count, whitespace);

                while (isspace(v->data[printed_length]))
                    printed_length++;

                std::string tmp = v->data.substr(printed_length);

                if (var.max_line_length < count)
                {
                    out << "FATAL ERROR: dt_var.cc - underflow! was "
                        "not reset" << std::endl;
                }
                else
                {
                    std::size_t remaining_space = var.max_line_length - count;
                    std::size_t str_len = util::get_substr_length(tmp, remaining_space);
                    out << tmp.substr(0, str_len);

                    count += str_len;
                    printed_length += str_len;
                }
            }

            out << " ]]";
            count += 3;
        }
    }

    return out;
}

