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
// dt_var.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include "data/dt_var.h"
#include "util/util.h"

Variable::Variable(std::string name, int depth)
{
    this->name = name;
    this->depth = depth;
}

Variable::Variable(std::string name)
{
    this->name = name;
    this->depth = 0;
}

Variable::~Variable(){};

// does this need a new variable?
bool Variable::add_value(std::string elem)
{
    std::string s(elem);
    util::trim(elem);

    if(s.front() == '$')
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
        VarData *vd = new VarData();
        vd->type = VarType::VARIABLE;
        vd->data = s;
        vars.push_back(vd);
    }
    else if (!vars.empty() && vars.back()->type == VarType::STRING)
    {
        VarData *vd = vars.back();
        vd->data += " " + s;
    }
    else
    {
        VarData *vd = new VarData();
        vd->type = VarType::STRING;

        // if the previous variable was a symbol, we need a space seperator.
        if (!vars.empty())
            s.insert(0, " ");

        vd->data = s;
        vars.push_back(vd);
    }

    return true;
}

static inline void print_newline(std::ostream& out,
                                 std::size_t& count,
                                 std::string whitespace)
{
    out << "\n" << whitespace;
    count = whitespace.size();
}

std::ostream& operator<<( std::ostream& out, const Variable &var)
{
    std::string whitespace;
    bool first_var = true;
    std::size_t count = 0;

    for(int i = 0; i < var.depth; i++)
        whitespace += "    ";

    out << whitespace << var.name << " = ";
    count += whitespace.size() + var.name.size() + 3;
    whitespace += "    ";

    for(Variable::VarData *v : var.vars)
    {
        // keeping lines below max_line_length charachters
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
        if (v->type == Variable::VarType::VARIABLE)
        {
            if (v->data.size() + count > var.max_line_length)
                print_newline(out, count, whitespace);

            out << v->data;
            count += v->data.size();
        }

        else if ((count + v->data.size()) < var.max_line_length)
        {
            out << "'" << v->data << "'";
            count += v->data.size() + 2;
        }

        else
        {
            if (count + 3 > var.max_line_length)
                print_newline(out, count, whitespace);


            util::sanitize_multi_line_string(v->data);
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


                while(isspace(v->data[printed_length]))
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
