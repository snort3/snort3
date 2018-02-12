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
// dt_comment.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "data/data_types/dt_comment.h"
#include "helpers/s2l_util.h"

static const std::size_t real_max_line_length = 80;
static const std::string start_multi_com = "--[[";
static const std::string end_multi_com = "--]]";

Comments::Comments(CommentType t)
{
    this->depth = 0;
    this->prev_empty = true;
    this->type = t;
    this->header = false;
}

Comments::Comments(int d, CommentType t)
{
    this->depth = d;
    this->prev_empty = true;
    this->type = t;
    this->header = false;
}

Comments::Comments(const std::string& c, int d, CommentType t)
{
    this->comment.push_back(std::string(c));
    this->depth = d;
    this->prev_empty = true;
    this->type = t;
    this->header = true;
}

void Comments::add_text(const std::string& text)
{
    if ( !(text.empty() && prev_empty) )
    {
        comment.push_back(std::string(text));
        prev_empty = text.empty();
    }
}

void Comments::add_sorted_text(const std::string& new_text)
{
    for (auto it = comment.begin(); it != comment.end(); ++it)
    {
        if (new_text.compare(*it) < 0)
        {
            comment.insert(it, new_text);
            return;
        }
        // no duplicates
        else if ((*it) == new_text)
            return;
    }

    comment.push_back(new_text);
}

bool Comments::empty() const
{
    return ((comment.empty()) ||
           (comment.size() == 1 && header));
}

bool Comments::size() const
{ return header ? comment.size() - 1 : comment.size(); }

std::ostream& operator<<(std::ostream& out, const Comments& c)
{
    std::string whitespace;
    std::string pre_str;
    bool first_str = true;

    if (c.comment.empty())
        return out;

    for (int i = 0; i < c.depth; i++)
        whitespace += "    ";

    // creating the correct format for strings
    if (c.type == Comments::CommentType::SINGLE_LINE)
    {
        pre_str = whitespace + "--";
    }
    else
    {
        out << start_multi_com;
        pre_str = whitespace + "    ";
    }

    const std::size_t pre_str_length = pre_str.size();

    for (std::string str : c.comment)
    {
        bool first_line = true;
        std::string curr_pre_str = pre_str;
        std::size_t max_line_length = real_max_line_length - pre_str_length - 1;

        // print a newline between strings, but not before the first line.
        if (first_str)
            first_str = false;
        else
            out << "\n";

        // if the line is empty, we need a newline. the loop won't print it.
        if (str.empty())
            out << "\n";

        else if (c.type == Comments::CommentType::MULTI_LINE)
            util::sanitize_lua_string(util::ltrim(str));

        while (!str.empty())
        {
            std::size_t substr_len = max_line_length;

            // determine the first space before 80 characters
            // if there are no spaces, print the entire string
            if (substr_len < str.size())
            {
                substr_len = str.rfind(' ', max_line_length);

                if (substr_len == std::string::npos)
                {
                    substr_len = str.find(' ');

                    if (substr_len == std::string::npos)
                        substr_len = str.size();
                }
            }

            // don't print the extra '\n' on the first line.
            if (first_line)
            {
                out << curr_pre_str << str.substr(0, substr_len);
                curr_pre_str += "    ";
                max_line_length -= 4; // account for extra four spaces
                first_line = false;
            }
            else
            {
                out << "\n" << curr_pre_str << str.substr(0, substr_len);
            }

            str.erase(0, substr_len + 1); // extra '1' is for the space
        }
    }

    if (c.type == Comments::CommentType::MULTI_LINE)
        out << '\n' << whitespace << end_multi_com;

    return out;
}

