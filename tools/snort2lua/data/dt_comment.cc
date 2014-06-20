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
// dt_comment.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include "data/dt_comment.h"

Comments::Comments(CommentType type)
{
    this->depth = 0;
    this->prev_empty = false;
    this->type = type;
}

Comments::Comments(int depth, CommentType type)
{
    this->depth = depth;
    this->prev_empty = false;
    this->type = type;
}

Comments::Comments(std::string comment, int depth, CommentType type)
{
    this->comment.push_back(std::string(comment));
    this->depth = depth;
    this->prev_empty = false;
    this->type = type;
}

Comments::~Comments()
{
} 

void Comments::add_text(std::string text)
{
    if (!text.empty() || !prev_empty)
    {
        comment.push_back(std::string(text));

        prev_empty = text.empty();
    }
}

std::ostream &operator<<( std::ostream& out, const Comments &c)
{
    std::string whitespace = "";
    std::string pre_str;

    if (c.comment.size() == 0)
        return out;

    for(int i = 0; i < c.depth; i++)
        whitespace += "    ";


    // creating the correct format for strings
    if (c.type == Comments::CommentType::Single_Lines)
    {
        pre_str = whitespace + "--";
    }
    else
    {
        out << c.start_multi_com;
        pre_str = whitespace + "    ";
    }


    const int pre_str_length = pre_str.size();
    const int max_line_length = c.max_line_length - pre_str_length - 1;


    for (std::string str : c.comment)
    {
        int str_pos = 0;
        bool first_line = true;
        std::string curr_pre_str = pre_str;

        if (str.size() == 0)
            out << "\n";

//        while(str_pos < curr_length)
        while(!str.empty())
        {
            int substr_len = max_line_length;
            if (substr_len < str.size())
            {
                substr_len = str.rfind(" ", max_line_length);

                if (substr_len == -1)
                    substr_len = max_line_length;
            }

            out << "\n" << curr_pre_str << str.substr(0, substr_len);
            str.erase(0, substr_len + 1); // extra '1' is for the space
//            str_pos += substr_len + 1; // extra '1' is for the space

            if (first_line)
            {
                curr_pre_str += "    ";
                first_line = false;
            }
        }
    }


    if (c.type == Comments::CommentType::Mult_Line)
        out << whitespace << c.end_multi_com;

    return out;
}

