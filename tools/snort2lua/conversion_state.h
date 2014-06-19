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
// converter.h author Josh Rosenbaum <jorosenba@cisco.com>

#ifndef CONVERSION_STATE_H
#define CONVERSION_STATE_H

#include <string>
#include <fstream>
#include <sstream>
#include <cctype>

#include "converter.h"
 
class ConversionState
{

public:
    ConversionState(Converter *cv){ this->cv = cv; }
    virtual ~ConversionState() {};
    virtual bool convert(std::stringstream& data)=0;

protected:
    Converter* cv;

    inline bool parse_string_option(std::string opt_name, std::stringstream& stream)
    {
        std::string val;

        if(stream >> val)
        {
            if(val.back() == ',')
                val.pop_back();

            cv->add_option_to_table(opt_name, val);
            return true;
        }

        cv->add_comment_to_table("snort.conf missing argument for: " + opt_name + " <int>");
        return false;
    }

    inline bool parse_int_option(std::string opt_name, std::stringstream& stream)
    {
        int val;

        if(stream >> val)
        {
            cv->add_option_to_table(opt_name, val);
            return true;
        }

        cv->add_comment_to_table("snort.conf missing argument for: " + opt_name + " <int>");
        return false;
    }

    // parse and add a curly bracketed list to the table
    inline bool parse_curly_bracket_list(std::string list_name, std::stringstream& stream)
    {
        std::string elem;
        bool retval = true;

        if(!(stream >> elem) || (elem != "{"))
            return false;

        while (stream >> elem && elem != "}")
            retval = cv->add_list_to_table(list_name, elem) && retval;

        return retval;
    }

    // parse and add a yes/no boolean option.
    inline bool parse_yn_bool_option(std::string opt_name, std::stringstream& stream)
    {
        std::string val;

        if(!(stream >> val))
            return false;

        else if(!val.compare("yes"))
            return cv->add_option_to_table(opt_name, true);

        else if (!val.compare("no"))
            return cv->add_option_to_table(opt_name, false);

        cv->add_comment_to_table("Unable to convert_option: " + opt_name + ' ' + val);
        return false;
    }

    // parse a curly bracketed bit and add it to the table
    inline bool parse_bracketed_byte_list(std::string list_name, std::stringstream& stream)
    {
        std::string elem;
        bool retval = true;

        if(!(stream >> elem) || (elem != "{"))
            return false;

        while (stream >> elem && elem != "}")
        {
            int dig;

            if (std::isdigit(elem[0]))
                dig = std::stoi(elem, nullptr, 0);
            else if (elem.size() == 1)
                dig = (int)elem[0];
            else
                dig = -1;

            if (0 <= dig && dig <= 255)
            {
                std::stringstream tmp;
                tmp << "0x" << std::hex << dig;
                retval = cv->add_list_to_table(list_name, tmp.str()) && retval;

            }
            else
            {
                cv->add_comment_to_table("Unable to convert " + elem +
                        "!!  The element must be a single charachter or number between 0 - 255 inclusive");
                retval = false;
            }
        }

        return retval;
    }

    // parse and add a curly bracket list '{...}' which is currently unsupported in Snort++
    inline bool parse_bracketed_unsupported_list(std::string list_name, std::stringstream& stream)
    {
        std::string tmp = "";
        std::string elem;

        if(!(stream >> elem) || (elem != "{"))
            return false;

        while (stream >> elem && elem != "}")
            tmp += " " + elem;

        // remove the extra space at the beginig of the string
        if(tmp.size() > 0)
            tmp.erase(tmp.begin());

        return cv->add_option_to_table("--" + list_name, tmp );
    }

    inline bool open_table_add_option(std::string table_name, std::string opt_name, std::string val)
    {
        bool tmpval = cv->open_table(table_name);
        tmpval = cv->add_option_to_table(opt_name, val) && tmpval;
        cv->close_table();
        return tmpval;
    }


private:

};


typedef ConversionState* (*conv_new_f)(Converter*);

struct ConvertMap
{
    std::string keyword;
    conv_new_f ctor;
};




#endif
