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
// conversion_state.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef CONVERSION_STATE_H
#define CONVERSION_STATE_H

#include <string>
#include <fstream>
#include <sstream>
#include <cctype>

#include "data/dt_data.h"

// the following three files are for the function 'set_next_rule_state'
#include "utils/s2l_util.h"
#include "rule_states/rule_api.h"
#include "utils/converter.h"

class Converter;
class ConversionState;
typedef ConversionState* (*conv_new_f)(Converter*, LuaData* ld);

struct ConvertMap
{
    std::string keyword;
    conv_new_f ctor;
};

// yes, forward declaring.  Without some improvements to design, this needs to stay here.
namespace rules
{
    extern const std::vector<const ConvertMap*> rule_api;
} // namespace rules.


class ConversionState
{

public:
    ConversionState(Converter* cv, LuaData* ld)
    {
        this->cv = cv;
        this->ld = ld;
    }

    virtual ~ConversionState() {};
    virtual bool convert(std::istringstream& data)=0;

protected:
    Converter* cv;
    LuaData* ld;

#if 0
    Forward declaration fo parsing methods. Since these are all inline,
    unable to forward declare in regular code.

    inline bool eat_option(std::istringstream& stream);
    inline bool parse_string_option(std::string opt_name,
                                        std::istringstream& stream
                                        bool required = true);
    inline bool parse_int_option(std::string opt_name,
                                        std::istringstream& stream
                                        bool required = true);
    inline bool parse_curly_bracket_list(std::string list_name,
                                        std::istringstream& stream);
    inline bool parse_yn_bool_option(std::string opt_name,
                                        std::istringstream& stream);
    inline bool parse_bracketed_byte_list(std::string list_name,
                                        std::istringstream& stream);
    inline bool parse_bracketed_unsupported_list(std::string list_name,
                                        std::istringstream& stream);
    inline bool parse_deleted_option(std::string table_name,
                                        std::istringstream& stream,
                                        bool required = true);

    //  rules have no order. Function placed here because every rule
    //  uses this.
    inline bool set_next_rule_state(std::istringstream& stream)

#endif


    inline bool eat_option(std::istringstream& stream)
    {
        std::string val;

        if (stream >> val)
            return true;
        return false;
    }

    inline bool parse_string_option(std::string opt_name,
                                    std::istringstream& stream,
                                    bool required = true)
    {
        std::string val;

        if(stream >> val)
        {
            if(val.back() == ',')
                val.pop_back();

            ld->add_option_to_table(opt_name, val);
            return true;
        }

        if (!required)
            return true;

        ld->add_comment_to_table("snort.conf missing argument for: " + opt_name + " <int>");
        return false;
    }

    inline bool parse_int_option(std::string opt_name,
                                    std::istringstream& stream,
                                    bool required = true)
    {
        int val;

        if(stream >> val)
        {
            ld->add_option_to_table(opt_name, val);
            return true;
        }

        if (!required)
            return true;

        ld->add_comment_to_table("snort.conf missing argument for: " + opt_name + " <int>");
        return false;
    }

    // parse and add a curly bracketed list to the table
    inline bool parse_curly_bracket_list(std::string list_name, std::istringstream& stream)
    {
        std::string elem;
        bool retval = true;

        if(!(stream >> elem) || (elem != "{"))
            return false;

        while (stream >> elem && elem != "}")
            retval = ld->add_list_to_table(list_name, elem) && retval;

        return retval;
    }

    // parse and add a yes/no boolean option.
    inline bool parse_yn_bool_option(std::string opt_name, std::istringstream& stream)
    {
        std::string val;

        if(!(stream >> val))
            return false;

        else if(!val.compare("yes"))
            return ld->add_option_to_table(opt_name, true);

        else if (!val.compare("no"))
            return ld->add_option_to_table(opt_name, false);

        ld->add_comment_to_table("Unable to convert_option: " + opt_name + ' ' + val);
        return false;
    }

    // parse a curly bracketed bit and add it to the table
    inline bool parse_bracketed_byte_list(std::string list_name, std::istringstream& stream)
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
                std::ostringstream tmp;
                tmp << "0x" << std::hex << dig;
                retval = ld->add_list_to_table(list_name, tmp.str()) && retval;

            }
            else
            {
                ld->add_comment_to_table("Unable to convert " + elem +
                        "!!  The element must be a single charachter or number between 0 - 255 inclusive");
                retval = false;
            }
        }

        return retval;
    }

    // parse and add a curly bracket list '{...}' which is currently unsupported in Snort++
    inline bool parse_bracketed_unsupported_list(std::string list_name, std::istringstream& stream)
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

        return ld->add_option_to_table("--" + list_name, tmp );
    }


    inline bool parse_deleted_option(std::string opt_name,
                                        std::istringstream& stream,
                                        bool required = true)
    {
        std::string val;
        ld->add_deleted_comment(opt_name);

        if(stream >> val)
            return true;

        if (!required)
            return true;
        return false;
    }


    inline bool set_next_rule_state(std::istringstream& stream)
    {
        std::string keyword;
        std::streamoff pos = stream.tellg();

        while(std::getline(stream, keyword, ':'))
        {
            std::size_t semi_colon_pos = keyword.find(';');
            if (semi_colon_pos != std::string::npos)
            {
                // found an option without a colon, so set stream
                // to semi-colon
                std::streamoff off = 1 + (std::streamoff)(pos) +
                                     (std::streamoff)(semi_colon_pos);
                stream.seekg(off);
                keyword = keyword.substr(0, semi_colon_pos);
            }

            // now, lets get the next option.
            util::trim(keyword);
            const ConvertMap* map = util::find_map(rules::rule_api, keyword);
            if (map)
            {
                ld->unselect_option(); // reset option data...just in case.
                cv->set_state(map->ctor(cv, ld));
                break;
            }
            else
            {
                ld->bad_rule(stream, keyword);

                // if there is data after this keyword,
                //    eat everything until end of keyword
                if (semi_colon_pos == std::string::npos)
                    std::getline(stream, keyword, ';');

                pos = stream.tellg();
            }
        }

        // This is definitely a special case to always return true, I have
        // already taken corrective action by signifyig this is a 'bad rule'.
        // Additionally, I don't return false earlier becasue, when possible,
        // I want to parse the entire rule. If I only return false when the
        // last option was invalid, this would lead to an incosistant and
        // unreliable return value.  Bottom line, I'm consistant by returning
        // true and handling "bad" values and directly signifgying to Data
        // classes this is a bad rule.
        return true;
    }


private:

};


#endif
