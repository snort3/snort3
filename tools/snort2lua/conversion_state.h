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
// conversion_state.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef CONVERSION_STATE_H
#define CONVERSION_STATE_H

#include <sstream>

#include "helpers/converter.h"
#include "helpers/s2l_util.h"
#include "rule_states/rule_api.h"

class DataApi;
class RuleApi;
class TableApi;

class ConversionState
{
public:
    ConversionState(Converter& c) : cv(c),
        // FIXIT-L these should be removed and accessed through cv
        data_api(c.get_data_api()),
        table_api(c.get_table_api()),
        rule_api(c.get_rule_api())
    { }
    virtual ~ConversionState() = default;
    virtual bool convert(std::istringstream& data)=0;

protected:
    Converter& cv;
    DataApi& data_api;
    TableApi& table_api;
    RuleApi& rule_api;

    inline bool eat_option(std::istringstream& stream)
    {
        std::string val;

        if (stream >> val)
            return true;
        return false;
    }

    inline bool parse_string_option(const std::string& opt_name,
        std::istringstream& stream)
    {
        std::string val;

        if (stream >> val)
        {
            if (val.back() == ',')
                val.pop_back();

            table_api.add_option(opt_name, val);
            return true;
        }

        table_api.add_comment("snort.conf missing argument for: " + opt_name + " <string>");
        return false;
    }

    inline bool parse_int_option(const std::string& opt_name,
        std::istringstream& stream, bool append)
    {
        int val;

        if (stream >> val)
        {
            if (append)
                table_api.append_option(opt_name, val);
            else
                table_api.add_option(opt_name, val);
            return true;
        }

        table_api.add_comment("snort.conf missing argument for: " + opt_name + " <int>");
        return false;
    }

    // Like parse_int_option() but reverses -1 and 0 values
    inline bool parse_int_option_reverse_m10(const std::string& opt_name,
        std::istringstream& stream)
    {
        int val;

        if (stream >> val)
        {
            val = !val ? -1 : ( val == -1 ? 0 : val );
            table_api.add_option(opt_name, val);
            return true;
        }

        table_api.add_comment("snort.conf missing argument for: " + opt_name + " <int>");
        return false;
    }

    // parse and add a curly bracketed list to the table
    inline bool parse_curly_bracket_list(const std::string& list_name, std::istringstream& stream)
    {
        std::string elem;
        bool retval = true;

        if (!(stream >> elem) || (elem != "{"))
            return false;

        while (stream >> elem && elem != "}")
            retval = table_api.add_list(list_name, elem) && retval;

        return retval;
    }

    // parse and add a yes/no boolean option.
    inline bool parse_yn_bool_option(const std::string& opt_name, std::istringstream& stream, bool append, const char* yes = "yes", const char* no = "no")
    {
        std::string val;

        if (!(stream >> val))
            return false;

        else if (val == yes)
        {
            if (append)
            {
                table_api.append_option(opt_name, true);
                return true;
            }
            else
                return table_api.add_option(opt_name, true);
        }
        else if (val == no)
        {
            if (append)
            {
                table_api.append_option(opt_name, false);
                return true;
            }
            else
                return table_api.add_option(opt_name, false);
        }

        table_api.add_comment("Unable to convert_option: " + opt_name + ' ' + val);
        return false;
    }

    // parse a curly bracketed bit and add it to the table
    inline bool parse_bracketed_byte_list(const std::string& list_name, std::istringstream& stream)
    {
        std::string elem;
        bool retval = true;

        if (!(stream >> elem) || (elem != "{"))
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
                retval = table_api.add_list(list_name, tmp.str()) && retval;
            }
            else
            {
                table_api.add_comment(
                    "Unable to convert " + elem + "!!  "
                    "The element must be a single character or number between 0 - 255 inclusive");
                retval = false;
            }
        }

        return retval;
    }

    // parse and add a curly bracket list '{...}' which is currently unsupported in Snort++
    inline bool parse_bracketed_unsupported_list(const std::string& list_name, std::istringstream& stream)
    {
        std::string tmp;
        std::string elem;

        if (!(stream >> elem) || (elem != "{"))
            return false;

        while (stream >> elem && elem != "}")
            tmp += " " + elem;

        // remove the extra space at the beginning of the string
        if (!tmp.empty())
            tmp.erase(tmp.begin());

        return table_api.add_option("--" + list_name, tmp);
    }

    inline bool parse_deleted_option(const std::string& opt_name,
        std::istringstream& stream)
    {
        std::string val;
        table_api.add_deleted_comment(opt_name);

        if (stream >> val)
            return true;

        return false;
    }

    inline bool set_next_rule_state(std::istringstream& stream)
    {
        std::string keyword;
        std::streamoff pos = stream.tellg();

        while (std::getline(stream, keyword, ':'))
        {
            std::size_t semi_colon_pos = keyword.find(';');
            if (semi_colon_pos != std::string::npos)
            {
                // found an option without a colon, so set stream to semi-colon
                std::streamoff off = 1 + (std::streamoff)(pos) + (std::streamoff)(semi_colon_pos);
                stream.seekg(off);
                keyword = keyword.substr(0, semi_colon_pos);
            }

            // now, lets get the next option.
            util::trim(keyword);
            const ConvertMap* map = util::find_map(rules::rule_options_api, keyword);
            if (map)
            {
                cv.set_state(map->ctor(cv));
                break;
            }
            else
            {
                rule_api.bad_rule(stream, keyword);

                // if there is data after this keyword,
                //    eat everything until end of keyword
                if (semi_colon_pos == std::string::npos)
                    std::getline(stream, keyword, ';');

                pos = stream.tellg();
            }
        }

        /*
         * The reason this function always returns true is because if the
         * function returned false, the main conversion loop would stop
         * converting.  However, every part of the rule which can be
         * converted, should be converted.  Therefore, this function
         * takes its own invalid conversion action by calling bad_rule(),
         * and then returns true.
         */
        return true;
    }
};

template<std::string* config_header>
class UnsupportedState : public ConversionState
{
public:
    UnsupportedState(Converter& c) : ConversionState(c) {}

    bool convert(std::istringstream& data_stream) override
    {
        data_api.add_unsupported_comment(*config_header +
            std::string(std::istreambuf_iterator<char>(data_stream), {}));
        return true;
    }
};

#endif

