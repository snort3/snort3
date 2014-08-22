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
// rule_threshold.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "rule_states/rule_api.h"
#include "utils/s2l_util.h"

namespace rules
{

namespace {


class React : public ConversionState
{
public:
    React() : ConversionState() {};
    virtual ~React() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace

bool React::convert(std::istringstream& data_stream)
{
    std::string args;
    std::string tmp;
    std::streamoff pos = data_stream.tellg();
    bool retval = true;

    args = util::get_rule_option_args(data_stream);

    // if there are no arguments, the option had a colon before a semicolon.
    // we are therefore done with this rule.
    if (!args.empty())
    {
        // a colon will have been parsed when retrieving the keyword.
        // Therefore, if a colon is present, we are in the next rule option.
        if (args.find(":") != std::string::npos)
        {
            data_stream.seekg(pos);
        }
        else
        {
            // since we still can't be sure if we passed the resp buffer,
            // check the next option and ensure it matches
            std::istringstream arg_stream(args);
            util::get_string(arg_stream, tmp, ",");

            if (!tmp.compare("msg") ||
                !tmp.compare("warn") ||
                !tmp.compare("block") ||
                !tmp.compare(0, 5, "proxy"))
            {
                // Now that we have confirmed this is a vlid option, parse it!!
                table_api.open_table("react");
                bool find_msg = false;

                do
                {
                    // FIXIT-1J If reject params are legitimately strings, these MUST
                    //          change so users don't think 'reset_dest=false' turns
                    //          the option off

                    if (!tmp.compare("warn"))
                        table_api.add_deleted_comment("warn");

                    else if (!tmp.compare("block"))
                        table_api.add_deleted_comment("block");

                    else if (!tmp.compare(0, 5, "proxy"))
                        table_api.add_deleted_comment(tmp);

                    else if (!tmp.compare("msg"))
                        find_msg = true;

                    else
                    {
                        rule_api.bad_rule(data_stream, "resp: " + tmp);
                        retval = false;
                    }


                } while (util::get_string(arg_stream, tmp, ","));


                // get this rule's msg
                if (find_msg)
                {
                    std::string msg = util::rule_option_find_val(data_stream, "msg");

                    if (!msg.empty())
                        table_api.add_option("msg", msg);

#if 0
                    // save the current position
                    const std::streamoff curr_pos = data_stream.tellg();

                    if (curr_pos == -1)
                        data_stream.clear();
                    std::string rule_keyword;

                    data_stream.seekg(0);
                    std::getline(data_stream, rule_keyword, '(');
                    std::streamoff tmp_pos = data_stream.tellg();

                    while(std::getline(data_stream, rule_keyword, ':'))
                    {
                        std::size_t semi_colon_pos = rule_keyword.find(';');
                        if (semi_colon_pos != std::string::npos)
                        {
                            // found an option without a colon, so set stream
                            // to semi-colon
                            std::streamoff off = 1 + (std::streamoff)(tmp_pos) +
                                                 (std::streamoff)(semi_colon_pos);
                            data_stream.seekg(off);
                            rule_keyword = rule_keyword.substr(0, semi_colon_pos);
                        }

                        // now, lets get the next option.
                        util::trim(rule_keyword);

                        if (!rule_keyword.compare("msg"))
                        {
                            std::string val = util::get_rule_option_args(data_stream);
                            table_api.add_option("msg", val);
                            break;
                        }
                        else  if (semi_colon_pos == std::string::npos)
                            std::getline(data_stream, rule_keyword, ';');


                        tmp_pos = data_stream.tellg();
                    }

                    // if we're at the end of the rule, don't clear
                    if (curr_pos != -1)
                        data_stream.clear();


                    data_stream.seekg(curr_pos);
#endif
                }
                table_api.close_table(); // "react"
            }
            else
            {
                data_stream.seekg(pos);
            }


        }
    }

    // create this table to ensure reject is instatiated
    table_api.open_table("react");
    table_api.close_table();

    // Finally, update the rule type
    rule_api.update_rule_type("react");
    return set_next_rule_state(data_stream) && retval;
}

/**************************
 *******  A P I ***********
 **************************/


static ConversionState* ctor()
{ return new React(); }

static const ConvertMap rule_react =
{
    "react",
    ctor,
};

const ConvertMap* react_map = &rule_react;

} // namespace rules
