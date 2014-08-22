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


class Resp : public ConversionState
{
public:
    Resp() : ConversionState() {};
    virtual ~Resp() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace

bool Resp::convert(std::istringstream& data_stream)
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

            if (!tmp.compare("reset_dest") ||
                !tmp.compare("reset_both") ||
                !tmp.compare("rst_snd") ||
                !tmp.compare("rst_rcv") ||
                !tmp.compare("rst_all") ||
                !tmp.compare("icmp_net") ||
                !tmp.compare("icmp_host") ||
                !tmp.compare("icmp_all") ||
                !tmp.compare("reset_source") ||
                !tmp.compare("icmp_port"))
            {
                // Now that we have confirmed this is a vlid option, parse it!!
                table_api.open_table("reject");

                do
                {
                    // FIXIT-1J If reject params are legitimately strings, these MUST
                    //          change so users don't think 'reset_dest=false' turns
                    //          the option off

                    if (!tmp.compare("reset_dest"))
                        table_api.add_option("reset_dest", "true");

                    else if (!tmp.compare("reset_both"))
                        table_api.add_option("reset_both", "true");

                    else if (!tmp.compare("rst_snd"))
                        table_api.add_option("rst_snd", "true");

                    else if (!tmp.compare("rst_rcv"))
                        table_api.add_option("rst_rcv", "true");

                    else if (!tmp.compare("rst_all"))
                        table_api.add_option("rst_all", "true");

                    else if (!tmp.compare("icmp_net"))
                        table_api.add_option("icmp_net", "true");

                    else if (!tmp.compare("icmp_host"))
                        table_api.add_option("icmp_host", "true");

                    else if (!tmp.compare("icmp_all"))
                        table_api.add_option("icmp_all", "true");

                    else if (!tmp.compare("reset_source"))
                        table_api.add_option("reset_source", "true");

                    else if (!tmp.compare("icmp_port"))
                        table_api.add_option("icmp_port", "true");

                    else
                    {
                        rule_api.bad_rule(data_stream, "resp: " + tmp);
                        retval = false;
                    }


                } while (util::get_string(arg_stream, tmp, ","));


                table_api.close_table(); // "reject"
            }
            else
            {
                data_stream.seekg(pos);
            }
        }
    }

    // create this table to ensure reject is instatiated
    table_api.open_table("reject");
    table_api.close_table();

    // Finally, update the rule type
    rule_api.update_rule_type("reject");
    return set_next_rule_state(data_stream) && retval;
}

/**************************
 *******  A P I ***********
 **************************/


static ConversionState* ctor()
{ return new Resp(); }

static const ConvertMap rule_resp =
{
    "resp",
    ctor,
};

const ConvertMap* resp_map = &rule_resp;

} // namespace rules
