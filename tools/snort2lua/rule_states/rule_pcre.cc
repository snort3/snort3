
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
// rule_pcre.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "rule_states/rule_api.h"
#include "utils/s2l_util.h"

namespace rules
{

namespace {


class Pcre : public ConversionState
{
public:
    Pcre() : ConversionState() {};
    virtual ~Pcre() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace

bool Pcre::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool sticky_buffer_set = false;

    std::string pcre_str = util::get_rule_option_args(data_stream);

    std::size_t pattern_end = pcre_str.rfind("/");
    std::string pattern = pcre_str.substr(0, pattern_end + 1);
    std::string options = pcre_str.substr(pattern_end + 1, std::string::npos);
    std::string new_opts = std::string();

    if (options.back() == '"')
        options.pop_back();
    else
        retval = false;

    for (char c : options )
    {
        std::string sticky_buffer = std::string(); // empty string

        switch(c)
        {
            case 'B': sticky_buffer = "pkt_data"; break;
            case 'U': sticky_buffer = "http_uri"; break;
            case 'P': sticky_buffer = "http_client_body"; break;
            case 'H': sticky_buffer = "http_header"; break;
            case 'M': sticky_buffer = "http_method"; break;
            case 'C': sticky_buffer = "http_cookie"; break;
            case 'I': sticky_buffer = "http_raw_uri"; break;
            case 'D': sticky_buffer = "http_raw_header"; break;
            case 'K': sticky_buffer = "http_raw_cookie"; break;
            case 'S': sticky_buffer = "http_stat_code"; break;
            case 'Y': sticky_buffer = "http_stat_msg"; break;
            case 'i':
            case 's':
            case 'm':
            case 'x':
            case 'A':
            case 'E':
            case 'G':
            case 'R':
            case 'O':
                new_opts += c;
                break;
            default:
            {
                std::string dlt_opt = "pcre: unkown option - '";
                dlt_opt.append(1, c);
                dlt_opt += "'";
                rule_api.add_comment_to_rule(dlt_opt);
                retval = false;
                break;
            }
        }

        if (!sticky_buffer.empty())
        {
            rule_api.add_rule_option(sticky_buffer);

            if (sticky_buffer_set)
                rule_api.add_comment_to_rule("WARNING: Two sticky buffers set for this regular expression!");
            else
                sticky_buffer_set = true;
        }
    }

    rule_api.add_rule_option("pcre", pattern + new_opts + "\"");
    return set_next_rule_state(data_stream) && retval;
}

/**************************
 *******  A P I ***********
 **************************/


static ConversionState* ctor()
{
    return new Pcre();
}


static const ConvertMap pcre_api =
{
    "pcre",
    ctor,
};

const ConvertMap* pcre_map = &pcre_api;

} // namespace rules

