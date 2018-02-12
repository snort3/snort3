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
// rule_pcre.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class Pcre : public ConversionState
{
public:
    Pcre(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool Pcre::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool sticky_buffer_set = false;
    std::string buffer = "pkt_data";

    char delim = '/';
    std::string pcre_str = util::get_rule_option_args(data_stream);
    std::string pattern;
    std::string new_opts;
    std::string options;

    if (pcre_str.front() == '!')
    {
        pattern += "!";
        pcre_str.erase(pcre_str.begin());
    }

    if (pcre_str.front() != '"' || pcre_str.back() != '"')
    {
        rule_api.bad_rule(data_stream, "pattern must be enclosed in \"");
        return set_next_rule_state(data_stream);
    }

    pcre_str.erase(pcre_str.begin());
    pattern += '"';

    if (pcre_str.front() == 'm')
    {
        pcre_str.erase(pcre_str.begin());
        pattern += 'm';
        delim = pcre_str.front();
    }

    const std::size_t pattern_end = pcre_str.rfind(delim);
    if ((pcre_str.front() != delim) || (pattern_end == 0))
    {
        std::string tmp = "Regex must be enclosed in delim '";
        tmp.append(delim, 1);
        rule_api.bad_rule(data_stream, tmp + "'");
        return set_next_rule_state(data_stream);
    }

    pattern += pcre_str.substr(0, pattern_end + 1);
    options = pcre_str.substr(pattern_end + 1, std::string::npos);
    new_opts = "";
    bool relative = false;

    for (char c : options )
    {
        std::string sticky_buffer = std::string(); // empty string

        switch (c)
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
        case 'O':
        case '"':     // end of reg_ex
            new_opts += c;
            break;
        case 'R':
            relative = true;
            new_opts += c;
            break;
        default:
        {
            std::string dlt_opt = "unknown option - '";
            dlt_opt.append(1, c);
            dlt_opt += "'";
            rule_api.bad_rule(data_stream, dlt_opt);
            break;
        }
        }

        if (!sticky_buffer.empty())
        {
            buffer = sticky_buffer;

            if (sticky_buffer_set)
                rule_api.bad_rule(data_stream,
                    "Two sticky buffers set for this regular expression!");
            else
                sticky_buffer_set = true;
        }
    }

    rule_api.add_option("pcre", pattern + new_opts);

    if ( !relative )
        rule_api.set_curr_options_buffer(buffer);

    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new Pcre(c); }

static const ConvertMap pcre_api =
{
    "pcre",
    ctor,
};

const ConvertMap* pcre_map = &pcre_api;
} // namespace rules

