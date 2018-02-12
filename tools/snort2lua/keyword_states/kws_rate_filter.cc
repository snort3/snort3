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
// kws_rate_filter.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace keywords
{
namespace
{
class RateFilter : public ConversionState
{
public:
    RateFilter(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;

private:
    void fix_separators(std::istringstream& stream);
};
} // namespace

void RateFilter::fix_separators(std::istringstream& stream)
{
    const std::streamoff pos = stream.tellg();
    std::size_t curr = pos;
    std::string s = stream.str();
    int cnt = 0;

    while ( (curr = s.find_first_of("[],", curr)) != std::string::npos )
    {
        switch (s[curr])
        {
        case '[':
            cnt++;
            break;
        case ']':
            cnt--;
            break;
        case ',':
            if (cnt == 0)
                s[curr] = ';';
            break;
        }
        ++curr;
    }

    stream.str(s);
    stream.clear();
    stream.seekg(pos);
}

bool RateFilter::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string args;

    table_api.open_table("rate_filter");
    table_api.open_table();

    fix_separators(data_stream);

    while (std::getline(data_stream, args, ';'))
    {
        std::string keyword;
        std::istringstream arg_stream(args);
        bool tmpval = true;

        arg_stream >> keyword;

        if (keyword.empty())
            continue;

        else if (keyword == "track")
            tmpval = parse_string_option("track", arg_stream);

        else if (keyword == "count")
            tmpval = parse_int_option("count", arg_stream, false);

        else if (keyword == "seconds")
            tmpval = parse_int_option("seconds", arg_stream, false);

        else if (keyword == "timeout")
            tmpval = parse_int_option("timeout", arg_stream, false);

        else if (keyword == "new_action")
            tmpval = parse_string_option("new_action", arg_stream);

        else if (keyword == "apply_to")
        {
            std::getline(arg_stream, keyword);
            util::trim(keyword);
            table_api.add_option("apply_to", keyword);
        }
        else if (keyword == "gen_id")
        {
            table_api.add_diff_option_comment("gen_id", "gid");
            tmpval = parse_int_option("gid", arg_stream, false);
        }
        else if (keyword == "sig_id")
        {
            table_api.add_diff_option_comment("sig_id", "sid");
            tmpval = parse_int_option("sid", arg_stream, false);
        }
        else
            tmpval = false;

        if (retval)
            retval = tmpval;
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new RateFilter(c); }

static const ConvertMap keyword_rate_filter =
{
    "rate_filter",
    ctor,
};

const ConvertMap* rate_filter_map = &keyword_rate_filter;
} // namespace keywords

