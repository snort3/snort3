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
// kws_event_filter.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace keywords
{
namespace
{
class Filter : public ConversionState
{
public:
    Filter(Converter& c, const std::string& s) : ConversionState(c), type(s) { }
    bool convert(std::istringstream& data_stream) override;

private:
    std::string type;
};
} // namespace

bool Filter::convert(std::istringstream& data_stream)
{
    std::string args;
    bool retval = true;
    static bool warn = true;

    table_api.open_table("event_filter");

    if ( warn && type == "threshold")
    {
        table_api.add_diff_option_comment("threshold", "event_filter");
        warn = false;
    }

    table_api.open_table();
    while (std::getline(data_stream, args, ','))
    {
        std::string keyword;
        bool tmpval;

        std::istringstream arg_stream(args);
        arg_stream >> keyword;

        if (keyword.empty())
            continue;

        else if (keyword == "count")
            tmpval = parse_int_option("count", arg_stream, false);

        else if (keyword == "seconds")
            tmpval = parse_int_option("seconds", arg_stream, false);

        else if (keyword == "type")
            tmpval = parse_string_option("type", arg_stream);

        else if (keyword == "track")
            tmpval = parse_string_option("track", arg_stream);

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
        {
            tmpval = false;
        }

        if (retval)
            retval = tmpval;
    }

    table_api.close_table();
    table_api.close_table();

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* threshold_ctor(Converter& c)
{ return new Filter(c, "threshold"); }

static ConversionState* event_filter_ctor(Converter& c)
{ return new Filter(c, "event_filter"); }

static const ConvertMap event_filter_api =
{
    "event_filter",
    event_filter_ctor,
};

static const ConvertMap threshold_api =
{
    "threshold",
    threshold_ctor,
};

const ConvertMap* event_filter_map = &event_filter_api;
const ConvertMap* threshold_map = &threshold_api;
} // namespace keywords

