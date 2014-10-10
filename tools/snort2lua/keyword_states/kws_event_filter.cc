/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// kws_event_filter.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/s2l_util.h"

namespace keywords
{

namespace {

class EventFilter : public ConversionState
{
public:
    EventFilter(Converter& c) : ConversionState(c) {};
    virtual ~EventFilter() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool EventFilter::convert(std::istringstream& data_stream)
{
    std::string args;
    bool retval = true;

    table_api.open_table("event_filter");
    table_api.open_table();

    while (std::getline(data_stream, args, ','))
    {
        std::string keyword;
        bool tmpval;

        std::istringstream arg_stream(args);
        arg_stream >> keyword;


        if (keyword.empty())
            continue;

        else if (!keyword.compare("count"))
            tmpval = parse_int_option("count", arg_stream);

        else if (!keyword.compare("seconds"))
            tmpval = parse_int_option("seconds", arg_stream);

        else if (!keyword.compare("type"))
            tmpval = parse_string_option("type", arg_stream);

        else if (!keyword.compare("track"))
            tmpval = parse_string_option("track", arg_stream);

        else if (!keyword.compare("gen_id"))
        {
            table_api.add_diff_option_comment("gen_id", "gid");
            tmpval = parse_int_option("gid", arg_stream);
        }

        else if (!keyword.compare("sig_id"))
        {
            table_api.add_diff_option_comment("sig_id", "sid");
            tmpval = parse_int_option("sid", arg_stream);
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

static ConversionState* ctor(Converter& c)
{ return new EventFilter(c); }

static const ConvertMap event_filter_api =
{
    "event_filter",
    ctor,
};

const ConvertMap* event_filter_map = &event_filter_api;

} // namespace keywords
