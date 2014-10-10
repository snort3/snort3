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
// kws_rate_filter.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/s2l_util.h"


namespace keywords
{

namespace {

class RateFilter : public ConversionState
{
public:
    RateFilter(Converter& c) : ConversionState(c) {};
    virtual ~RateFilter() {};
    virtual bool convert(std::istringstream& data);

private:
    bool parse_ip_list(std::istringstream& arg_stream, std::istringstream& data_stream);
};

} // namespace

static inline int check_list(std::string listToCheck)
{
    int brackets = 0;

    for (char& c : listToCheck)
    {
        if (c == '[')
            brackets++;

        else if (c == ']')
            brackets--;
    }

    return brackets;
}

bool RateFilter::parse_ip_list(std::istringstream& arg_stream, std::istringstream& data_stream)
{
    std::string tmp;
    int list = 0;

    // will automatically extract entire string since originally delineated on comma
    std::getline(arg_stream, tmp, ',');
    std::string fullIpList = util::trim(tmp);
    list = check_list(tmp);


    while (list > 0)
    {
        fullIpList += ",";
        std::getline(data_stream, tmp, ',');
        list += check_list(tmp);
        fullIpList += tmp;
    }

    if (arg_stream.bad() && data_stream.bad())
        return false;

    table_api.add_option("apply_to", fullIpList);
    return true;
}

bool RateFilter::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string args;


    table_api.open_table("rate_filter");

    while(std::getline(data_stream, args, ','))
    {
        std::string keyword;
        std::istringstream arg_stream(args);
        bool tmpval = true;

        arg_stream >> keyword;


        if(keyword.empty())
            continue;

        else if (!keyword.compare("track"))
            tmpval = parse_string_option("track", arg_stream);

        else if (!keyword.compare("count"))
            tmpval = parse_int_option("count", arg_stream);

        else if (!keyword.compare("seconds"))
            tmpval = parse_int_option("seconds", arg_stream);

        else if (!keyword.compare("timeout"))
            tmpval = parse_int_option("timeout", arg_stream);

        else if (!keyword.compare("new_action"))
            tmpval = parse_string_option("new_action", arg_stream);

        else if (!keyword.compare("apply_to"))
            tmpval = parse_ip_list(arg_stream, data_stream);

        else if(!keyword.compare("gen_id"))
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
