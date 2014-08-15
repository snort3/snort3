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
// out_fast.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/s2l_util.h"

namespace output
{

namespace {

class AlertFast : public ConversionState
{
public:
    AlertFast(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~AlertFast() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool AlertFast::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    ld->open_top_level_table("alert_fast");

    if (!(data_stream >> keyword))
        return true;

    retval = ld->add_option_to_table("file", keyword);


    if (!(data_stream >> keyword))
        return retval;

    if (!keyword.compare("packet"))
    {
        retval = ld->add_option_to_table("packet", true) && retval;

        if (!(data_stream >> keyword))
            return retval;
    }
    else
    {
        ld->add_option_to_table("packet", false);
    }


    int limit;
    char c = '\0';
    std::string units = "B";

    std::istringstream tmp_stream(keyword);
    tmp_stream >> limit;  // gauranteed success since keyword is non-empty
    if (tmp_stream >> c)
    {
        if (c == 'K' || c == 'k')
            units = "K";
        else if (c == 'M' || c == 'm')
            units = "M";
        else if (c == 'G' || c == 'g')
            units = "G";
    }


    retval = ld->add_option_to_table("limit", limit) && retval;
    retval = ld->add_option_to_table("units", units) && retval;

    // If we read something, more data available and bad input
    if (data_stream >> keyword)
        retval = false;

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    ld->open_top_level_table("alert_fast"); // in case there are no arguments
    ld->close_table();
    return new AlertFast(cv, ld);
}

static const ConvertMap alert_fast_api =
{
    "alert_fast",
    ctor,
};

const ConvertMap* alert_fast_map = &alert_fast_api;

} // namespace output
