//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// out_fast.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace output
{
namespace
{
class AlertFast : public ConversionState
{
public:
    AlertFast(Converter& c) : ConversionState(c) { }
    virtual ~AlertFast() { }
    virtual bool convert(std::istringstream& data_stream);
};
} // namespace

bool AlertFast::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    table_api.open_top_level_table("alert_fast");

    if (!(data_stream >> keyword))
        return true;

    table_api.add_deleted_comment("<filename> can no longer be specific");

    if (!(data_stream >> keyword))
        return retval;

    if (!keyword.compare("packet"))
    {
        retval = table_api.add_option("packet", true) && retval;

        if (!(data_stream >> keyword))
            return retval;
    }
    else
    {
        table_api.add_option("packet", false);
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

    retval = table_api.add_option("limit", limit) && retval;
    retval = table_api.add_option("units", units) && retval;

    // If we read something, more data available and bad input
    if (data_stream >> keyword)
        retval = false;

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    c.get_table_api().open_top_level_table("alert_fast"); // in case there are no arguments
    c.get_table_api().close_table();
    return new AlertFast(c);
}

static const ConvertMap alert_fast_api =
{
    "alert_fast",
    ctor,
};

const ConvertMap* alert_fast_map = &alert_fast_api;
} // namespace output

