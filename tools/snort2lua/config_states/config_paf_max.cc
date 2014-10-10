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
// config_paf_max.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/s2l_util.h"

namespace config
{

namespace {

class PafMax : public ConversionState
{
public:
    PafMax(Converter& c) : ConversionState(c) {};
    virtual ~PafMax() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool PafMax::convert(std::istringstream& data_stream)
{
    bool retval = true;
    int val;

    table_api.open_table("stream_tcp");

    if (data_stream >> val)
    {
        if (val < 1460)
            table_api.add_diff_option_comment("paf_max [0:63780]", "max_pdu [1460:63780]");
        else
            retval = table_api.add_option("max_pdu", val);
    }
    else
        data_api.failed_conversion(data_stream);

    table_api.close_table();
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new PafMax(c); }

static const ConvertMap paf_max_api =
{
    "paf_max",
    ctor,
};

const ConvertMap* paf_max_map = &paf_max_api;

} // namespace config
