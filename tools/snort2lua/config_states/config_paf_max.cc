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
// config_paf_max.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class PafMax : public ConversionState
{
public:
    PafMax(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool PafMax::convert(std::istringstream& data_stream)
{
    int val;

    if (data_stream >> val)
    {
        // FIXIT-H this is a hack to ensure max_pdu is in every configuration
        // file and does not overwrite the stream_tcp table

#if 0
        table_api.open_table("stream_tcp");

        if (val < 1460)
        {
            table_api.add_diff_option_comment("paf_max [0:63780]", "max_pdu [1460:63780]");
            val = 1460;
        }

        table_api.add_option("max_pdu", val);
        table_api.close_table();
#else

        if (val < 1460)
        {
            data_api.add_comment("option change: 'paf_max [0:63780]' --> 'max_pdu [1460:32768]'");
            val = 1460;
        }
        else if (val > 32768)
        {
            data_api.add_comment("option change: 'paf_max [0:63780]' --> 'max_pdu [1460:32768]'");
            val = 32768;
        }
        data_api.add_comment("stream_tcp.max_pdu = " + std::to_string(val));
#endif

        if (!(data_stream >> val))
            return true;

        data_api.failed_conversion(data_stream, std::to_string(val));
    }
    else
    {
        data_api.failed_conversion(data_stream, "option required!");
    }

    return false;
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

