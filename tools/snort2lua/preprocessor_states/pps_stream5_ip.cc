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
// pps_stream_ip.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class StreamIp : public ConversionState
{
public:
    StreamIp(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool StreamIp::convert(std::istringstream& data_stream)
{
    std::string args;
    bool retval = true;

    table_api.open_table("stream_ip");

    while (util::get_string(data_stream, args, ","))
    {
        std::string keyword;
        bool tmpval = true;
        std::istringstream arg_stream(args);

        if (!(arg_stream >> keyword))
        {
            tmpval = false;
        }
        else if (keyword == "timeout")
        {
            table_api.add_diff_option_comment("timeout", "session_timeout");
            tmpval = parse_int_option("session_timeout", arg_stream, false);
        }
        else
        {
            tmpval = false;
        }

        if (retval && !tmpval)
            retval = false;
    }

    table_api.close_table();
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new StreamIp(c); }

static const ConvertMap preprocessor_stream_ip =
{
    "stream5_ip",
    ctor,
};

const ConvertMap* stream_ip_map = &preprocessor_stream_ip;
} // namespace preprocessors

