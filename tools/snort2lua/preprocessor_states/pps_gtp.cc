//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// pps_gtp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class Gtp : public ConversionState
{
public:
    Gtp(Converter& c) : ConversionState(c) { }
    virtual ~Gtp() { }
    virtual bool convert(std::istringstream& data_stream);
};
} // namespace

bool Gtp::convert(std::istringstream& data_stream)
{
    std::string args;
    bool retval = true;

    table_api.open_table("udp");

    while (util::get_string(data_stream, args, ",;"))
    {
        std::string keyword;
        bool tmpval = true;
        std::istringstream arg_stream(args);

        if (!(arg_stream >> keyword))
        {
            tmpval = false;
        }
        else if (!keyword.compare("ports"))
        {
            table_api.add_diff_option_comment("ports", "gtp_ports");
            tmpval = parse_curly_bracket_list("gtp_ports", arg_stream);
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
{
    return new Gtp(c);
}

static const ConvertMap preprocessor_gtp =
{
    "gtp",
    ctor,
};

const ConvertMap* gtp_map = &preprocessor_gtp;
} // namespace preprocessors

